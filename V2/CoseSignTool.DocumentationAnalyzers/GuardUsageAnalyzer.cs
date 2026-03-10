// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.DocumentationAnalyzers;

using System;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
[ExcludeFromCodeCoverage]
public sealed class GuardUsageAnalyzer : DiagnosticAnalyzer
{
    public const string UseGuardThrowIfNullDiagnosticId = "CSTGUARD001";
    public const string UseGuardThrowIfNullOrWhiteSpaceDiagnosticId = "CSTGUARD002";
    public const string UseGuardThrowIfDisposedDiagnosticId = "CSTGUARD003";

    private static readonly DiagnosticDescriptor UseGuardThrowIfNullRule = new(
        id: UseGuardThrowIfNullDiagnosticId,
        title: "Use Guard.ThrowIfNull in multi-targeted libraries",
        messageFormat: "Use Guard.ThrowIfNull for parameter null-checks when targeting netstandard and newer frameworks",
        category: "Maintainability",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor UseGuardThrowIfNullOrWhiteSpaceRule = new(
        id: UseGuardThrowIfNullOrWhiteSpaceDiagnosticId,
        title: "Use Guard.ThrowIfNullOrWhiteSpace in multi-targeted libraries",
        messageFormat: "Use Guard.ThrowIfNullOrWhiteSpace for string null/empty/whitespace validation when targeting netstandard and newer frameworks",
        category: "Maintainability",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor UseGuardThrowIfDisposedRule = new(
        id: UseGuardThrowIfDisposedDiagnosticId,
        title: "Use Guard.ThrowIfDisposed in multi-targeted libraries",
        messageFormat: "Use Guard.ThrowIfDisposed for disposal checks when targeting netstandard and newer frameworks",
        category: "Maintainability",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
        UseGuardThrowIfNullRule,
        UseGuardThrowIfNullOrWhiteSpaceRule,
        UseGuardThrowIfDisposedRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterOperationAction(AnalyzeInvocation, OperationKind.Invocation);
        context.RegisterOperationAction(AnalyzeThrow, OperationKind.Throw);
    }

    private static void AnalyzeInvocation(OperationAnalysisContext context)
    {
        if (!ShouldAnalyzeProject(context.Options.AnalyzerConfigOptionsProvider))
        {
            return;
        }

        if (!HasMultiTargetNetstandardMarker(context.Compilation))
        {
            return;
        }

        if (!IsGuardAvailable(context.Compilation))
        {
            return;
        }

        var invocation = (IInvocationOperation)context.Operation;
        var targetMethod = invocation.TargetMethod;

        // Guard itself is allowed to call the newer BCL helpers and polyfill as needed.
        if (IsWithinGuardImplementation(context.ContainingSymbol))
        {
            return;
        }

        var compilation = context.Compilation;

        var argumentNullExceptionType = compilation.GetTypeByMetadataName("System.ArgumentNullException");
        if (argumentNullExceptionType is not null &&
            targetMethod.Name == "ThrowIfNull" &&
            SymbolEqualityComparer.Default.Equals(targetMethod.ContainingType, argumentNullExceptionType))
        {
            context.ReportDiagnostic(Diagnostic.Create(UseGuardThrowIfNullRule, invocation.Syntax.GetLocation()));
            return;
        }

        var argumentExceptionType = compilation.GetTypeByMetadataName("System.ArgumentException");
        if (argumentExceptionType is not null &&
            targetMethod.Name == "ThrowIfNullOrWhiteSpace" &&
            SymbolEqualityComparer.Default.Equals(targetMethod.ContainingType, argumentExceptionType))
        {
            context.ReportDiagnostic(Diagnostic.Create(UseGuardThrowIfNullOrWhiteSpaceRule, invocation.Syntax.GetLocation()));
            return;
        }

        var objectDisposedExceptionType = compilation.GetTypeByMetadataName("System.ObjectDisposedException");
        if (objectDisposedExceptionType is not null &&
            targetMethod.Name == "ThrowIf" &&
            SymbolEqualityComparer.Default.Equals(targetMethod.ContainingType, objectDisposedExceptionType))
        {
            context.ReportDiagnostic(Diagnostic.Create(UseGuardThrowIfDisposedRule, invocation.Syntax.GetLocation()));
        }
    }

    private static void AnalyzeThrow(OperationAnalysisContext context)
    {
        if (!ShouldAnalyzeProject(context.Options.AnalyzerConfigOptionsProvider))
        {
            return;
        }

        if (!HasMultiTargetNetstandardMarker(context.Compilation))
        {
            return;
        }

        if (!IsGuardAvailable(context.Compilation))
        {
            return;
        }

        // Guard itself is allowed to throw/bridge as needed.
        if (IsWithinGuardImplementation(context.ContainingSymbol))
        {
            return;
        }

        var throwOp = (IThrowOperation)context.Operation;
        var thrownType = GetThrownExceptionType(throwOp.Exception);
        if (thrownType is null)
        {
            return;
        }

        var compilation = context.Compilation;

        var argumentNullExceptionType = compilation.GetTypeByMetadataName("System.ArgumentNullException");
        if (argumentNullExceptionType is not null &&
            SymbolEqualityComparer.Default.Equals(thrownType, argumentNullExceptionType))
        {
            context.ReportDiagnostic(Diagnostic.Create(UseGuardThrowIfNullRule, throwOp.Syntax.GetLocation()));
            return;
        }

        // Only flag ArgumentException patterns that look like string null/empty/whitespace parameter validation.
        // Other ArgumentException uses (range checks, format validation, etc.) are intentionally not flagged.
        var argumentExceptionType = compilation.GetTypeByMetadataName("System.ArgumentException");
        if (argumentExceptionType is not null &&
            SymbolEqualityComparer.Default.Equals(thrownType, argumentExceptionType) &&
            IsWithinStringNullOrEmptyOrWhiteSpaceIf(throwOp.Syntax))
        {
            context.ReportDiagnostic(Diagnostic.Create(UseGuardThrowIfNullOrWhiteSpaceRule, throwOp.Syntax.GetLocation()));
        }
    }

    private static bool ShouldAnalyzeProject(AnalyzerConfigOptionsProvider optionsProvider)
    {
        // Only enforce for projects that are known (via build constants) to multi-target netstandard + modern .NET.
        // We prefer an explicit constant over relying on build_property.* availability.
        var global = optionsProvider.GlobalOptions;

        if (global.TryGetValue("build_property.IsTestProject", out var isTestProject) &&
            string.Equals(isTestProject, "true", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private static bool HasMultiTargetNetstandardMarker(Compilation compilation)
    {
        var tree = compilation.SyntaxTrees.FirstOrDefault();
        if (tree is null)
        {
            return false;
        }

        if (tree.Options is not CSharpParseOptions csharp)
        {
            return false;
        }

        return csharp.PreprocessorSymbolNames.Contains("COSESIGNTOOL_MULTITARGET_NETSTANDARD", StringComparer.Ordinal);
    }

    private static bool IsGuardAvailable(Compilation compilation)
    {
        return compilation.GetTypeByMetadataName("CoseSign1.Abstractions.Guard") is not null;
    }

    private static bool IsWithinGuardImplementation(ISymbol? containingSymbol)
    {
        // Allow the Guard implementation to delegate to newer framework methods.
        for (var type = containingSymbol?.ContainingType; type is not null; type = type.ContainingType)
        {
            if (type.Name == "Guard" &&
                type.ContainingNamespace.ToDisplayString() == "CoseSign1.Abstractions")
            {
                return true;
            }
        }

        return false;
    }

    private static INamedTypeSymbol? GetThrownExceptionType(IOperation? exceptionOperation)
    {
        if (exceptionOperation is null)
        {
            return null;
        }

        while (exceptionOperation is IConversionOperation conversion)
        {
            exceptionOperation = conversion.Operand;
            if (exceptionOperation is null)
            {
                return null;
            }
        }

        return exceptionOperation.Type as INamedTypeSymbol;
    }

    private static bool IsWithinStringNullOrEmptyOrWhiteSpaceIf(SyntaxNode throwSyntax)
    {
        // Syntactic heuristic: we only want to enforce Guard for the verbose pattern
        //   if (string.IsNullOrWhiteSpace(x)) throw new ArgumentException(...)
        //   if (string.IsNullOrEmpty(x)) throw new ArgumentException(...)
        // (including equivalent forms where the throw is inside the if statement block).
        for (var node = throwSyntax.Parent; node is not null; node = node.Parent)
        {
            if (node is Microsoft.CodeAnalysis.CSharp.Syntax.IfStatementSyntax ifStatement)
            {
                var conditionText = ifStatement.Condition.ToString();
                if (conditionText.Contains("string.IsNullOrWhiteSpace", StringComparison.Ordinal) ||
                    conditionText.Contains("string.IsNullOrEmpty", StringComparison.Ordinal))
                {
                    return true;
                }
            }
        }

        return false;
    }
}
