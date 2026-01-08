// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace CoseSignTool.DocumentationAnalyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
[ExcludeFromCodeCoverage]
public sealed class ExceptionDocumentationAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "CSTDOC001";

    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticId,
        title: "Thrown exceptions must be documented",
        messageFormat: "Document thrown exception(s) with <exception> tags: {0}",
        category: "Documentation",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterOperationBlockStartAction(AnalyzeOperationBlock);
    }

    private static void AnalyzeOperationBlock(OperationBlockStartAnalysisContext context)
    {
        if (context.OwningSymbol is not IMethodSymbol method)
        {
            return;
        }

        ISymbol documentedOn = method;

        if (method.MethodKind is MethodKind.PropertyGet or MethodKind.PropertySet or MethodKind.EventAdd or MethodKind.EventRemove)
        {
            documentedOn = method.AssociatedSymbol ?? method;
        }

        if (!IsPublicApi(documentedOn))
        {
            return;
        }

        if (method.IsImplicitlyDeclared)
        {
            return;
        }

        if (method.ContainingType.TypeKind == TypeKind.Interface)
        {
            return;
        }

        var exceptionType = context.Compilation.GetTypeByMetadataName("System.Exception");
        if (exceptionType is null)
        {
            return;
        }

        var thrownExceptionMetadataNames = new HashSet<string>(StringComparer.Ordinal);
        var firstThrowLocation = default(Location);

        context.RegisterOperationAction(opContext =>
        {
            var throwOp = (IThrowOperation)opContext.Operation;
            var thrownType = GetThrownExceptionType(throwOp.Exception);
            if (thrownType is null)
            {
                return;
            }

            if (!thrownType.InheritsFromOrEquals(exceptionType))
            {
                return;
            }

            firstThrowLocation ??= throwOp.Syntax.GetLocation();
            thrownExceptionMetadataNames.Add(thrownType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat));
        }, OperationKind.Throw);

        context.RegisterOperationBlockEndAction(endContext =>
        {
            if (thrownExceptionMetadataNames.Count == 0)
            {
                return;
            }

            var documented = GetDocumentedExceptionTypes(documentedOn, endContext.CancellationToken);
            var missing = thrownExceptionMetadataNames.Where(t => !documented.Contains(t)).ToArray();
            if (missing.Length == 0)
            {
                return;
            }

            var location = firstThrowLocation ?? method.Locations.FirstOrDefault();
            if (location is null)
            {
                return;
            }

            var missingDisplay = string.Join(", ", missing.Select(ShortName));
            endContext.ReportDiagnostic(Diagnostic.Create(Rule, location, missingDisplay));
        });
    }

        // NOTE: Operation-based analysis is in AnalyzeOperationBlock.

    private static HashSet<string> GetDocumentedExceptionTypes(ISymbol symbol, CancellationToken cancellationToken)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var xml = symbol.GetDocumentationCommentXml(cancellationToken: cancellationToken);
        if (string.IsNullOrWhiteSpace(xml))
        {
            return result;
        }

        try
        {
            var doc = XDocument.Parse("<root>" + xml + "</root>");
            foreach (var element in doc.Descendants("exception"))
            {
                var cref = element.Attribute("cref")?.Value;
                if (string.IsNullOrWhiteSpace(cref))
                {
                    continue;
                }

                // Accept both "T:Namespace.Type" and "Namespace.Type" forms.
                cref = cref.Trim();
                if (cref.StartsWith("T:", StringComparison.Ordinal))
                {
                    cref = cref.Substring(2);
                }

                if (!cref.StartsWith("global::", StringComparison.Ordinal))
                {
                    cref = "global::" + cref;
                }

                result.Add(cref);
            }
        }
        catch
        {
            // If the docs are malformed, other analyzers/compilers will handle that.
        }

        return result;
    }

    private static bool IsPublicApi(ISymbol symbol)
    {
        if (symbol.IsImplicitlyDeclared)
        {
            return false;
        }

        if (symbol.DeclaredAccessibility != Accessibility.Public)
        {
            return false;
        }

        for (var containingType = symbol.ContainingType; containingType is not null; containingType = containingType.ContainingType)
        {
            if (containingType.DeclaredAccessibility != Accessibility.Public)
            {
                return false;
            }
        }

        return true;
    }

    private static string ShortName(string fullyQualified)
    {
        const string globalPrefix = "global::";
        if (fullyQualified.StartsWith(globalPrefix, StringComparison.Ordinal))
        {
            fullyQualified = fullyQualified.Substring(globalPrefix.Length);
        }

        var lastDot = fullyQualified.LastIndexOf('.');
        return lastDot >= 0 ? fullyQualified.Substring(lastDot + 1) : fullyQualified;
    }

    private static INamedTypeSymbol? GetThrownExceptionType(IOperation? exceptionOperation)
    {
        if (exceptionOperation is null)
        {
            return null;
        }

        // In many cases the thrown expression is implicitly converted to System.Exception.
        // Unwrap conversions so we can report the concrete exception type.
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
}

internal static class SymbolExtensions
{
    public static bool InheritsFromOrEquals(this INamedTypeSymbol type, INamedTypeSymbol baseType)
    {
        for (INamedTypeSymbol? current = type; current is not null; current = current.BaseType)
        {
            if (SymbolEqualityComparer.Default.Equals(current, baseType))
            {
                return true;
            }
        }

        return false;
    }
}
