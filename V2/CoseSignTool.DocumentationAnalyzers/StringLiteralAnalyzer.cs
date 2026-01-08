// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace CoseSignTool.DocumentationAnalyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
[ExcludeFromCodeCoverage]
public sealed class StringLiteralAnalyzer : DiagnosticAnalyzer
{
    public const string DiagnosticId = "CSTSTR001";

    private static readonly DiagnosticDescriptor Rule = new(
        id: DiagnosticId,
        title: "String literals must use ClassStrings",
        messageFormat: "Move string literal to internal static ClassStrings and reference it from there",
        category: "Maintainability",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(Rule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeStringLiteral, SyntaxKind.StringLiteralExpression);
        context.RegisterSyntaxNodeAction(AnalyzeInterpolatedString, SyntaxKind.InterpolatedStringExpression);
    }

    private static void AnalyzeStringLiteral(SyntaxNodeAnalysisContext context)
    {
        var literal = (LiteralExpressionSyntax)context.Node;

        if (IsWithinAllowedStringContainer(literal))
        {
            return;
        }

        // If the literal is already being supplied via ClassStrings.* then it wouldn't be a literal.
        // This analyzer enforces removing literals entirely from non-ClassStrings code.
        context.ReportDiagnostic(Diagnostic.Create(Rule, literal.GetLocation()));
    }

    private static void AnalyzeInterpolatedString(SyntaxNodeAnalysisContext context)
    {
        var interpolated = (InterpolatedStringExpressionSyntax)context.Node;

        if (IsWithinAllowedStringContainer(interpolated))
        {
            return;
        }

        // Interpolated strings embed literal text. Prefer a format string in ClassStrings + string.Format.
        context.ReportDiagnostic(Diagnostic.Create(Rule, interpolated.GetLocation()));
    }

    private static bool IsWithinAllowedStringContainer(SyntaxNode node)
    {
        return node.AncestorsAndSelf().OfType<TypeDeclarationSyntax>().Any(t => t.Identifier.ValueText is "ClassStrings" or "AssemblyStrings");
    }
}
