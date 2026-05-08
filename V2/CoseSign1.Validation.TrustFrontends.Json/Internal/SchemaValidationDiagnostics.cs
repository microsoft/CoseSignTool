// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Internal;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using global::Json.Schema;

/// <summary>
/// Lifts JsonSchema.Net evaluation outcomes into <see cref="TrustPolicyTranslationDiagnostic"/>
/// values. Surfaces every leaf failure as a <c>TPX100</c> error with a JSON-pointer instance
/// location. Predicate-schema gating (D4) reuses the same machinery for per-fact predicate
/// schemas, emitting <c>TPX201</c> instead.
/// </summary>
internal static class SchemaValidationDiagnostics
{
    /// <summary>
    /// Validates <paramref name="document"/> against the embedded schema and appends one
    /// diagnostic per leaf failure to <paramref name="diagnostics"/>.
    /// </summary>
    /// <param name="document">The parsed JSON document tree (root element).</param>
    /// <param name="documentSource">Optional source identifier (e.g. file URI) included in diagnostic locations.</param>
    /// <param name="diagnostics">The accumulator the failures are appended to.</param>
    /// <returns><see langword="true"/> when the document validates; <see langword="false"/> otherwise.</returns>
    public static bool ValidateOrCollect(
        JsonElement document,
        string? documentSource,
        List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        EvaluationResults results = EmbeddedSchema.Get().Evaluate(document, BuildOptions());
        if (results.IsValid)
        {
            return true;
        }

        AppendLeafFailures(results, AssemblyStrings.CodeSchemaValidation, factId: null, predicatePointerOverride: null, documentSource, diagnostics);

        EnsureUmbrellaError(documentSource, diagnostics);

        return false;
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensive)]
    private static void EnsureUmbrellaError(string? documentSource, List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        if (HasError(diagnostics))
        {
            return;
        }

        // Defensive: JsonSchema.Net invariably populates leaf errors for !IsValid, but if a
        // future version inverts that contract, surface a single umbrella error so totality
        // (§6.5.4 #2) is preserved.
        diagnostics.Add(new TrustPolicyTranslationDiagnostic
        {
            Severity = TrustPolicySeverity.Error,
            Code = AssemblyStrings.CodeSchemaValidation,
            Message = string.Format(
                CultureInfo.InvariantCulture,
                AssemblyStrings.ErrSchemaValidationFormat,
                AssemblyStrings.SourcePointerRoot,
                AssemblyStrings.CodeSchemaValidation),
            Location = MakeLocation(documentSource, AssemblyStrings.SourcePointerRoot),
        });
    }

    /// <summary>
    /// Validates <paramref name="predicate"/> against an arbitrary capability-supplied schema
    /// (predicate-schema gating per D4). Returns <see langword="true"/> on success.
    /// </summary>
    /// <param name="predicate">The user's predicate JSON tree.</param>
    /// <param name="predicateSchemaNode">The host-supplied schema for the fact's predicate.</param>
    /// <param name="factId">The fact id whose predicate is being validated.</param>
    /// <param name="predicatePointer">JSON-pointer path to the predicate in the source document.</param>
    /// <param name="documentSource">Optional source identifier embedded in diagnostic locations.</param>
    /// <param name="diagnostics">The accumulator the failures are appended to.</param>
    /// <returns><see langword="true"/> when the predicate validates against the schema.</returns>
    public static bool ValidatePredicateAgainstSchema(
        JsonNode? predicate,
        JsonNode predicateSchemaNode,
        string factId,
        string predicatePointer,
        string? documentSource,
        List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        JsonSchema schema;
        try
        {
            schema = JsonSchema.FromText(predicateSchemaNode.ToJsonString());
        }
        catch (Exception ex) when (ex is FormatException or JsonException or global::Json.Schema.JsonSchemaException)
        {
            diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodePredicateSchemaMismatch,
                Message = string.Format(
                    CultureInfo.InvariantCulture,
                    AssemblyStrings.ErrPredicateSchemaMismatchFormat,
                    factId,
                    predicatePointer,
                    ex.Message),
                Location = MakeLocation(documentSource, predicatePointer),
            });
            return false;
        }

        JsonElement predicateElement = ToElement(predicate);
        EvaluationResults results = schema.Evaluate(predicateElement, BuildOptions());
        if (results.IsValid)
        {
            return true;
        }

        AppendLeafFailures(results, AssemblyStrings.CodePredicateSchemaMismatch, factId, predicatePointer, documentSource, diagnostics);
        return false;
    }

    private static EvaluationOptions BuildOptions() => new()
    {
        OutputFormat = OutputFormat.Hierarchical,
    };

    private static JsonElement ToElement(JsonNode? node)
    {
        // JsonSchema.Net 9.x's Evaluate signature accepts JsonElement; project the JsonNode to
        // an element via the canonical text round-trip. The cost is negligible for predicates.
        if (node is null)
        {
            using JsonDocument nullDoc = JsonDocument.Parse(AssemblyStrings.NullValueLiteral);
            return nullDoc.RootElement.Clone();
        }

        using JsonDocument doc = JsonDocument.Parse(node.ToJsonString());
        return doc.RootElement.Clone();
    }

    private static bool HasError(List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        for (int i = 0; i < diagnostics.Count; i++)
        {
            if (diagnostics[i].Severity == TrustPolicySeverity.Error)
            {
                return true;
            }
        }

        return false;
    }

    private static void AppendLeafFailures(
        EvaluationResults node,
        string diagnosticCode,
        string? factId,
        string? predicatePointerOverride,
        string? documentSource,
        List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        if (!node.IsValid && node.Errors is { Count: > 0 } errors)
        {
            string pointerText = predicatePointerOverride ?? PointerOf(node);

            foreach (KeyValuePair<string, string> entry in errors)
            {
                string formatted = factId is null
                    ? string.Format(
                        CultureInfo.InvariantCulture,
                        AssemblyStrings.ErrSchemaValidationFormat,
                        pointerText,
                        entry.Value)
                    : string.Format(
                        CultureInfo.InvariantCulture,
                        AssemblyStrings.ErrPredicateSchemaMismatchFormat,
                        factId,
                        pointerText,
                        entry.Value);

                diagnostics.Add(new TrustPolicyTranslationDiagnostic
                {
                    Severity = TrustPolicySeverity.Error,
                    Code = diagnosticCode,
                    Message = formatted,
                    Location = MakeLocation(documentSource, pointerText),
                });
            }
        }

        if (node.Details is { Count: > 0 } details)
        {
            foreach (EvaluationResults child in details)
            {
                AppendLeafFailures(child, diagnosticCode, factId, predicatePointerOverride, documentSource, diagnostics);
            }
        }
    }

    private static string PointerOf(EvaluationResults node)
    {
        string pointer = node.InstanceLocation.ToString();
        return string.IsNullOrEmpty(pointer) ? AssemblyStrings.SourcePointerRoot : pointer;
    }

    private static SourceLocation MakeLocation(string? source, string pointer)
    {
        string sourceText = string.IsNullOrEmpty(source)
            ? pointer
            : string.Format(CultureInfo.InvariantCulture, AssemblyStrings.LocationWithSourceFormat, source, pointer);
        return new SourceLocation(sourceText, 0, 0, 0);
    }
}
