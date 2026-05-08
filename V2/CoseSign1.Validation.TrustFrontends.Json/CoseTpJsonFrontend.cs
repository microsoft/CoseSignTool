// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.TrustFrontends.Json.Internal;

/// <summary>
/// Canonical reference frontend (<c>cose-tp-json/v1</c>): parses JSONC, validates against the
/// embedded schema, walks the document into a <see cref="TrustPolicySpec"/>, and surfaces
/// diagnostics with JSON-pointer source locations.
/// </summary>
/// <remarks>
/// <para>
/// Implements the eight translation guarantees of §6.5.4: the spec is byte-deterministic for
/// equal inputs (asserted by tests), totality holds (every parse-success → spec OR error),
/// fact attribute fidelity is enforced via Phase 3's registry, capability gating runs against
/// <see cref="TrustPolicyTranslationContext.AvailableFacts"/>, no code execution occurs (pure
/// data walks only), and runtime is bounded.
/// </para>
/// <para>
/// JSONC ergonomics — comments and trailing commas — are handled by the
/// <see cref="JsonDocumentOptions"/> exposed via <see cref="CoseTpJsonOptions.ParseOptions"/>;
/// no string-pre-processing pass strips comments. After
/// <see cref="JsonDocument.Parse(string, JsonDocumentOptions)"/> returns, the comment text is
/// gone, and the canonical IR's serializer never re-emits comments.
/// </para>
/// </remarks>
public sealed class CoseTpJsonFrontend : ICoseTrustPolicyFrontend<JsonDocument>
{
    private static readonly IReadOnlySet<string> SupportedMediaTypesSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        AssemblyStrings.MediaTypeJson,
        AssemblyStrings.MediaTypeJsonc,
    };

    /// <inheritdoc />
    public string FrontendId => AssemblyStrings.FrontendId;

    /// <inheritdoc />
    public IReadOnlySet<string> SupportedMediaTypes => SupportedMediaTypesSet;

    /// <summary>Gets the canonical <c>$schema</c> URL the frontend recognises.</summary>
    public static string SchemaUrl => AssemblyStrings.SchemaUrl;

    /// <summary>
    /// Gets the on-disk schema file's logical resource name as embedded in this assembly. The
    /// drift-assertion test compares this resource's bytes to <c>V2/schemas/cose-tp/v1.json</c>.
    /// </summary>
    public static string EmbeddedSchemaResourceName => AssemblyStrings.SchemaResourceName;

    /// <summary>
    /// Returns the raw bytes of the embedded schema. Used by tests to detect drift between
    /// the on-disk schema and the embedded copy.
    /// </summary>
    /// <returns>The embedded schema file's bytes (UTF-8).</returns>
    public static byte[] GetEmbeddedSchemaBytes() => EmbeddedSchema.GetBytes();

    /// <summary>
    /// Parses raw JSONC text into a <see cref="JsonDocument"/> using
    /// <see cref="CoseTpJsonOptions.ParseOptions"/> (comments + trailing commas allowed). Errors
    /// are surfaced as <see cref="TrustPolicyTranslationDiagnostic"/> in <paramref name="diagnostics"/>;
    /// the method returns <see langword="null"/> on malformed input.
    /// </summary>
    /// <param name="text">The raw document text.</param>
    /// <param name="documentSource">Optional source identifier embedded in diagnostic locations.</param>
    /// <param name="diagnostics">Accumulator for translation diagnostics.</param>
    /// <returns>The parsed document, or <see langword="null"/> on a syntax error.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="text"/> or <paramref name="diagnostics"/> is null.</exception>
    public static JsonDocument? TryParse(string text, string? documentSource, List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        Cose.Abstractions.Guard.ThrowIfNull(text);
        Cose.Abstractions.Guard.ThrowIfNull(diagnostics);

        try
        {
            return JsonDocument.Parse(text, CoseTpJsonOptions.ParseOptions);
        }
        catch (JsonException ex)
        {
            diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodeMalformedJson,
                Message = string.Format(
                    CultureInfo.InvariantCulture,
                    AssemblyStrings.ErrMalformedJsonFormat,
                    ex.Message),
                Location = new SourceLocation(documentSource, MaxOne(ex.LineNumber.GetValueOrDefault()), MaxOne(ex.BytePositionInLine.GetValueOrDefault()), 0),
            });
            return null;
        }
    }

    /// <inheritdoc />
    public TrustPolicyTranslationResult Translate(JsonDocument document, TrustPolicyTranslationContext ctx)
    {
        Cose.Abstractions.Guard.ThrowIfNull(document);
        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        return TranslateCore(document, ctx, documentSource: null);
    }

    /// <summary>
    /// Translates <paramref name="document"/> while preserving an external
    /// <paramref name="documentSource"/> (e.g. file URI) in emitted diagnostics' source locations.
    /// </summary>
    /// <param name="document">The parsed document.</param>
    /// <param name="ctx">The translation context.</param>
    /// <param name="documentSource">Source identifier embedded in diagnostic locations.</param>
    /// <returns>The translation result.</returns>
    public TrustPolicyTranslationResult Translate(JsonDocument document, TrustPolicyTranslationContext ctx, string? documentSource)
    {
        Cose.Abstractions.Guard.ThrowIfNull(document);
        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        return TranslateCore(document, ctx, documentSource);
    }

    /// <summary>
    /// Translates raw text directly. Combines <see cref="TryParse"/>, schema validation, and the
    /// document walk into one call. Comments and trailing commas are accepted.
    /// </summary>
    /// <param name="documentText">The raw document text.</param>
    /// <param name="ctx">The translation context.</param>
    /// <param name="documentSource">Source identifier embedded in diagnostic locations.</param>
    /// <returns>The translation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="documentText"/> or <paramref name="ctx"/> is null.</exception>
    public TrustPolicyTranslationResult TranslateText(string documentText, TrustPolicyTranslationContext ctx, string? documentSource = null)
    {
        Cose.Abstractions.Guard.ThrowIfNull(documentText);
        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        using JsonDocument? doc = TryParse(documentText, documentSource, diagnostics);
        if (doc is null)
        {
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        TrustPolicyTranslationResult parsed = TranslateCore(doc, ctx, documentSource, diagnostics);
        return parsed;
    }

    private static int MaxOne(long value) => value <= 0 ? 0 : checked((int)value);

    private static TrustPolicyTranslationResult TranslateCore(
        JsonDocument document,
        TrustPolicyTranslationContext ctx,
        string? documentSource,
        List<TrustPolicyTranslationDiagnostic>? seedDiagnostics = null)
    {
        List<TrustPolicyTranslationDiagnostic> diagnostics = seedDiagnostics ?? new List<TrustPolicyTranslationDiagnostic>();

        // Schema-validate against the JsonElement directly (JsonSchema.Net 9.x's Evaluate is
        // JsonElement-shaped). The walk uses the JsonNode projection of the same bytes so the
        // canonical pointer paths align between validator output and translator output.
        if (!SchemaValidationDiagnostics.ValidateOrCollect(document.RootElement, documentSource, diagnostics))
        {
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        JsonNode? root = JsonNode.Parse(document.RootElement.GetRawText());
        if (root is not JsonObject rootObj)
        {
            diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodeMalformedJson,
                Message = AssemblyStrings.ErrUnsupportedDocumentNullSpec,
                Location = new SourceLocation(documentSource, 0, 0, 0),
            });
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        var translator = new DocumentTranslator(ctx, documentSource, diagnostics);
        TrustPolicySpec spec = translator.WalkRoot(rootObj);

        if (HasError(diagnostics))
        {
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        return new TrustPolicyTranslationResult { Spec = spec, Diagnostics = diagnostics };
    }

    private static bool HasError(IReadOnlyList<TrustPolicyTranslationDiagnostic> diagnostics)
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
}
