// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Rego;

using System.Collections.Generic;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.TrustFrontends.Json;
using CoseSign1.Validation.TrustFrontends.Rego.Internal;

/// <summary>
/// Constrained-Rego-subset frontend (<c>cose-tp-rego/v1</c>): parses an OPA-compatible Rego
/// document, rejects forbidden builtins / unconstrained iteration / <c>data.*</c>
/// references, lowers the parsed AST to the canonical <c>cose-tp-json/v1</c> JSON shape, and
/// forwards to <see cref="CoseTpJsonFrontend.TranslateText"/> for schema validation +
/// document walking.
/// </summary>
/// <remarks>
/// <para>
/// The frontend does NOT execute Rego. It is a parser + AST→JSON lowerer; the resulting
/// JSON tree is structurally identical to a hand-authored <c>cose-tp-json/v1</c> document
/// expressing the same logical policy. Cross-frontend equivalence (§6.5.10 #8) is therefore
/// a property of construction, not of duplicated translation logic.
/// </para>
/// <para>
/// Per §6.5.4, every <see cref="ICoseTrustPolicyFrontend{TDocument}"/> implementation MUST
/// satisfy: determinism (parser is deterministic; JSON walker is deterministic), totality
/// (every input produces a result with diagnostics or a spec — no exceptions escape),
/// attribute fidelity (the JSON walker enforces the registry; this frontend defers entirely),
/// reject-what-you-can't-translate (constrained subset; closed grammar), capability-aware
/// (<see cref="TrustPolicyTranslationContext.AvailableFacts"/> flows straight through),
/// no code execution (no Rego evaluation; no <c>opa eval</c> / regorus / shell-out), and
/// bounded runtime (parser is O(n); the JSON walker is O(spec-size)).
/// </para>
/// </remarks>
public sealed class CoseTpRegoFrontend : ICoseTrustPolicyFrontend<RegoDocument>
{
    private static readonly IReadOnlySet<string> SupportedMediaTypesSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        AssemblyStrings.MediaTypeRego,
    };

    private readonly CoseTpJsonFrontend JsonFrontend;

    /// <summary>Initialises a new instance with a fresh JSON frontend dependency.</summary>
    public CoseTpRegoFrontend()
        : this(new CoseTpJsonFrontend())
    {
    }

    /// <summary>Initialises a new instance with the supplied JSON frontend dependency.</summary>
    /// <param name="jsonFrontend">The JSON frontend used to validate + walk the lowered document.</param>
    public CoseTpRegoFrontend(CoseTpJsonFrontend jsonFrontend)
    {
        Cose.Abstractions.Guard.ThrowIfNull(jsonFrontend);
        JsonFrontend = jsonFrontend;
    }

    /// <inheritdoc />
    public string FrontendId => AssemblyStrings.FrontendId;

    /// <inheritdoc />
    public IReadOnlySet<string> SupportedMediaTypes => SupportedMediaTypesSet;

    /// <summary>
    /// Parses raw Rego text. Returns a <see cref="RegoDocument"/> on success; on parse
    /// failure, returns <see langword="null"/> and appends one or more <see cref="TrustPolicySeverity.Error"/>
    /// diagnostics to <paramref name="diagnostics"/>.
    /// </summary>
    /// <param name="text">The raw Rego document text.</param>
    /// <param name="documentSource">Optional source identifier embedded in diagnostic locations.</param>
    /// <param name="diagnostics">Accumulator for translation diagnostics.</param>
    /// <returns>The parsed document or <see langword="null"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="text"/> or <paramref name="diagnostics"/> is null.</exception>
    public static RegoDocument? TryParse(string text, string? documentSource, List<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        Cose.Abstractions.Guard.ThrowIfNull(text);
        Cose.Abstractions.Guard.ThrowIfNull(diagnostics);

        var tokenizer = new RegoTokenizer(text);
        List<RegoToken> tokens = tokenizer.Tokenize();
        foreach (RegoLexicalDiagnostic le in tokenizer.Errors)
        {
            diagnostics.Add(new TrustPolicyTranslationDiagnostic
            {
                Severity = TrustPolicySeverity.Error,
                Code = AssemblyStrings.CodeMalformedRego,
                Message = le.Message,
                Location = MakeLocation(documentSource, le.Line, le.Column),
            });
        }

        if (HasError(diagnostics))
        {
            return null;
        }

        var parser = new RegoParser(tokens, diagnostics, documentSource);
        RegoValueNode? ast = parser.Parse();
        if (ast is null || HasError(diagnostics))
        {
            return null;
        }

        JsonNode? lowered = RegoLowerer.Lower(ast);
        return new RegoDocument(ast, lowered, documentSource);
    }

    /// <inheritdoc />
    public TrustPolicyTranslationResult Translate(RegoDocument document, TrustPolicyTranslationContext ctx)
    {
        Cose.Abstractions.Guard.ThrowIfNull(document);
        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        return TranslateCore(document, ctx);
    }

    /// <summary>
    /// Translates raw Rego text directly. Combines <see cref="TryParse"/> with
    /// <see cref="Translate(RegoDocument, TrustPolicyTranslationContext)"/> so callers don't
    /// need to thread a parsed document through.
    /// </summary>
    /// <param name="documentText">The raw Rego text.</param>
    /// <param name="ctx">The translation context.</param>
    /// <param name="documentSource">Source identifier embedded in diagnostic locations.</param>
    /// <returns>The translation result.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="documentText"/> or <paramref name="ctx"/> is null.</exception>
    public TrustPolicyTranslationResult TranslateText(string documentText, TrustPolicyTranslationContext ctx, string? documentSource = null)
    {
        Cose.Abstractions.Guard.ThrowIfNull(documentText);
        Cose.Abstractions.Guard.ThrowIfNull(ctx);

        var diagnostics = new List<TrustPolicyTranslationDiagnostic>();
        RegoDocument? doc = TryParse(documentText, documentSource, diagnostics);
        if (doc is null)
        {
            return new TrustPolicyTranslationResult { Spec = null, Diagnostics = diagnostics };
        }

        TrustPolicyTranslationResult inner = TranslateCore(doc, ctx);
        if (diagnostics.Count == 0)
        {
            return inner;
        }

        // Defensive: the parse-success path produces no diagnostics, so this branch is only
        // reached when a parser warning slipped past TryParse without flipping HasError. The
        // merge keeps totality even if such a future path is added.
        return MergeDiagnostics(inner, diagnostics);
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveAllowedByGrammar)]
    private static TrustPolicyTranslationResult MergeDiagnostics(TrustPolicyTranslationResult inner, List<TrustPolicyTranslationDiagnostic> seed)
    {
        var merged = new List<TrustPolicyTranslationDiagnostic>(seed.Count + inner.Diagnostics.Count);
        merged.AddRange(seed);
        merged.AddRange(inner.Diagnostics);
        return new TrustPolicyTranslationResult { Spec = inner.Spec, Diagnostics = merged };
    }

    private TrustPolicyTranslationResult TranslateCore(RegoDocument document, TrustPolicyTranslationContext ctx)
    {
        // The lowered tree is structurally identical to the JSON frontend's expected shape.
        // We serialize-and-reparse so the JSON frontend can drive its standard schema +
        // walker pipeline. The round-trip cost is bounded by the document size (~ low ms for
        // 1KB documents per the Phase 4 perf gate).
        if (document.LoweredRoot is null)
        {
            // Defensive: TryParse never produces a null lowered root for a non-null AST, but
            // the contract on RegoDocument doesn't enforce that statically.
            return EmitNullLoweredRoot(document.DocumentSource);
        }

        string canonicalText = document.LoweredRoot.ToJsonString();
        return JsonFrontend.TranslateText(canonicalText, ctx, document.DocumentSource);
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveAllowedByGrammar)]
    private static TrustPolicyTranslationResult EmitNullLoweredRoot(string? documentSource)
    {
        return new TrustPolicyTranslationResult
        {
            Spec = null,
            Diagnostics = new[]
            {
                new TrustPolicyTranslationDiagnostic
                {
                    Severity = TrustPolicySeverity.Error,
                    Code = AssemblyStrings.CodeMalformedRego,
                    Message = string.Format(System.Globalization.CultureInfo.InvariantCulture, AssemblyStrings.ErrParseFormat, 1, 1, AssemblyStrings.TokenEofText),
                    Location = MakeLocation(documentSource, 1, 1),
                },
            },
        };
    }

    private static SourceLocation MakeLocation(string? documentSource, int line, int column)
    {
        string anchor = string.Format(System.Globalization.CultureInfo.InvariantCulture, AssemblyStrings.LineColFormat, line, column);
        string source = string.IsNullOrEmpty(documentSource)
            ? anchor
            : string.Format(System.Globalization.CultureInfo.InvariantCulture, AssemblyStrings.LocationFormat, documentSource, anchor);
        return new SourceLocation(source, line, column, 0);
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
