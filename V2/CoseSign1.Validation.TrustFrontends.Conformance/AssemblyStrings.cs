// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

/// <summary>
/// Centralised user-visible literals for the conformance suite. The repo's
/// <c>StringLiteralAnalyzer</c> requires every test-failure message and diagnostic-style
/// constant to be sourced from a constants file rather than inlined.
/// </summary>
internal static class AssemblyStrings
{
    // Conformance fixture names used by the canonical fact-fidelity matrix. Each registered
    // fact id resolves to one fixture per predicate form: a property-assertion shorthand
    // and a path+operator universal predicate (D1 hybrid).
    internal const string FixtureSuffixPropertyForm = ".property";
    internal const string FixtureSuffixPathOperatorForm = ".path-operator";

    // Fixture sub-folders.
    internal const string FactsFolder = "facts";
    internal const string UntranslatableFolder = "untranslatable";
    internal const string ParametricFolder = "parametric";
    internal const string CapabilityFolder = "capability";
    internal const string SchemaFolder = "schema";
    internal const string PerfFolder = "perf";

    // Logical fixture names — the Conformance package owns the canonical names so frontends
    // ship matching documents under the same logical identifier. Cross-frontend equivalence
    // (§6.5.10 #8) keys off these identifiers.
    internal const string FixtureUntranslatableFreeText = "untranslatable/free-text-search";
    internal const string FixtureUntranslatableUnknownFact = "untranslatable/unknown-fact";
    internal const string FixtureUntranslatableUnknownOperator = "untranslatable/unknown-operator";
    internal const string FixtureCapabilityMissingFact = "capability/missing-fact";
    internal const string FixtureSchemaMalformedJson = "schema/malformed";
    internal const string FixtureSchemaShapeViolation = "schema/shape-violation";
    internal const string FixtureParametricHostBaseline = "parametric/host-baseline";
    internal const string FixtureParametricHostAlternate = "parametric/host-alternate";
    internal const string FixturePerfRepresentative = "perf/representative-1kb";
    internal const string FixtureCrossEquivalenceCanonical = "cross/canonical-policy";

    // §6.5.10 #6 parametric fixture parameter names.
    internal const string ParameterNameTrustedHost = "trusted_host";

    // §6.5.10 #4 perf-gate budgets (D11 — non-negotiable).
    internal const int PerfWarmupIterations = 10;
    internal const int PerfMeasuredIterations = 100;
    internal const double PerfBudgetP99Ms = 10.0;
    internal const double PerfBudgetMeanMs = 5.0;
    internal const int DocumentSizeUpperBoundBytes = 1024;

    // §6.5.10 #1 determinism iteration count (Phase 2 ships 1000; we keep the same level).
    internal const int DeterminismIterations = 1000;

    // §6.5.10 #3 cross-form rule-evaluation iteration count. The fact-fidelity test asserts
    // the property and path/operator forms produce predicates that agree on a small bag of
    // synthetic JSON projections — the runtime invariant the lowerer is required to honour.
    internal const int CrossFormProjectionsToTry = 4;

    // Canonical TPX diagnostic codes the conformance suite asserts. Sourced from
    // CoseSign1.Validation.TrustFrontends.Json.AssemblyStrings (see frontend README) but
    // pinned here so the conformance contract is independent of any one frontend.
    internal const string CodeMalformedJson = "TPX001";
    internal const string CodeSchemaValidation = "TPX100";
    internal const string CodeUnknownFactId = "TPX200";
    internal const string CodeUntranslatableNode = "TPX301";

    // Fixture / file extensions.
    internal const string FixtureExtensionDefault = ".coseTrustPolicy.json";

    // Failure messages.
    internal const string ErrFixtureNotFound = "Conformance fixture '{0}' was not registered by the adapter under '{1}/'. Add the fixture file or update the adapter's fixture map. The fact-fidelity test (§6.5.10 #2) requires a fixture per registered fact id in BOTH predicate forms.";
    internal const string ErrFactFixtureMissing = "No conformance fixture found for fact id '{0}' (form='{1}'). Every registered fact MUST have a {1} fixture so §6.5.10 #2 (attribute fidelity) holds.";
    internal const string ErrTranslationFailed = "Conformance fixture '{0}' failed to translate. Diagnostics: {1}";
    internal const string ErrTranslationUnexpectedlySucceeded = "Conformance fixture '{0}' was expected to fail with code '{1}' but translation succeeded.";
    internal const string ErrUnexpectedDiagnosticCode = "Conformance fixture '{0}' produced diagnostics {1} but expected at least one with code '{2}'.";
    internal const string ErrCanonicalDriftFormat = "Iteration {0} drifted from canonical projection. Expected '{1}'; got '{2}'.";
    internal const string ErrPerfP99FailureFormat = "p99 translation latency {0:F2}ms exceeds {1:F2}ms budget (mean {2:F2}ms over {3} samples). §6.5.10 #4 perf gate.";
    internal const string ErrPerfMeanFailureFormat = "Mean translation latency {0:F2}ms exceeds {1:F2}ms budget (p99 {2:F2}ms over {3} samples). Catches steady-state slowness even when p99 is fine. §6.5.10 #4 perf gate.";
    internal const string ErrPerfDocumentTooLarge = "Perf-gate fixture is {0} bytes; §6.5.10 #4 budget applies to documents ≤ {1} bytes.";
    internal const string ErrSourceLocationMissingFormat = "Diagnostic with code '{0}' on fixture '{1}' lacks a SourceLocation. §6.5.10 #7 requires malformed-document diagnostics carry navigable line/col.";
    internal const string ErrFactSpecScopeMismatchFormat = "Fact '{0}' fixture (form='{1}') compiled but did not produce a RequireFactSpec naming this fact id. Found spec: {2}";
    internal const string ErrCrossFormEvaluationDisagreesFormat = "Fact '{0}' cross-form predicates disagree on synthetic projection #{1}: property={2}, path-operator={3}. The two D1 forms MUST agree on every fact projection.";
    internal const string ErrParameterSubstitutionUnchanged = "Parametric fixture '{0}' produced byte-identical specs under '{1}={2}' and '{1}={3}' — parameter substitution did not affect the IR. §6.5.10 #6.";
    internal const string ErrCrossFrontendDriftFormat = "Cross-frontend pair ({0}, {1}) for logical fixture '{2}' produced different canonical IRs:\n {0}: {3}\n {1}: {4}";
    internal const string ErrCapabilityGateExpectedError = "Capability fixture '{0}' was expected to surface a {1} diagnostic when AvailableFacts excludes the referenced fact and AllowUnknownFacts=false.";
    internal const string ErrAdapterReturnedNullDocument = "Adapter '{0}' returned a null parsed document for fixture '{1}'.";

    // Justification strings (StyleCop / coverage exclusion).
    internal const string JustifyDefensiveAdapter = "Defensive — adapter contract guarantees a non-null fixture map; this branch protects against future adapter implementations that violate the contract.";

    // Path joins.
    internal const string PathSeparator = "/";

    // Diagnostic-rendering helpers.
    internal const string DiagnosticListSeparator = "; ";

    // Synthetic projection keys used by the fact-fidelity cross-form rule-evaluation gate.
    // The conformance suite walks the fact's reflected JSON projection shape and crafts a
    // small set of synthetic JsonObject instances whose property values trip predicates in
    // both directions (matching, non-matching, type-mismatched, missing).
    internal const string SyntheticProjectionVariantTrue = "true";
    internal const string SyntheticProjectionVariantFalse = "false";
    internal const string SyntheticProjectionVariantOther = "other";
    internal const string SyntheticProjectionVariantMissing = "missing";

    // Canonical $schema URL.
    internal const string CanonicalSchemaUrl = "https://raw.githubusercontent.com/microsoft/CoseSignTool/main/V2/schemas/cose-tp/v1.json";

    // Synthetic projection sentinels.
    internal const string SyntheticForeignSentinel = "__foreign__";
    internal const string SyntheticMismatchSentinel = "__mismatch__";

    // Test-category labels.
    internal const string CategoryConformance = "Conformance";
    internal const string CategoryConformanceDeterminism = "ConformanceDeterminism";
    internal const string CategoryConformancePerf = "ConformancePerf";
    internal const string CategoryConformanceCrossFrontend = "ConformanceCrossFrontend";

    // Format / message helpers (the analyzer rejects string literals outside ClassStrings /
    // AssemblyStrings, so every Assert.Fail / Assert.That message lives here).
    internal const string DocSummaryEmpty = "(none)";
    internal const string FormatFactFixtureNamePattern = "{0}/{1}{2}";
    internal const string FormatPredicateBracketOpen = "[";
    internal const string FormatPredicateBracketCloseSpace = "] ";
    internal const string ErrPropertyFixtureWrongPredicateTypeFormat = "Fact '{0}' property fixture should produce a PropertyAssertionPredicateSpec (form='{1}').";
    internal const string ErrPathOperatorFixtureWrongPredicateTypeFormat = "Fact '{0}' path-operator fixture should produce a PathOperatorPredicateSpec (form='{1}').";
    internal const string ErrPropertyFormCompileFailedFormat = "Property form fixture '{0}' must compile against the registry.";
    internal const string ErrPathOperatorFormCompileFailedFormat = "Path/operator form fixture '{0}' must compile against the registry.";
    internal const string ErrSameFixtureSameParamsMustAgree = "Same fixture + same params must produce byte-identical IRs (subset of §6.5.10 #1).";
    internal const string ErrAlternateFixtureCanonicalDriftFormat = "Alternate fixture must produce a distinct IR from the baseline fixture.";
    internal const string ErrMalformedJsonMissingErrorDiagnostic = "Malformed-JSON fixture must produce at least one Error diagnostic.";
    internal const string ErrFactIdNotRegisteredFormat = "Fact id '{0}' not registered. AttributeDrivenFactRegistry MUST resolve every id surfaced in the registry's AllFactIds enumeration.";
    internal const string ErrUnsupportedCrossFormOperatorFormat = "Path/operator fixture used unsupported operator '{0}' for cross-form agreement check. Conformance fact fixtures must use Equals / NotEquals / Exists for cross-form parity with property-shorthand.";
    internal const string ErrCrossFrontendFixtureFailedFormat = "Frontend '{0}' fixture '{1}' did not translate: {2}";
    internal const string ErrConformanceFixtureNotFoundFormat = "Conformance fixture '{0}' not found in the {1} adapter's fixture set.";
    internal const string ErrAdapterReturnedNullParse = "Adapter '{0}' returned a null parsed document for fixture '{1}'.";

    // Marker interface names — used by reflection-based scope inference. The conformance
    // suite tolerates assembly-rename / namespace-move by matching on simple type name.
    internal const string MarkerInterfaceMessageFact = "IMessageFact";
    internal const string MarkerInterfaceCounterSignatureFact = "ICounterSignatureFact";

    // String literals consumed by adapter implementations (test project consumers).
    internal const string TpxCodeMalformedJsonStringTag = "TPX001";
    internal const string DiagnosticEmptyTagError = "Error";
    internal const string DefaultParamHostBaselineValue = "issuer.example.com";
    internal const string DefaultParamHostDifferentValue = "different.example.com";
    internal const string DefaultParamHostAlternateValue = "alternate.example.com";
    internal const string PerfNoSamplesText = "(no samples)";
    internal const string PerfStatsFormat = "mean={0:F2}ms p99={1:F2}ms min={2:F2}ms max={3:F2}ms n={4}";
    internal const string DiagnosticListSeparatorChar = "; ";
    internal const string JustifyDefensiveLoadOrFail = "Defensive — adapter contract guarantees a non-null parsed document for every advertised fixture; this branch fires only on adapter implementation bugs and surfaces them as test failures.";
}
