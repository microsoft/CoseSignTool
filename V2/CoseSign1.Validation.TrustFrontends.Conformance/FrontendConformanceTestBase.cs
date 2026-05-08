// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.Trust.PlanPolicy.Spec;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Combinators;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Compilation;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Diagnostics;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Json;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Predicates;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Requirements;
using CoseSign1.Validation.Trust.Rules;
using NUnit.Framework;

/// <summary>
/// Reusable conformance test suite covering §6.5.10's eight ship-eligibility properties.
/// Frontend test projects derive a sealed test fixture from this class, provide an adapter,
/// and NUnit auto-discovers the inherited <c>[Test]</c> methods. The base class is generic in
/// the parsed-document type so each frontend stays statically typed; it never reflects over
/// the document.
/// </summary>
/// <typeparam name="TDocument">The frontend's parsed-document type.</typeparam>
/// <remarks>
/// <para>
/// The eight properties (see <see href="../README.md"/>):
/// <list type="number">
///   <item>Determinism — same <c>(doc, params)</c> ×N → byte-identical canonical IR.</item>
///   <item>Attribute fidelity — every registered fact has a frontend example for both
///         predicate forms; both forms agree on synthetic projections (D1 invariant).</item>
///   <item>Reject untranslatable — free-text/aggregations/joins → Error diagnostic.</item>
///   <item>Bounded runtime — 1KB doc, p99 ≤ 10ms AND mean ≤ 5ms (statistical).</item>
///   <item>Capability-aware — missing fact id with AllowUnknownFacts=false → TPX200.</item>
///   <item>Parameter substitution — same doc + different <c>$param</c> → different IRs.</item>
///   <item>Schema validation — malformed → diagnostic with SourceLocation.</item>
///   <item>Cross-frontend equivalence — same logical policy → equal IRs (degenerate harness
///         in Phase 4; Phase 5a Rego frontend lights it up properly).</item>
/// </list>
/// </para>
/// <para>
/// Why a base class rather than [TestCaseSource]-driven templating? Two reasons. First, NUnit
/// inheritance gives natural per-test-method assertion granularity in CI output (each
/// <c>Conformance_N_*</c> shows up as a discrete test, so a regression in #4 doesn't mask #5).
/// Second, a base class can hold per-fixture cached parsed documents — re-parsing 1000× per
/// test would dilute the runtime budget under #4.
/// </para>
/// <para>
/// CRITICAL FOR FRONTEND AUTHORS: derive your test class as <c>[TestFixture] public class
/// MyFrontendConformanceTests : FrontendConformanceTestBase&lt;MyDocument&gt;</c>. NUnit
/// requires a non-abstract concrete fixture to discover the base's <c>[Test]</c> methods.
/// </para>
/// </remarks>
public abstract class FrontendConformanceTestBase<TDocument>
    where TDocument : class
{
    private IConformanceFrontendAdapter<TDocument>? AdapterInstance;
    private IFactRegistry? Registry;

    /// <summary>
    /// Creates the adapter under test. Called once per test fixture; the result is cached.
    /// </summary>
    /// <returns>A non-null adapter.</returns>
    protected abstract IConformanceFrontendAdapter<TDocument> CreateAdapter();

    /// <summary>
    /// Creates the fact registry the conformance suite drives off. Default implementation
    /// uses <see cref="AttributeDrivenFactRegistry.FromLoadedAssemblies"/>; frontend authors
    /// override only when they need to constrain the catalogue (e.g. integration tests over a
    /// reduced assembly set).
    /// </summary>
    /// <returns>The fact registry.</returns>
    protected virtual IFactRegistry CreateFactRegistry() => AttributeDrivenFactRegistry.FromLoadedAssemblies();

    /// <summary>Gets the adapter under test (cached after first call).</summary>
    protected IConformanceFrontendAdapter<TDocument> Adapter => AdapterInstance ??= CreateAdapter();

    /// <summary>Gets the fact registry (cached after first call).</summary>
    protected IFactRegistry FactRegistry => Registry ??= CreateFactRegistry();

    /// <summary>
    /// §6.5.10 #1 — Determinism. Translate the perf representative fixture
    /// <see cref="AssemblyStrings.DeterminismIterations"/> times and assert every iteration's
    /// canonical-JSON projection matches the first.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformanceDeterminism)]
    public void Conformance_1_Determinism_SameInputProducesByteIdenticalSpec()
    {
        TDocument doc = LoadOrFail(AssemblyStrings.FixturePerfRepresentative);
        TrustPolicyTranslationContext ctx = new();

        TrustPolicyTranslationResult first = Adapter.Translate(doc, ctx);
        AssertSuccess(first, AssemblyStrings.FixturePerfRepresentative);

        string canonical = TrustPolicySpecSerializer.ToCanonicalJson(first.Spec!);

        for (int i = 0; i < AssemblyStrings.DeterminismIterations; i++)
        {
            TrustPolicyTranslationResult next = Adapter.Translate(doc, ctx);
            AssertSuccess(next, AssemblyStrings.FixturePerfRepresentative);
            string nextCanonical = TrustPolicySpecSerializer.ToCanonicalJson(next.Spec!);

            // Surface the deviating iteration in the failure message so a flaky frontend
            // shows where the drift happened (e.g. iteration 17 — stateful mutation around
            // the cache boundary).
            Assert.That(
                nextCanonical,
                Is.EqualTo(canonical),
                () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCanonicalDriftFormat, i, canonical, nextCanonical));
        }
    }

    /// <summary>
    /// §6.5.10 #2 — Attribute fidelity. Every registered fact has a fixture for both
    /// predicate forms; both forms translate to a <see cref="RequireFactSpec"/> referencing
    /// the matching fact id; both forms compile cleanly and produce predicates that agree on
    /// a small bag of synthetic JSON projections (the runtime invariant the lowerer
    /// guarantees per D1).
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformance)]
    public void Conformance_2_AttributeFidelity_EveryFactHasBothFormsAndCrossFormAgrees()
    {
        IConformanceFrontendAdapter<TDocument> adapter = Adapter;
        IFactRegistry registry = FactRegistry;
        IReadOnlySet<string> provided = adapter.ProvidedFixtureNames;

        // 1) Existence: every required (factId, form) pair appears in the adapter's fixture map.
        foreach (string factId in registry.AllFactIds)
        {
            string propertyForm = ConformanceFixtureNaming.FactFixtureName(factId, ConformanceFixtureNaming.PropertyFormSuffix);
            string pathOperatorForm = ConformanceFixtureNaming.FactFixtureName(factId, ConformanceFixtureNaming.PathOperatorFormSuffix);

            Assert.That(provided, Contains.Item(propertyForm), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrFactFixtureMissing, factId, ConformanceFixtureNaming.PropertyFormSuffix));
            Assert.That(provided, Contains.Item(pathOperatorForm), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrFactFixtureMissing, factId, ConformanceFixtureNaming.PathOperatorFormSuffix));

            // 2) Translatability + RequireFactSpec emission: both forms produce a spec
            //    containing a RequireFactSpec naming the fact id.
            RequireFactSpec propertySpec = LoadAndExtractRequireFact(propertyForm, factId);
            RequireFactSpec pathOperatorSpec = LoadAndExtractRequireFact(pathOperatorForm, factId);

            // Capture the predicate kinds — we expect property form → PropertyAssertionPredicateSpec
            // and path/operator form → PathOperatorPredicateSpec; the IR keeps both first-class
            // per D1's hybrid contract.
            Assert.That(propertySpec.Predicate, Is.InstanceOf<PropertyAssertionPredicateSpec>(), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPropertyFixtureWrongPredicateTypeFormat, factId, ConformanceFixtureNaming.PropertyFormSuffix));
            Assert.That(pathOperatorSpec.Predicate, Is.InstanceOf<PathOperatorPredicateSpec>(), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPathOperatorFixtureWrongPredicateTypeFormat, factId, ConformanceFixtureNaming.PathOperatorFormSuffix));

            // 3) Compile both forms — both must compile without error against the registry.
            //    This is the bridge between the IR-level fixture and the runtime-evaluation
            //    invariant.
            Assert.DoesNotThrow(() => TrustPolicySpecCompiler.Compile(WrapInScope(propertySpec, factId), registry), string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPropertyFormCompileFailedFormat, propertyForm));
            Assert.DoesNotThrow(() => TrustPolicySpecCompiler.Compile(WrapInScope(pathOperatorSpec, factId), registry), string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPathOperatorFormCompileFailedFormat, pathOperatorForm));

            // 4) Cross-form rule-evaluation invariant: both predicates must agree on a small
            //    bag of synthetic JSON projections. We synthesise projections by walking the
            //    PropertyAssertionPredicateSpec keys and supplying matching / mismatching /
            //    missing values. PredicateLowerer compiles to a Func<object,bool> that uses
            //    the JsonNode projection of an object instance, so we evaluate in the same
            //    JsonNode space directly.
            AssertCrossFormAgreement(factId, propertySpec, pathOperatorSpec);
        }
    }

    /// <summary>
    /// §6.5.10 #3 — Reject untranslatable. Documents using free-text search, unknown fact
    /// ids, or unsupported operators MUST surface an Error-severity diagnostic and produce a
    /// null spec. The test runs translation with <see cref="TrustPolicyTranslationContext.AvailableFacts"/>
    /// populated from the live registry so frontends that gate at translation time fire on
    /// the unknown-fact fixture; schema-rejected fixtures fire regardless.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformance)]
    public void Conformance_3_RejectUntranslatable_ProducesErrorDiagnostic()
    {
        AssertRejected(AssemblyStrings.FixtureUntranslatableFreeText);
        AssertRejected(AssemblyStrings.FixtureUntranslatableUnknownFact);
        AssertRejected(AssemblyStrings.FixtureUntranslatableUnknownOperator);
    }

    /// <summary>
    /// §6.5.10 #4 — Bounded runtime. The perf-representative fixture (≤ 1KB) MUST translate
    /// at p99 ≤ 10ms AND mean ≤ 5ms over <see cref="AssemblyStrings.PerfMeasuredIterations"/>
    /// samples after <see cref="AssemblyStrings.PerfWarmupIterations"/> warm-up runs. The
    /// dual budget catches both outliers (p99) and steady-state slowness (mean).
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformancePerf)]
    public void Conformance_4_BoundedRuntime_OneKbDocMeetsP99AndMeanBudgets()
    {
        // The fixture is loaded as raw text so the byte-count assertion is meaningful (the
        // parsed-document representation is frontend-defined and may differ in size).
        string text = Adapter.LoadFixtureText(AssemblyStrings.FixturePerfRepresentative);
        int bytes = Encoding.UTF8.GetByteCount(text);
        Assert.That(bytes, Is.LessThanOrEqualTo(AssemblyStrings.DocumentSizeUpperBoundBytes), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPerfDocumentTooLarge, bytes, AssemblyStrings.DocumentSizeUpperBoundBytes));

        TDocument doc = LoadOrFail(AssemblyStrings.FixturePerfRepresentative);
        TrustPolicyTranslationContext ctx = new();

        // Sample under the full Translate(TDocument, ctx) entry point — that's the same
        // method shipped frontends route through and is the realistic workload.
        double[] samples = PerfBudget.Capture(() => Adapter.Translate(doc, ctx));
        double p99 = PerfBudget.P99(samples);
        double mean = PerfBudget.Mean(samples);

        Assert.That(p99, Is.LessThanOrEqualTo(AssemblyStrings.PerfBudgetP99Ms), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPerfP99FailureFormat, p99, AssemblyStrings.PerfBudgetP99Ms, mean, samples.Length));
        Assert.That(mean, Is.LessThanOrEqualTo(AssemblyStrings.PerfBudgetMeanMs), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrPerfMeanFailureFormat, mean, AssemblyStrings.PerfBudgetMeanMs, p99, samples.Length));
    }

    /// <summary>
    /// §6.5.10 #5 — Capability-aware. When <see cref="FactCapabilities.AvailableFactIds"/>
    /// excludes the fact id referenced by the fixture AND
    /// <see cref="TrustPolicyTranslationContext.AllowUnknownFacts"/> is false (default), the
    /// translator MUST emit a TPX200 error naming the missing fact.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformance)]
    public void Conformance_5_CapabilityAware_MissingFactIdProducesTpx200()
    {
        TDocument doc = LoadOrFail(AssemblyStrings.FixtureCapabilityMissingFact);

        // Empty capability set: no fact ids advertised at all, so the fixture's referenced
        // fact id is by definition missing. AllowUnknownFacts defaults to false — the
        // capability gate fires.
        TrustPolicyTranslationContext ctx = new()
        {
            AvailableFacts = new FactCapabilities { AvailableFactIds = new HashSet<string>(StringComparer.Ordinal) },
        };

        TrustPolicyTranslationResult result = Adapter.Translate(doc, ctx);

        Assert.That(result.IsSuccess, Is.False, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCapabilityGateExpectedError, AssemblyStrings.FixtureCapabilityMissingFact, AssemblyStrings.CodeUnknownFactId));
        Assert.That(result.Diagnostics.Any(d => d.Code == AssemblyStrings.CodeUnknownFactId && d.Severity == TrustPolicySeverity.Error), Is.True, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedDiagnosticCode, AssemblyStrings.FixtureCapabilityMissingFact, RenderDiagnostics(result.Diagnostics), AssemblyStrings.CodeUnknownFactId));
    }

    /// <summary>
    /// §6.5.10 #6 — Parameter substitution. The same parametric document under two distinct
    /// parameter values produces two distinct IRs; the same document under equal parameter
    /// values produces byte-identical IRs. Combined: parameter binding affects IR output and
    /// is deterministic.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformance)]
    public void Conformance_6_ParameterSubstitution_DifferentValuesProduceDifferentIrs()
    {
        TDocument baselineDoc = LoadOrFail(AssemblyStrings.FixtureParametricHostBaseline);
        TDocument alternateDoc = LoadOrFail(AssemblyStrings.FixtureParametricHostAlternate);

        // Same fixture, same parameter value → byte-identical canonical IR. Locks the
        // determinism-under-binding subset of #1 specifically through the binder seam.
        TrustPolicyTranslationResult baselineRunA = TranslateWithParam(baselineDoc, AssemblyStrings.ParameterNameTrustedHost, AssemblyStrings.DefaultParamHostBaselineValue);
        TrustPolicyTranslationResult baselineRunB = TranslateWithParam(baselineDoc, AssemblyStrings.ParameterNameTrustedHost, AssemblyStrings.DefaultParamHostBaselineValue);
        AssertSuccess(baselineRunA, AssemblyStrings.FixtureParametricHostBaseline);
        AssertSuccess(baselineRunB, AssemblyStrings.FixtureParametricHostBaseline);
        string canonicalRunA = TrustPolicySpecSerializer.ToCanonicalJson(baselineRunA.Spec!);
        string canonicalRunB = TrustPolicySpecSerializer.ToCanonicalJson(baselineRunB.Spec!);
        Assert.That(canonicalRunB, Is.EqualTo(canonicalRunA), AssemblyStrings.ErrSameFixtureSameParamsMustAgree);

        // Same fixture under a different parameter → different canonical IR. The §6.5.10 #6
        // contract: parameter substitution is observable in the IR.
        TrustPolicyTranslationResult differentValueRun = TranslateWithParam(baselineDoc, AssemblyStrings.ParameterNameTrustedHost, AssemblyStrings.DefaultParamHostDifferentValue);
        AssertSuccess(differentValueRun, AssemblyStrings.FixtureParametricHostBaseline);
        string canonicalDifferent = TrustPolicySpecSerializer.ToCanonicalJson(differentValueRun.Spec!);
        Assert.That(canonicalDifferent, Is.Not.EqualTo(canonicalRunA), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrParameterSubstitutionUnchanged, AssemblyStrings.FixtureParametricHostBaseline, AssemblyStrings.ParameterNameTrustedHost, AssemblyStrings.DefaultParamHostBaselineValue, AssemblyStrings.DefaultParamHostDifferentValue));

        // Different document targeting the same parameter — exists primarily to keep the
        // alternate fixture loaded by the suite (so the harness asserts the adapter actually
        // ships it) and to provide a third axis of variation. Translating it confirms the
        // harness handles a non-default parameter shape.
        TrustPolicyTranslationResult alternateRun = TranslateWithParam(alternateDoc, AssemblyStrings.ParameterNameTrustedHost, AssemblyStrings.DefaultParamHostAlternateValue);
        AssertSuccess(alternateRun, AssemblyStrings.FixtureParametricHostAlternate);
        Assert.That(TrustPolicySpecSerializer.ToCanonicalJson(alternateRun.Spec!), Is.Not.EqualTo(canonicalRunA), AssemblyStrings.ErrAlternateFixtureCanonicalDriftFormat);
    }

    /// <summary>
    /// §6.5.10 #7 — Schema validation. A malformed-JSON document MUST surface a parse-error
    /// diagnostic carrying a non-null <see cref="SourceLocation"/> so authors / IDE tooling
    /// can navigate to the offending site. A separately-malformed shape-violation document
    /// MUST surface a TPX100 schema-validation error.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformance)]
    public void Conformance_7_SchemaValidation_MalformedDocumentProducesNavigableDiagnostic()
    {
        // Malformed JSON — the frontend's text-entry overload routes the parser exception
        // into a TPX001 (or equivalent) diagnostic with a SourceLocation.
        string malformedText = Adapter.LoadFixtureText(AssemblyStrings.FixtureSchemaMalformedJson);
        TrustPolicyTranslationResult malformed = Adapter.TranslateText(malformedText, new TrustPolicyTranslationContext());
        Assert.That(malformed.IsSuccess, Is.False, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrTranslationUnexpectedlySucceeded, AssemblyStrings.FixtureSchemaMalformedJson, AssemblyStrings.TpxCodeMalformedJsonStringTag));
        TrustPolicyTranslationDiagnostic? parseError = malformed.Diagnostics.FirstOrDefault(d => d.Severity == TrustPolicySeverity.Error);
        Assert.That(parseError, Is.Not.Null, AssemblyStrings.ErrMalformedJsonMissingErrorDiagnostic);
        Assert.That(parseError!.Location, Is.Not.Null, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrSourceLocationMissingFormat, parseError.Code, AssemblyStrings.FixtureSchemaMalformedJson));

        // Shape violation — JSON is well-formed but does not match the canonical schema.
        // Frontends MUST surface a TPX100 (or equivalent schema-validation) diagnostic with
        // a SourceLocation pointing at the offending instance.
        string shapeViolationText = Adapter.LoadFixtureText(AssemblyStrings.FixtureSchemaShapeViolation);
        TrustPolicyTranslationResult shapeViolation = Adapter.TranslateText(shapeViolationText, new TrustPolicyTranslationContext());
        Assert.That(shapeViolation.IsSuccess, Is.False, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrTranslationUnexpectedlySucceeded, AssemblyStrings.FixtureSchemaShapeViolation, AssemblyStrings.CodeSchemaValidation));
        TrustPolicyTranslationDiagnostic? schemaError = shapeViolation.Diagnostics.FirstOrDefault(d => d.Severity == TrustPolicySeverity.Error && d.Code == AssemblyStrings.CodeSchemaValidation);
        Assert.That(schemaError, Is.Not.Null, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedDiagnosticCode, AssemblyStrings.FixtureSchemaShapeViolation, RenderDiagnostics(shapeViolation.Diagnostics), AssemblyStrings.CodeSchemaValidation));
        Assert.That(schemaError!.Location, Is.Not.Null, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrSourceLocationMissingFormat, schemaError.Code, AssemblyStrings.FixtureSchemaShapeViolation));
    }

    /// <summary>
    /// §6.5.10 #8 — Cross-frontend equivalence (single-frontend lock). Phase 4 ships only the
    /// JSON frontend, so the canonical "same logical policy" pair degenerates to (json, json)
    /// using the canonical-equivalence fixture. Two parallel adapter instances translate the
    /// same logical fixture; the canonical IRs must match. When Phase 5a Rego frontend lands,
    /// <see cref="CrossFrontendEquivalenceTestBase{TDocumentA, TDocumentB}"/> picks up the
    /// (json, rego) pair without code change.
    /// </summary>
    [Test]
    [Category(AssemblyStrings.CategoryConformanceCrossFrontend)]
    public void Conformance_8_CrossFrontendEquivalence_LocksHarnessAtSingleFrontend()
    {
        IConformanceFrontendAdapter<TDocument> adapterA = CreateAdapter();
        IConformanceFrontendAdapter<TDocument> adapterB = CreateAdapter();

        TDocument docA = LoadOrFailFor(adapterA, AssemblyStrings.FixtureCrossEquivalenceCanonical);
        TDocument docB = LoadOrFailFor(adapterB, AssemblyStrings.FixtureCrossEquivalenceCanonical);

        TrustPolicyTranslationResult resultA = adapterA.Translate(docA, new TrustPolicyTranslationContext());
        TrustPolicyTranslationResult resultB = adapterB.Translate(docB, new TrustPolicyTranslationContext());

        AssertSuccess(resultA, AssemblyStrings.FixtureCrossEquivalenceCanonical);
        AssertSuccess(resultB, AssemblyStrings.FixtureCrossEquivalenceCanonical);

        string canonicalA = TrustPolicySpecSerializer.ToCanonicalJson(resultA.Spec!);
        string canonicalB = TrustPolicySpecSerializer.ToCanonicalJson(resultB.Spec!);

        Assert.That(canonicalB, Is.EqualTo(canonicalA), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCrossFrontendDriftFormat, adapterA.FrontendId, adapterB.FrontendId, AssemblyStrings.FixtureCrossEquivalenceCanonical, canonicalA, canonicalB));
    }

    /// <summary>
    /// Loads a parsed document for the given logical fixture name; raises a test failure when
    /// the adapter does not advertise the name or returns a null parse.
    /// </summary>
    /// <param name="name">The logical fixture name.</param>
    /// <returns>The non-null parsed document.</returns>
    protected TDocument LoadOrFail(string name) => LoadOrFailFor(Adapter, name);

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveLoadOrFail)]
    private static TDocument LoadOrFailFor(IConformanceFrontendAdapter<TDocument> adapter, string name)
    {
        TDocument? doc = adapter.LoadFixture(name);
        if (doc is null)
        {
            Assert.Fail(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrAdapterReturnedNullDocument, adapter.FrontendId, name));
        }

        return doc!;
    }

    private static void AssertSuccess(TrustPolicyTranslationResult result, string fixtureName)
    {
        Assert.That(result.IsSuccess, Is.True, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrTranslationFailed, fixtureName, RenderDiagnostics(result.Diagnostics)));
    }

    internal static string RenderDiagnostics(IReadOnlyList<TrustPolicyTranslationDiagnostic> diagnostics)
    {
        if (diagnostics.Count == 0)
        {
            return AssemblyStrings.DocSummaryEmpty;
        }

        StringBuilder sb = new();
        for (int i = 0; i < diagnostics.Count; i++)
        {
            if (i > 0)
            {
                sb.Append(AssemblyStrings.DiagnosticListSeparator);
            }

            TrustPolicyTranslationDiagnostic d = diagnostics[i];
            sb.Append(AssemblyStrings.FormatPredicateBracketOpen).Append(d.Severity).Append(' ').Append(d.Code).Append(AssemblyStrings.FormatPredicateBracketCloseSpace).Append(d.Message);
        }

        return sb.ToString();
    }

    private void AssertRejected(string fixtureName)
    {
        // For the untranslatable contract to be meaningful when a frontend doesn't gate
        // unknown fact ids at translation time (the JSON frontend defers to compile by
        // default), we supply an AvailableFacts surface derived from the live registry. This
        // is the production-realistic call shape, and it guarantees the unknown-fact fixture
        // surfaces TPX200 rather than slipping through translation.
        TrustPolicyTranslationContext ctx = new()
        {
            AvailableFacts = new FactCapabilities { AvailableFactIds = ToReadOnlyOrderedSet(FactRegistry.AllFactIds) },
        };

        TDocument? doc = Adapter.LoadFixture(fixtureName);
        TrustPolicyTranslationResult result;
        if (doc is null)
        {
            // Frontends may ship untranslatable fixtures as raw text only when the document
            // would not parse cleanly to TDocument (e.g. an unknown-fact fixture that schema
            // happens to reject before parse completes). Either route is acceptable; the
            // contract is that translation surfaces an Error diagnostic, not that it parses.
            result = Adapter.TranslateText(Adapter.LoadFixtureText(fixtureName), ctx);
        }
        else
        {
            result = Adapter.Translate(doc, ctx);
        }

        Assert.That(result.IsSuccess, Is.False, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrTranslationUnexpectedlySucceeded, fixtureName, AssemblyStrings.DiagnosticEmptyTagError));
        Assert.That(result.Diagnostics.Any(d => d.Severity == TrustPolicySeverity.Error), Is.True, () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnexpectedDiagnosticCode, fixtureName, RenderDiagnostics(result.Diagnostics), AssemblyStrings.DiagnosticEmptyTagError));
    }

    private static IReadOnlySet<string> ToReadOnlyOrderedSet(IReadOnlySet<string> source)
    {
        // Defensive copy so a future adapter cannot accidentally observe a registry's
        // internal set instance and rely on its identity. The returned set is independent.
        HashSet<string> copy = new(source, StringComparer.Ordinal);
        return copy;
    }

    private RequireFactSpec LoadAndExtractRequireFact(string fixtureName, string expectedFactId)
    {
        TDocument doc = LoadOrFail(fixtureName);
        TrustPolicyTranslationResult result = Adapter.Translate(doc, new TrustPolicyTranslationContext());
        AssertSuccess(result, fixtureName);
        RequireFactSpec? leaf = FindFirstRequireFact(result.Spec!, expectedFactId);
        return leaf ?? FailMissingRequireFact(expectedFactId, fixtureName, result.Spec!);
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveLoadOrFail)]
    private static RequireFactSpec FailMissingRequireFact(string expectedFactId, string fixtureName, TrustPolicySpec spec)
    {
        Assert.Fail(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrFactSpecScopeMismatchFormat, expectedFactId, fixtureName, TrustPolicySpecSerializer.ToCanonicalJson(spec)));
        return null!;
    }

    private TrustPolicyTranslationResult TranslateWithParam(TDocument doc, string paramName, string value)
    {
        // The translation context carries the parameter dictionary primarily for documentation
        // / future audit hooks; per D5 the actual substitution happens in a post-translate
        // Bind pass on the produced spec. Translate alone leaves $param refs in place.
        Dictionary<string, JsonNode?> parameters = new(StringComparer.Ordinal)
        {
            [paramName] = JsonValue.Create(value),
        };

        TrustPolicyTranslationContext ctx = new()
        {
            Parameters = ToReadOnlyNonNullableMap(parameters),
        };

        TrustPolicyTranslationResult translated = Adapter.Translate(doc, ctx);
        if (!translated.IsSuccess)
        {
            return EarlyReturnFromBindingPath(translated);
        }

        // Apply the binder pass — the post-translate substitution that's the actual D5
        // contract. The same dictionary feeds both the Translate context (so frontends that
        // want pre-emptive validation can introspect it) and Bind (which performs the
        // mutation).
        TrustPolicySpec bound = translated.Spec!.Bind(parameters);
        return new TrustPolicyTranslationResult { Spec = bound, Diagnostics = translated.Diagnostics };
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveLoadOrFail)]
    private static TrustPolicyTranslationResult EarlyReturnFromBindingPath(TrustPolicyTranslationResult translated) => translated;

    private static IReadOnlyDictionary<string, JsonNode> ToReadOnlyNonNullableMap(IReadOnlyDictionary<string, JsonNode?> source)
    {
        // TrustPolicyTranslationContext.Parameters is typed as IReadOnlyDictionary<string,
        // JsonNode> (non-nullable values). The binder takes the broader nullable shape. Bridge
        // by filtering out null values — they cannot be supplied as parameters via the
        // context anyway.
        Dictionary<string, JsonNode> map = new(StringComparer.Ordinal);
        foreach (KeyValuePair<string, JsonNode?> entry in source)
        {
            if (entry.Value is not null)
            {
                map[entry.Key] = entry.Value;
            }
        }

        return map;
    }

    /// <summary>
    /// Locates the first <see cref="RequireFactSpec"/> in <paramref name="spec"/> matching the
    /// supplied fact id. Used by the attribute-fidelity test to assert each fixture lowers
    /// down to a leaf fact reference.
    /// </summary>
    /// <param name="spec">The translated spec to walk.</param>
    /// <param name="factId">The fact id to locate.</param>
    /// <returns>The matching <see cref="RequireFactSpec"/> or <see langword="null"/>.</returns>
    internal static RequireFactSpec? FindFirstRequireFact(TrustPolicySpec spec, string factId)
    {
        switch (spec)
        {
            case RequireFactSpec rf when string.Equals(rf.FactTypeId, factId, StringComparison.Ordinal):
                return rf;
            case MessageRequirementSpec mr:
                return FindFirstRequireFact(mr.Inner, factId);
            case PrimarySigningKeyRequirementSpec psk:
                return FindFirstRequireFact(psk.Inner, factId);
            case AnyCounterSignatureRequirementSpec acs:
                return FindFirstRequireFact(acs.Inner, factId);
            case AndSpec a:
                return a.Operands.Select(o => FindFirstRequireFact(o, factId)).FirstOrDefault(r => r is not null);
            case OrSpec o:
                return o.Operands.Select(c => FindFirstRequireFact(c, factId)).FirstOrDefault(r => r is not null);
            case NotSpec n:
                return FindFirstRequireFact(n.Operand, factId);
            case ImpliesSpec i:
                return FindFirstRequireFact(i.Antecedent, factId) ?? FindFirstRequireFact(i.Consequent, factId);
            default:
                return null;
        }
    }

    /// <summary>
    /// Wraps a leaf <see cref="RequireFactSpec"/> in the appropriate scope requirement for
    /// the supplied fact id so the resulting tree compiles cleanly via
    /// <see cref="TrustPolicySpecCompiler"/>. Scope is inferred from the fact id's CLR type.
    /// </summary>
    /// <param name="leaf">The leaf to wrap.</param>
    /// <param name="factId">The fact id of <paramref name="leaf"/>.</param>
    /// <returns>The scope-wrapped spec.</returns>
    private TrustPolicySpec WrapInScope(RequireFactSpec leaf, string factId)
    {
        if (!FactRegistry.TryGetFactType(factId, out Type? clrType))
        {
            FailUnregisteredFactId(factId);
        }

        // Infer scope from the fact's marker interfaces. The compiler enforces scope
        // correctness so producing the right wrapper is essential for the
        // 'Compile-without-error' assertion to be meaningful.
        Type[] interfaces = clrType!.GetInterfaces();
        if (Array.Exists(interfaces, t => t.Name == AssemblyStrings.MarkerInterfaceMessageFact))
        {
            return new MessageRequirementSpec(leaf);
        }

        if (Array.Exists(interfaces, t => t.Name == AssemblyStrings.MarkerInterfaceCounterSignatureFact))
        {
            return new AnyCounterSignatureRequirementSpec(leaf, OnEmptyBehavior.Deny);
        }

        // Default — primary signing key. Covers ISigningKeyFact and any future scope-marker
        // surface added by the validation core.
        return new PrimarySigningKeyRequirementSpec(leaf);
    }

    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage(Justification = AssemblyStrings.JustifyDefensiveLoadOrFail)]
    private static void FailUnregisteredFactId(string factId)
    {
        Assert.Fail(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrFactIdNotRegisteredFormat, factId));
    }

    /// <summary>
    /// Cross-form rule-evaluation invariant: build a small bag of synthetic JSON projections
    /// that vary the property the predicate targets, then compile both predicates and assert
    /// they agree on every projection. Implements the runtime invariant the
    /// <c>PredicateLowerer</c> guarantees per D1.
    /// </summary>
    /// <param name="factId">The fact id under test (used in failure messages).</param>
    /// <param name="propertyForm">The property-shorthand spec.</param>
    /// <param name="pathOperatorForm">The path+operator spec.</param>
    private void AssertCrossFormAgreement(string factId, RequireFactSpec propertyForm, RequireFactSpec pathOperatorForm)
    {
        // Identify the property name and the asserted value from the property-shorthand
        // form. The path/operator form is expected to target the same property via
        // $.<property> path, so the synthetic projections vary that one key.
        PropertyAssertionPredicateSpec property = (PropertyAssertionPredicateSpec)propertyForm.Predicate;
        PathOperatorPredicateSpec pathOperator = (PathOperatorPredicateSpec)pathOperatorForm.Predicate;

        // Use the first asserted (key, value) pair as the synthesis pivot — fixtures use a
        // single-property shorthand to keep the equivalence reasoning simple.
        KeyValuePair<string, JsonNode?> pivot = property.Assertions.First();
        string pivotKey = pivot.Key;
        JsonNode? matchingValue = pivot.Value?.DeepClone();

        // Build four synthetic projections: matching value, mismatching value, type-foreign
        // value, missing key. Each projection is a JsonObject whose JSON shape is exactly
        // what JsonSerializer.SerializeToNode of a real fact would produce.
        JsonObject matchProjection = new() { [pivotKey] = matchingValue?.DeepClone() };
        JsonObject mismatchProjection = new() { [pivotKey] = SyntheticMismatch(matchingValue) };
        JsonObject foreignProjection = new() { [pivotKey] = JsonValue.Create(AssemblyStrings.SyntheticForeignSentinel) };
        JsonObject missingProjection = new();

        JsonObject[] projections =
        {
            matchProjection,
            mismatchProjection,
            foreignProjection,
            missingProjection,
        };

        // Compile each predicate's matcher in JsonNode space directly. We avoid reflecting
        // PredicateLowerer (it's internal) and instead apply the operator semantics here —
        // the conformance suite is the authority on the runtime invariant, not a wrapper
        // over the lowerer's implementation.
        for (int i = 0; i < projections.Length; i++)
        {
            JsonObject projection = projections[i];
            bool propertyVerdict = EvaluatePropertyForm(property, projection);
            bool pathOperatorVerdict = EvaluatePathOperatorForm(pathOperator, projection);

            Assert.That(pathOperatorVerdict, Is.EqualTo(propertyVerdict), () => string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrCrossFormEvaluationDisagreesFormat, factId, i, propertyVerdict, pathOperatorVerdict));
        }
    }

    internal static JsonNode SyntheticMismatch(JsonNode? matching)
    {
        // Produce a value of the same JSON kind that is structurally distinct from the
        // matching one. Booleans flip; strings get suffixed; numbers shift by 1; nulls /
        // arrays fall back to a string sentinel.
        switch (matching)
        {
            case JsonValue v when v.TryGetValue(out bool b):
                return JsonValue.Create(!b);
            case JsonValue v when v.TryGetValue(out string? s) && s is not null:
                return JsonValue.Create(s + AssemblyStrings.SyntheticMismatchSentinel);
            case JsonValue v when v.TryGetValue(out long l):
                return JsonValue.Create(l + 1);
            case JsonValue v when v.TryGetValue(out double d):
                return JsonValue.Create(d + 1);
            default:
                return JsonValue.Create(AssemblyStrings.SyntheticMismatchSentinel);
        }
    }

    internal static bool EvaluatePropertyForm(PropertyAssertionPredicateSpec spec, JsonObject projection)
    {
        // Property assertion: each (key, value) pair must structurally match. This mirrors
        // PredicateLowerer.CompilePropertyAssertion exactly so the conformance assertion is
        // an independent re-derivation, not a tautology over the same code.
        foreach (KeyValuePair<string, JsonNode?> entry in spec.Assertions)
        {
            if (!projection.TryGetPropertyValue(entry.Key, out JsonNode? actual))
            {
                return false;
            }

            if (entry.Value is JsonArray expectedArr)
            {
                if (!expectedArr.Any(item => JsonNode.DeepEquals(actual, item)))
                {
                    return false;
                }
            }
            else if (!JsonNode.DeepEquals(actual, entry.Value))
            {
                return false;
            }
        }

        return true;
    }

    internal static bool EvaluatePathOperatorForm(PathOperatorPredicateSpec spec, JsonObject projection)
    {
        // Resolve the path against the projection. Paths in conformance fixtures are simple
        // $.<single-segment>; we accept that constrained subset here.
        string path = spec.Path;
        if (path.Length < 3 || path[0] != '$' || path[1] != '.')
        {
            return false;
        }

        string key = path.Substring(2);
        bool present = projection.TryGetPropertyValue(key, out JsonNode? actual);

        switch (spec.Operator)
        {
            case PredicateOperator.Exists:
                return present;
            case PredicateOperator.Equals:
                return present && JsonNode.DeepEquals(actual, spec.Value);
            case PredicateOperator.NotEquals:
                return !present || !JsonNode.DeepEquals(actual, spec.Value);
            default:
                // Conformance fixtures use Exists/Equals/NotEquals only — these are the
                // operators the property-shorthand form maps to. Any other operator on a
                // fixture is a fixture-authoring error.
                Assert.Fail(string.Format(CultureInfo.InvariantCulture, AssemblyStrings.ErrUnsupportedCrossFormOperatorFormat, spec.Operator));
                return false;
        }
    }
}
