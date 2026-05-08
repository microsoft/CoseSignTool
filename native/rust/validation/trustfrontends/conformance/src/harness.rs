// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The 8-property conformance harness (§6.5.10).
//!
//! Each `run_conformance_*` function panics on assertion failure (Rust test
//! idiom) and returns successfully when the property holds. Downstream test
//! files invoke them inside `#[test]` functions; see
//! `tests/json_conformance.rs`.
//!
//! The harness intentionally re-creates the frontend instance per property
//! so leftover translator caches cannot mask non-determinism — see
//! [`crate::ConformanceAdapter::create_frontend`].

use crate::adapter::ConformanceAdapter;
use crate::analysis::{collect_fact_ids, contains_param_literal};
use crate::fixtures::{
    capability_path, cross_path, parametric_path, per_fact_path, perf_path, read_fixture,
    read_fixture_text, schema_path, untranslatable_path,
};
use crate::perf::{measure_p99, PERF_TARGET_P99_MILLIS};
use cose_sign1_trust_policy_spec::{
    bind, to_canonical_json, FactCapabilities, TrustPolicySeverity,
    TrustPolicyTranslationContext, TrustPolicyTranslationResult,
};
use serde_json::Value;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Constants used across multiple property tests.
// ---------------------------------------------------------------------------

/// Number of repeated translations executed by the determinism property.
///
/// 1024 is high enough to surface non-determinism that is cache- or
/// hash-randomisation-driven, low enough to keep CI fast.
pub const DETERMINISM_REPEAT_COUNT: usize = 1024;

// ---------------------------------------------------------------------------
// Property 1 — Determinism (§6.5.10 #1).
// ---------------------------------------------------------------------------

/// §6.5.10 #1: translating the same `(doc, params)` pair repeatedly produces
/// canonical-IR JSON that is byte-identical across all runs.
///
/// Pulls the perf fixture (a representative ≤ 1 KiB document) so the
/// determinism check runs over a non-trivial spec — a tiny `allow_all`
/// document would not exercise enough surface to surface
/// hash-iteration-order bugs.
pub fn run_conformance_1_determinism<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let fixture = perf_path(&adapter.fixture_root(), adapter.fixture_extension());

    let canonical = translate_to_canonical_json(adapter, &fixture);
    for run in 1..DETERMINISM_REPEAT_COUNT {
        let again = translate_to_canonical_json(adapter, &fixture);
        assert_eq!(
            canonical, again,
            "§6.5.10 #1 (determinism) failed at run {run}: canonical-IR JSON \
             diverged from the first run. Fixture: {}",
            fixture.display(),
        );
    }
}

// ---------------------------------------------------------------------------
// Property 2 — Attribute fidelity (§6.5.10 #2).
// ---------------------------------------------------------------------------

/// §6.5.10 #2: every fact id the host advertises has a per-fact fixture that
/// translates successfully into a `RequireFact { fact_id: <expected> }` node,
/// and the canonical-IR JSON dump is stable.
pub fn run_conformance_2_attribute_fidelity<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let root = adapter.fixture_root();
    let extension = adapter.fixture_extension();
    let fact_ids = adapter.registered_fact_ids();
    assert!(
        !fact_ids.is_empty(),
        "§6.5.10 #2 (attribute fidelity) requires the adapter to advertise at \
         least one fact id. Got an empty set.",
    );

    for fact_id in &fact_ids {
        let path = per_fact_path(&root, fact_id, extension);
        assert!(
            path.exists(),
            "§6.5.10 #2 (attribute fidelity): missing per-fact fixture for \
             '{fact_id}' at {}. Encoding rule: '/' becomes '--' in filenames.",
            path.display(),
        );

        let result = translate_fixture(adapter, &path);
        assert!(
            result.is_success(),
            "§6.5.10 #2 (attribute fidelity): translating per-fact fixture for \
             '{fact_id}' failed. Diagnostics: {:?}",
            result.diagnostics,
        );
        let spec = result.spec.expect("is_success guarantees Some");
        let referenced_ids = collect_fact_ids(&spec);
        assert!(
            referenced_ids.contains(fact_id.as_str()),
            "§6.5.10 #2 (attribute fidelity): per-fact fixture for '{fact_id}' \
             produced a spec that does not reference the expected fact id. \
             Referenced: {referenced_ids:?}",
        );

        // Determinism per-fact: re-translate and assert byte-equal canonical IR.
        let canonical_a = to_canonical_json(&spec).expect("canonical JSON encode");
        let result_b = translate_fixture(adapter, &path);
        let spec_b = result_b
            .spec
            .expect("re-translation of a successful fixture must succeed");
        let canonical_b = to_canonical_json(&spec_b).expect("canonical JSON encode");
        assert_eq!(
            canonical_a, canonical_b,
            "§6.5.10 #2 (attribute fidelity): per-fact fixture for '{fact_id}' \
             is non-deterministic across calls.",
        );
    }
}

// ---------------------------------------------------------------------------
// Property 3 — Reject untranslatable (§6.5.10 #3).
// ---------------------------------------------------------------------------

/// §6.5.10 #3: documents that reach for arbitrary code, unknown fact ids, or
/// unsupported operators MUST surface an `Error`-severity diagnostic and
/// return a `None` spec.
///
/// Phase 4 fixtures: `free_text_search`, `unknown_fact`, `unknown_operator`.
pub fn run_conformance_3_reject_untranslatable<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let scenarios: &[(&str, &str)] = &[
        ("free_text_search", "TPX100"),
        ("unknown_fact", "TPX200"),
        ("unknown_operator", "TPX100"),
    ];

    let extension = adapter.fixture_extension();
    let root = adapter.fixture_root();

    for (scenario, expected_code_prefix) in scenarios {
        let path = untranslatable_path(&root, scenario, extension);
        // Some scenarios (e.g. unknown_fact) need capability gating to fire;
        // we use an explicitly closed capability surface so the gate is on.
        let mut ctx = TrustPolicyTranslationContext::empty();
        if *scenario == "unknown_fact" {
            ctx.available_facts = Some(FactCapabilities::ids_only(adapter.registered_fact_ids()));
            ctx.allow_unknown_facts = false;
        }
        let result = translate_fixture_with_ctx(adapter, &path, ctx);
        assert!(
            !result.is_success(),
            "§6.5.10 #3 (reject untranslatable): '{scenario}' fixture \
             unexpectedly translated successfully.",
        );
        let codes: Vec<&str> = result.diagnostics.iter().map(|d| d.code.as_str()).collect();
        assert!(
            codes.iter().any(|c| c.starts_with(expected_code_prefix)),
            "§6.5.10 #3 (reject untranslatable): '{scenario}' fixture did not \
             surface a {expected_code_prefix}xxx diagnostic. Got: {codes:?}",
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.severity == TrustPolicySeverity::Error),
            "§6.5.10 #3 (reject untranslatable): '{scenario}' diagnostics \
             carried no Error severity. Got: {:?}",
            result.diagnostics,
        );
    }
}

// ---------------------------------------------------------------------------
// Property 4 — Bounded runtime (§6.5.10 #4).
// ---------------------------------------------------------------------------

/// §6.5.10 #4: a representative ≤ 1 KiB document translates with p99 ≤ 10 ms.
///
/// Statistical: [`crate::PERF_WARMUP_COUNT`] warm-up iterations followed by
/// [`crate::PERF_SAMPLE_COUNT`] timed samples; nearest-rank p99.
pub fn run_conformance_4_bounded_runtime<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let path = perf_path(&adapter.fixture_root(), adapter.fixture_extension());

    // Verify the fixture is actually ≤ 1 KiB up front — anti-cheating.
    let bytes = read_fixture(&path);
    assert!(
        bytes.len() <= 1024,
        "§6.5.10 #4 (bounded runtime): perf fixture is {} bytes, must be \
         ≤ 1024. Path: {}",
        bytes.len(),
        path.display(),
    );

    let frontend = adapter.create_frontend();
    let ctx = TrustPolicyTranslationContext::empty();
    let measurement = measure_p99(|| {
        let document = adapter.load_document(&path);
        let result = frontend.translate(document, &ctx);
        std::hint::black_box(result);
    });

    let p99_millis = measurement.p99.as_millis();
    assert!(
        p99_millis <= PERF_TARGET_P99_MILLIS as u128,
        "§6.5.10 #4 (bounded runtime): p99 over {} samples is {} ms, target \
         is ≤ {} ms. Mean={}us, max={}us, min={}us.",
        measurement.sample_count,
        p99_millis,
        PERF_TARGET_P99_MILLIS,
        measurement.mean.as_micros(),
        measurement.max.as_micros(),
        measurement.min.as_micros(),
    );
}

// ---------------------------------------------------------------------------
// Property 5 — Capability-aware (§6.5.10 #5).
// ---------------------------------------------------------------------------

/// §6.5.10 #5: when the host's [`FactCapabilities`] omits a fact id required
/// by the document AND `allow_unknown_facts == false`, the translator emits
/// `TPX200` naming the missing fact.
///
/// The Phase 2 walker already surfaces `TPX200`; this property locks the
/// behaviour by exercising it through a fixture so any future change that
/// silently degrades the gate (e.g. defaulting `allow_unknown_facts` to
/// `true`) trips the suite.
pub fn run_conformance_5_capability_aware<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let path = capability_path(&adapter.fixture_root(), "missing_fact", adapter.fixture_extension());

    // Closed surface that does NOT advertise the fact the fixture references.
    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.available_facts = Some(FactCapabilities::ids_only(["x509-chain-trusted/v1"]));
    ctx.allow_unknown_facts = false;

    let result = translate_fixture_with_ctx(adapter, &path, ctx);
    assert!(
        !result.is_success(),
        "§6.5.10 #5 (capability-aware): fixture unexpectedly translated when \
         capability surface should have rejected it. Diagnostics: {:?}",
        result.diagnostics,
    );
    let tpx200 = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX200")
        .unwrap_or_else(|| {
            panic!(
                "§6.5.10 #5 (capability-aware): expected TPX200 diagnostic, got: {:?}",
                result.diagnostics,
            )
        });
    assert!(
        tpx200.severity == TrustPolicySeverity::Error,
        "§6.5.10 #5 (capability-aware): TPX200 must be Error severity",
    );

    // Inverse leg: same fixture with `allow_unknown_facts = true` SHOULD
    // succeed (the capability gate is opt-out).
    let mut ctx_open = TrustPolicyTranslationContext::empty();
    ctx_open.available_facts = Some(FactCapabilities::ids_only(["x509-chain-trusted/v1"]));
    ctx_open.allow_unknown_facts = true;
    let open = translate_fixture_with_ctx(adapter, &path, ctx_open);
    assert!(
        open.is_success(),
        "§6.5.10 #5 (capability-aware): allow_unknown_facts=true should \
         tolerate an unadvertised fact id. Diagnostics: {:?}",
        open.diagnostics,
    );
}

// ---------------------------------------------------------------------------
// Property 6 — Parameter substitution (§6.5.10 #6).
// ---------------------------------------------------------------------------

/// §6.5.10 #6: the same parameterised document binds to different IRs under
/// different parameter sets. Phase 4 fixtures supply two parameter sets
/// (`host_baseline.params.json`, `host_alternate.params.json`) and the
/// harness asserts:
/// 1. The unbound spec carries `$param` literals.
/// 2. Binding with set A produces an IR distinct from binding with set B.
/// 3. Both bound IRs are literal-free (no leftover `$param` references).
pub fn run_conformance_6_parameter_substitution<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let root = adapter.fixture_root();
    let extension = adapter.fixture_extension();
    let baseline_path = parametric_path(&root, "host_baseline", extension);

    let result = translate_fixture(adapter, &baseline_path);
    assert!(
        result.is_success(),
        "§6.5.10 #6 (parameter substitution): unbound translation failed. \
         Diagnostics: {:?}",
        result.diagnostics,
    );
    let unbound = result.spec.expect("ok");
    assert!(
        contains_param_literal(&unbound),
        "§6.5.10 #6 (parameter substitution): unbound spec should carry \
         $param literals (D5 contract: bind is post-translate).",
    );

    // Read the param JSON files committed alongside the document.
    let params_a = load_params_for(&root, "host_baseline");
    let params_b = load_params_for(&root, "host_alternate");
    assert_ne!(
        params_a, params_b,
        "§6.5.10 #6 (parameter substitution): host_baseline.params and \
         host_alternate.params must differ to make the property meaningful.",
    );

    let bound_a = bind(unbound.clone(), &params_a)
        .expect("§6.5.10 #6: binding host_baseline params should succeed");
    let bound_b = bind(unbound, &params_b)
        .expect("§6.5.10 #6: binding host_alternate params should succeed");

    let canonical_a = to_canonical_json(&bound_a).expect("encode bound_a");
    let canonical_b = to_canonical_json(&bound_b).expect("encode bound_b");
    assert_ne!(
        canonical_a, canonical_b,
        "§6.5.10 #6 (parameter substitution): different parameter sets must \
         produce different canonical IRs.",
    );
    assert!(
        !contains_param_literal(&bound_a) && !contains_param_literal(&bound_b),
        "§6.5.10 #6 (parameter substitution): bound specs must be literal-free.",
    );
}

// ---------------------------------------------------------------------------
// Property 7 — Schema validation (§6.5.10 #7).
// ---------------------------------------------------------------------------

/// §6.5.10 #7: malformed JSON surfaces `TPX001` with a `SourceLocation`;
/// shape-violating documents surface `TPX100` with a non-empty diagnostic
/// message that points at the offending construct.
pub fn run_conformance_7_schema_validation<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    let root = adapter.fixture_root();
    let extension = adapter.fixture_extension();

    // Malformed text — translate by passing the raw text to the document loader's
    // panic-on-bad-JSON path is unsuitable here (we want to observe the
    // diagnostic, not blow up the test). Hosts with non-JSON frontends will
    // override the malformed_text scenario via their own translator path.
    // For the JSON adapter, we drive translate_text directly to capture the
    // TPX001 diagnostic.
    let malformed_path = schema_path(&root, "malformed_text", extension);
    let malformed_text = read_fixture_text(&malformed_path);
    let malformed_result = translate_text_via_json(&malformed_text);
    if let Some(result) = malformed_result {
        assert!(
            !result.is_success(),
            "§6.5.10 #7 (schema validation): malformed_text fixture unexpectedly \
             translated successfully.",
        );
        let tpx001 = result
            .diagnostics
            .iter()
            .find(|d| d.code == "TPX001")
            .unwrap_or_else(|| {
                panic!(
                    "§6.5.10 #7 (schema validation): expected TPX001 for \
                     malformed_text, got: {:?}",
                    result.diagnostics,
                )
            });
        assert!(
            tpx001.location.is_some(),
            "§6.5.10 #7 (schema validation): TPX001 must carry a SourceLocation",
        );
    }

    // Shape violation — drive through the structured loader.
    let shape_path = schema_path(&root, "shape_violation", extension);
    let result = translate_fixture(adapter, &shape_path);
    assert!(
        !result.is_success(),
        "§6.5.10 #7 (schema validation): shape_violation fixture unexpectedly \
         translated successfully.",
    );
    let tpx100 = result
        .diagnostics
        .iter()
        .find(|d| d.code == "TPX100")
        .unwrap_or_else(|| {
            panic!(
                "§6.5.10 #7 (schema validation): expected TPX100 for shape_violation, got: {:?}",
                result.diagnostics,
            )
        });
    assert!(
        !tpx100.message.is_empty(),
        "§6.5.10 #7 (schema validation): TPX100 must carry a non-empty message",
    );
}

// ---------------------------------------------------------------------------
// Property 8 — Cross-frontend equivalence (§6.5.10 #8).
// ---------------------------------------------------------------------------

/// §6.5.10 #8: the same logical policy expressed via two frontends produces
/// canonical-IR JSON that is byte-identical between them.
///
/// Phase 4 ships only one frontend (JSON), so the canonical degenerate run is
/// `(json, json)` over the same fixture: byte-equality across two parses of
/// the same document. Phase 5a expands the matrix to `(json, rego)` with the
/// same `cross/canonical_policy/` directory.
pub fn run_conformance_8_cross_equivalence<FA, FB, DA, DB>(a: &FA, b: &FB)
where
    FA: ConformanceAdapter<DA>,
    FB: ConformanceAdapter<DB>,
{
    const CROSS_BASE: &str = "canonical_policy";
    let path_a = cross_path(&a.fixture_root(), CROSS_BASE, a.fixture_extension());
    let path_b = cross_path(&b.fixture_root(), CROSS_BASE, b.fixture_extension());

    let canonical_a = translate_to_canonical_json(a, &path_a);
    let canonical_b = translate_to_canonical_json(b, &path_b);
    assert_eq!(
        canonical_a, canonical_b,
        "§6.5.10 #8 (cross-frontend equivalence): canonical-IR JSON differs \
         between fixtures {} and {}.",
        path_a.display(),
        path_b.display(),
    );
}

// ---------------------------------------------------------------------------
// Composite — run every property in order (with one adapter).
// ---------------------------------------------------------------------------

/// Run every §6.5.10 property using `adapter` for both legs of #8 (degenerate
/// cross-equivalence). Use this for the canonical "full conformance pass" in
/// a single-frontend test crate.
pub fn run_conformance_all<F, TDoc>(adapter: &F)
where
    F: ConformanceAdapter<TDoc>,
{
    run_conformance_1_determinism(adapter);
    run_conformance_2_attribute_fidelity(adapter);
    run_conformance_3_reject_untranslatable(adapter);
    run_conformance_4_bounded_runtime(adapter);
    run_conformance_5_capability_aware(adapter);
    run_conformance_6_parameter_substitution(adapter);
    run_conformance_7_schema_validation(adapter);
    run_conformance_8_cross_equivalence(adapter, adapter);
}

// ---------------------------------------------------------------------------
// Internal helpers.
// ---------------------------------------------------------------------------

fn translate_fixture<F, TDoc>(
    adapter: &F,
    path: &std::path::Path,
) -> TrustPolicyTranslationResult
where
    F: ConformanceAdapter<TDoc>,
{
    translate_fixture_with_ctx(adapter, path, TrustPolicyTranslationContext::empty())
}

fn translate_fixture_with_ctx<F, TDoc>(
    adapter: &F,
    path: &std::path::Path,
    ctx: TrustPolicyTranslationContext,
) -> TrustPolicyTranslationResult
where
    F: ConformanceAdapter<TDoc>,
{
    let frontend = adapter.create_frontend();
    let document = adapter.load_document(path);
    frontend.translate(document, &ctx)
}

fn translate_to_canonical_json<F, TDoc>(adapter: &F, path: &std::path::Path) -> String
where
    F: ConformanceAdapter<TDoc>,
{
    let result = translate_fixture(adapter, path);
    let spec = result.spec.unwrap_or_else(|| {
        panic!(
            "translation failed for {}: diagnostics={:?}",
            path.display(),
            result.diagnostics,
        )
    });
    to_canonical_json(&spec).expect("canonical encode")
}

/// Drive the JSON frontend's [`translate_text`](cose_sign1_trustfrontends_json::CoseTpJsonFrontend::translate_text)
/// path so the harness can observe `TPX001` for malformed JSON.
///
/// Returns `None` for non-JSON frontends — the malformed-text scenario is
/// inherently JSON-specific. Future Rego frontends ship their own malformed-text
/// handling and override property 7 directly in their test crate.
fn translate_text_via_json(text: &str) -> Option<TrustPolicyTranslationResult> {
    let frontend = cose_sign1_trustfrontends_json::CoseTpJsonFrontend::new();
    Some(frontend.translate_text(
        text,
        &TrustPolicyTranslationContext::empty(),
        Some("conformance/schema/malformed_text"),
    ))
}

fn load_params_for(root: &std::path::Path, scenario: &str) -> BTreeMap<String, Value> {
    let mut path = root.to_path_buf();
    path.push("parametric");
    path.push(format!("{scenario}.params.json"));
    let bytes = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "§6.5.10 #6: missing params file {}: {err}. Each parametric \
             scenario must ship a sibling `<scenario>.params.json`.",
            path.display(),
        )
    });
    let map: BTreeMap<String, Value> = serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!(
            "§6.5.10 #6: params file {} is not a valid JSON object: {err}",
            path.display(),
        )
    });
    map
}
