// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(missing_docs)]

//! `cose_sign1_trustfrontends_conformance` — Phase 4 (np-conformance) of the
//! native Rust trust-policy port.
//!
//! This crate ships the reusable conformance harness that every shipping
//! CoseSign1 trust-policy frontend MUST pass to be ship-eligible. The harness
//! implements the 8-property contract defined in §6.5.10 of the eval doc:
//!
//! 1. **Determinism** — translate the same `(doc, params)` repeatedly and
//!    every canonical-IR JSON dump is byte-identical (§6.5.4 #1).
//! 2. **Attribute fidelity** — every fact id the host registers has at least
//!    one frontend example that translates to a `RequireFact` node carrying
//!    that exact id, and the canonical-IR JSON of the result is stable.
//! 3. **Reject untranslatable** — documents that reach for arbitrary code,
//!    unknown fact ids, or unsupported operators produce `Error` diagnostics
//!    with the matching `TPXxxx` code (§6.5.4 #4).
//! 4. **Bounded runtime** — a representative ≤1 KiB document translates with
//!    p99 ≤ 10 ms over a statistically meaningful sample (§6.5.4 #7).
//! 5. **Capability-aware** — when the host's [`FactCapabilities`] omits a fact
//!    id required by the document AND `allow_unknown_facts == false`, the
//!    translator emits `TPX200` (§6.5.4 #5).
//! 6. **Parameter substitution** — the same parameterised document binds to
//!    different IRs under different parameter sets, and the unbound spec
//!    round-trips deterministically (§6.5.4 #2 + D5).
//! 7. **Schema validation** — malformed JSON and shape-violating documents
//!    surface `TPX001` / `TPX100` with a non-trivial `SourceLocation`.
//! 8. **Cross-frontend equivalence** — a canonical document expressed in two
//!    frontends produces canonical-IR JSON that is byte-identical between
//!    them (§6.5.4 #3 + D7). The harness exposes this even with one frontend
//!    so the contract is locked in before Phase 5a (Rego) ships.
//!
//! # How to opt a frontend in
//!
//! Implement [`ConformanceAdapter`] for the new frontend in its own test
//! crate and call the per-property `run_conformance_*` functions inside
//! `#[test]` functions. See `tests/json_conformance.rs` for the canonical
//! example using [`JsonConformanceAdapter`].
//!
//! # Fixture set
//!
//! Fixtures live under `fixtures/` in this crate and are organised by
//! property:
//!
//! - `fixtures/per_fact/<fact-id-encoded>.<ext>` — one per registered fact.
//!   The id encoding replaces `/` with `--` because `/` cannot appear in a
//!   filesystem path on Windows; the harness round-trips encode/decode.
//! - `fixtures/untranslatable/{free_text_search,unknown_fact,unknown_operator}.<ext>`
//! - `fixtures/capability/missing_fact.<ext>`
//! - `fixtures/schema/{malformed_text,shape_violation}.<ext>`
//! - `fixtures/parametric/{host_baseline,host_alternate}.<ext>`
//! - `fixtures/perf/representative_1kb.<ext>` (≤ 1 KiB)
//! - `fixtures/cross/<base>/<base>.<ext>` (one per frontend)
//!
//! `<ext>` is the value [`ConformanceAdapter::fixture_extension`] returns
//! (e.g. `coseTrustPolicy.json` for the JSON frontend).
//!
//! # Cross-port note
//!
//! This Rust suite is logically equivalent to .NET's
//! `CoseSign1.Validation.TrustFrontends.Conformance` (Phase 4 train delivery).
//! The 8 properties match verbatim. Cross-language IR equivalence (a Rust
//! frontend producing the same canonical IR as a .NET frontend for the same
//! fixture) is enforced for the JSON frontend at fixture
//! `cross/canonical_policy/canonical_policy.coseTrustPolicy.json` against the
//! committed golden file `canonical_ir.expected.json`. Other frontends inherit
//! the lock when they ship.

pub mod adapter;
pub mod analysis;
pub mod fixtures;
pub mod harness;
pub mod json_adapter;
pub mod perf;

pub use adapter::ConformanceAdapter;
pub use analysis::{collect_fact_ids, contains_param_literal};
pub use harness::{
    run_conformance_1_determinism, run_conformance_2_attribute_fidelity,
    run_conformance_3_reject_untranslatable, run_conformance_4_bounded_runtime,
    run_conformance_5_capability_aware, run_conformance_6_parameter_substitution,
    run_conformance_7_schema_validation, run_conformance_8_cross_equivalence,
    run_conformance_all,
};
pub use json_adapter::JsonConformanceAdapter;
pub use perf::{
    measure_p99, nearest_rank_percentile, PerfMeasurement, PERF_SAMPLE_COUNT,
    PERF_TARGET_P99_MILLIS, PERF_WARMUP_COUNT,
};
