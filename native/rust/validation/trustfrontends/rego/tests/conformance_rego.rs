// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wires the constrained `cose-tp-rego/v1` frontend through every
//! §6.5.10 property using [`RegoConformanceAdapter`]. Mirrors the
//! per-property test shape of `tests/json_conformance.rs` in the
//! conformance crate so a regression on any one property surfaces as a
//! single test failure rather than a composite that hides the rest.

use cose_sign1_trustfrontends_conformance::{
    run_conformance_1_determinism, run_conformance_2_attribute_fidelity,
    run_conformance_3_reject_untranslatable, run_conformance_4_bounded_runtime,
    run_conformance_5_capability_aware, run_conformance_6_parameter_substitution,
    run_conformance_8_cross_equivalence, JsonConformanceAdapter,
};
use cose_sign1_trustfrontends_rego::RegoConformanceAdapter;

fn adapter() -> RegoConformanceAdapter {
    RegoConformanceAdapter::default()
}

#[test]
fn property_1_determinism() {
    run_conformance_1_determinism(&adapter());
}

#[test]
fn property_2_attribute_fidelity() {
    run_conformance_2_attribute_fidelity(&adapter());
}

#[test]
fn property_3_reject_untranslatable() {
    run_conformance_3_reject_untranslatable(&adapter());
}

#[test]
fn property_4_bounded_runtime() {
    run_conformance_4_bounded_runtime(&adapter());
}

#[test]
fn property_5_capability_aware() {
    run_conformance_5_capability_aware(&adapter());
}

#[test]
fn property_6_parameter_substitution() {
    run_conformance_6_parameter_substitution(&adapter());
}

// Property 7 (schema validation) tests JSON-shaped malformed text and is
// inherently JSON-specific (the Rego sibling fixture is a parse failure
// before reaching the JSON walker). Rego frontend's parse-time analogue is
// covered exhaustively in `tests/reject_list.rs` (`tpx001_*`).

#[test]
fn property_8_cross_equivalence_json_and_rego() {
    run_conformance_8_cross_equivalence(
        &JsonConformanceAdapter::default(),
        &adapter(),
    );
}
