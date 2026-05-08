// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wires the canonical `cose-tp-json/v1` frontend through every §6.5.10
//! property. Mirrors the .NET `FrontendConformanceTestBase` per-property test
//! shape so a regression on any single property surfaces as one test failure
//! rather than a single composite failure that hides the rest.

use cose_sign1_trustfrontends_conformance::{
    run_conformance_1_determinism, run_conformance_2_attribute_fidelity,
    run_conformance_3_reject_untranslatable, run_conformance_4_bounded_runtime,
    run_conformance_5_capability_aware, run_conformance_6_parameter_substitution,
    run_conformance_7_schema_validation, run_conformance_8_cross_equivalence,
    JsonConformanceAdapter,
};

fn adapter() -> JsonConformanceAdapter {
    JsonConformanceAdapter::default()
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

#[test]
fn property_7_schema_validation() {
    run_conformance_7_schema_validation(&adapter());
}

#[test]
fn property_8_cross_equivalence_degenerate() {
    // Phase 4 ships only the JSON frontend, so the canonical degenerate run is
    // (json, json) — locks the contract surface ahead of Phase 5a (Rego).
    run_conformance_8_cross_equivalence(&adapter(), &adapter());
}
