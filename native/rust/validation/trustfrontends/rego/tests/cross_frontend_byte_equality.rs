// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! §6.5.10 #8 (cross-frontend equivalence): the JSON and Rego frontends
//! produce byte-identical canonical-IR JSON for the same logical policy.
//! Driven through the conformance harness — the assertion is enforced by
//! [`run_conformance_8_cross_equivalence`] which reads each frontend's
//! sibling `cross/canonical_policy/canonical_policy.<ext>` fixture and
//! diffs the canonical IR.

use cose_sign1_trustfrontends_conformance::{
    run_conformance_8_cross_equivalence, JsonConformanceAdapter,
};
use cose_sign1_trustfrontends_rego::RegoConformanceAdapter;

#[test]
fn json_and_rego_produce_byte_equal_canonical_ir() {
    run_conformance_8_cross_equivalence(
        &JsonConformanceAdapter::default(),
        &RegoConformanceAdapter::default(),
    );
}

#[test]
fn rego_against_itself_is_a_degenerate_pivot() {
    // Sanity: the Rego frontend is internally consistent against the
    // shared cross fixture — same harness driver, both adapters resolve
    // to Rego.
    run_conformance_8_cross_equivalence(
        &RegoConformanceAdapter::default(),
        &RegoConformanceAdapter::default(),
    );
}
