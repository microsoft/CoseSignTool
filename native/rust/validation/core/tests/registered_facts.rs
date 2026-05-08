// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 3 (`np-fact-registry`) per-pack smoke check.
//!
//! Asserts the validation/core crate's `register_facts!{}` expansion
//! ships exactly the 4 baseline message-level fact ids, attributed to
//! the `cose_sign1_validation` crate.

use std::collections::BTreeSet;

#[test]
fn registered_facts_match_expected_ids() {
    let descriptors = cose_sign1_validation::__cose_sign1_trust_facts();

    let ids: BTreeSet<&str> = descriptors.iter().map(|d| d.id).collect();
    let expected: BTreeSet<&str> = [
        "content-type/v1",
        "counter-signature-subject/v1",
        "detached-payload-present/v1",
        "unknown-counter-signature-bytes/v1",
    ]
    .iter()
    .copied()
    .collect();

    assert_eq!(
        ids, expected,
        "Phase 1 baseline message-level ids must be byte-identical."
    );

    for descriptor in &descriptors {
        assert_eq!(descriptor.crate_name, "cose_sign1_validation");
    }
}
