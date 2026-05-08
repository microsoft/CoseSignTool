// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 3 (`np-fact-registry`) per-pack smoke check.
//!
//! Asserts the MST pack's `register_facts!{}` expansion ships exactly
//! the 3 baseline MST receipt fact ids, attributed to this crate.

use std::collections::BTreeSet;

#[test]
fn registered_facts_match_expected_ids() {
    let descriptors = cose_sign1_transparent_mst::__cose_sign1_trust_facts();

    let ids: BTreeSet<&str> = descriptors.iter().map(|d| d.id).collect();
    let expected: BTreeSet<&str> = [
        "mst-receipt-issuer-host/v1",
        "mst-receipt-present/v1",
        "mst-receipt-trusted/v1",
    ]
    .iter()
    .copied()
    .collect();

    assert_eq!(
        ids, expected,
        "Phase 1 baseline MST ids must be byte-identical. The remaining \
         MST receipt-detail facts (kid, statement-sha256, statement-coverage, \
         signature-verified) are surfaced as Phase 1 baseline gaps in the \
         Phase 3 final report and intentionally not registered here."
    );

    for descriptor in &descriptors {
        assert_eq!(descriptor.crate_name, "cose_sign1_transparent_mst");
    }
}
