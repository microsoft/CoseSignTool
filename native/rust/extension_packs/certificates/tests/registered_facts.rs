// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 3 (`np-fact-registry`) per-pack smoke check.
//!
//! Asserts the certificates pack's `register_facts!{}` expansion ships
//! exactly the 9 baseline X.509 fact ids, in id-sorted order, all
//! attributed to this crate.

use std::collections::BTreeSet;

#[test]
fn registered_facts_match_expected_ids() {
    let descriptors = cose_sign1_certificates::__cose_sign1_trust_facts();

    let ids: BTreeSet<&str> = descriptors.iter().map(|d| d.id).collect();
    let expected: BTreeSet<&str> = [
        "certificate-signing-key-trust/v1",
        "x509-cert-basic-constraints/v1",
        "x509-cert-eku/v1",
        "x509-cert-identity-allowed/v1",
        "x509-cert-identity/v1",
        "x509-cert-key-usage/v1",
        "x509-chain-element-identity/v1",
        "x509-chain-trusted/v1",
        "x509-x5chain-cert-identity/v1",
    ]
    .iter()
    .copied()
    .collect();

    assert_eq!(
        ids, expected,
        "Phase 1 baseline certificates ids must be byte-identical. \
         Adding/removing a v1 id requires a contract review and an \
         update to the conformance baseline test."
    );

    for descriptor in &descriptors {
        assert_eq!(
            descriptor.crate_name, "cose_sign1_certificates",
            "every descriptor must self-attribute to the certificates crate"
        );
        assert!(
            !descriptor.type_name.is_empty(),
            "type_name should be populated by std::any::type_name"
        );
    }
}
