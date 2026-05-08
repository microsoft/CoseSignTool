// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 3 (`np-fact-registry`) **conformance baseline** test.
//!
//! Asserts that the [`HandRolledFactRegistry`] built from every pack
//! crate's `register_facts!{}` output is byte-identical to Phase 1's
//! deprecated [`StaticFactRegistry`] baseline. This is the immutable
//! contract that prevents future drift: renaming any v1 fact id is a
//! v2 breaking change, never a mutation of /v1.
//!
//! Phase 4 (`np-conformance`) extends this with predicate-schema
//! fidelity; Phase 5a (`np-frontend-rego`) extends with cross-frontend
//! equivalence.

#![allow(deprecated)] // intentionally drives the deprecated StaticFactRegistry as the baseline

use std::collections::BTreeSet;

use cose_sign1_trust_policy_spec::{
    HandRolledFactRegistry, IFactRegistry, StaticFactRegistry,
};

/// Snapshot of a registry as `(id, type_name)` pairs.
fn snapshot<R: IFactRegistry>(registry: &R) -> BTreeSet<(String, String)> {
    let mut out = BTreeSet::new();
    for id in registry.all_fact_ids() {
        let type_name = registry
            .try_get_fact_type(id)
            .expect("registered id must resolve to a type");
        out.insert((id.clone(), type_name.to_string()));
    }
    out
}

#[test]
fn hand_rolled_equals_static_baseline() {
    let static_reg = StaticFactRegistry::default_mappings();

    let hand_rolled = HandRolledFactRegistry::from_packs(&[
        cose_sign1_certificates::__cose_sign1_trust_facts(),
        cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
        cose_sign1_validation::__cose_sign1_trust_facts(),
    ])
    .expect("hand-rolled registry must construct cleanly");

    let static_set = snapshot(&static_reg);
    let hr_set = snapshot(&hand_rolled);

    assert_eq!(
        static_set,
        hr_set,
        "Hand-rolled registry MUST be byte-identical to Phase 1 StaticFactRegistry baseline. \
         Renaming any v1 id is a v2 breaking change — not allowed without explicit migration. \
         Static-only: {:?}; HandRolled-only: {:?}",
        static_set.difference(&hr_set).collect::<Vec<_>>(),
        hr_set.difference(&static_set).collect::<Vec<_>>(),
    );
}

#[test]
fn hand_rolled_round_trip_resolution_matches_baseline() {
    // Forward + reverse lookup must agree across both registries for every baseline id.
    let static_reg = StaticFactRegistry::default_mappings();
    let hand_rolled = HandRolledFactRegistry::from_packs(&[
        cose_sign1_certificates::__cose_sign1_trust_facts(),
        cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
        cose_sign1_validation::__cose_sign1_trust_facts(),
    ])
    .unwrap();

    for id in static_reg.all_fact_ids() {
        let type_static = static_reg.try_get_fact_type(id).unwrap();
        let type_hand_rolled = hand_rolled.try_get_fact_type(id).unwrap();
        assert_eq!(type_static, type_hand_rolled, "forward parity for {id}");

        let id_back_static = static_reg.try_get_fact_id(type_static).unwrap();
        let id_back_hr = hand_rolled.try_get_fact_id(type_hand_rolled).unwrap();
        assert_eq!(id_back_static, id_back_hr, "reverse parity for {id}");
        assert_eq!(id_back_hr, id);
    }
}

#[test]
fn hand_rolled_descriptor_carries_pack_attribution() {
    let hand_rolled = HandRolledFactRegistry::from_packs(&[
        cose_sign1_certificates::__cose_sign1_trust_facts(),
        cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
        cose_sign1_validation::__cose_sign1_trust_facts(),
    ])
    .unwrap();

    let cert_descriptor = hand_rolled
        .try_get_descriptor("x509-chain-trusted/v1")
        .expect("baseline id must resolve");
    assert_eq!(cert_descriptor.crate_name, "cose_sign1_certificates");
    assert!(
        cert_descriptor.type_name.contains("X509ChainTrustedFact"),
        "type_name must mention concrete type, got {:?}",
        cert_descriptor.type_name,
    );

    let mst_descriptor = hand_rolled
        .try_get_descriptor("mst-receipt-issuer-host/v1")
        .expect("baseline id must resolve");
    assert_eq!(mst_descriptor.crate_name, "cose_sign1_transparent_mst");

    let core_descriptor = hand_rolled
        .try_get_descriptor("content-type/v1")
        .expect("baseline id must resolve");
    assert_eq!(core_descriptor.crate_name, "cose_sign1_validation");
}

#[test]
fn baseline_size_is_sixteen_immutable() {
    // The Phase 1 baseline freezes at 16 facts. Any change here is
    // intentional + reviewed; do not bump the literal without updating
    // the contract documents.
    let static_reg = StaticFactRegistry::default_mappings();
    assert_eq!(
        static_reg.all_fact_ids().len(),
        16,
        "Phase 1 baseline freezes at 16 facts. To add a new id, follow the contract: register a new /v1 type, update the contract doc, then update this test."
    );

    let hand_rolled = HandRolledFactRegistry::from_packs(&[
        cose_sign1_certificates::__cose_sign1_trust_facts(),
        cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
        cose_sign1_validation::__cose_sign1_trust_facts(),
    ])
    .unwrap();
    assert_eq!(hand_rolled.len(), 16);
}
