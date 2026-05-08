// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage for the Phase 3 [`HandRolledFactRegistry`] error paths and
//! introspection surfaces. The happy-path / parity-with-baseline check
//! lives in [`conformance_baseline.rs`]; this fixture exercises only
//! the branches that the conformance baseline cannot reach.

use cose_sign1_trust_policy_spec::{
    HandRolledFactRegistry, IFactRegistry, RegistryError,
};
use cose_sign1_validation_primitives::TrustFactDescriptor;

fn descriptor(id: &'static str, type_name: &'static str) -> TrustFactDescriptor {
    TrustFactDescriptor::new(id, type_name, "test_pack")
}

#[test]
fn empty_registry_resolves_nothing() {
    let registry = HandRolledFactRegistry::empty();
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.all_fact_ids().is_empty());
    assert!(registry.try_get_fact_type("anything/v1").is_none());
    assert!(registry.try_get_fact_id("Anything").is_none());
    assert!(registry.try_get_descriptor("anything/v1").is_none());
    assert!(registry
        .try_get_descriptor_by_type_name("Anything")
        .is_none());
    assert_eq!(registry.iter_descriptors().count(), 0);
}

#[test]
fn from_packs_collects_across_multiple_packs() {
    let pack_a = vec![descriptor("alpha/v1", "PackA::Alpha")];
    let pack_b = vec![
        descriptor("beta/v1", "PackB::Beta"),
        descriptor("gamma/v1", "PackB::Gamma"),
    ];

    let registry = HandRolledFactRegistry::from_packs(&[pack_a, pack_b]).unwrap();

    assert_eq!(registry.len(), 3);
    assert!(!registry.is_empty());
    assert_eq!(registry.try_get_fact_type("alpha/v1"), Some("PackA::Alpha"));
    assert_eq!(registry.try_get_fact_type("beta/v1"), Some("PackB::Beta"));
    assert_eq!(
        registry.try_get_fact_type("gamma/v1"),
        Some("PackB::Gamma")
    );
    assert_eq!(
        registry.try_get_fact_id("PackA::Alpha"),
        Some("alpha/v1")
    );

    // BTreeMap keeps iteration sorted by id regardless of pack order.
    let ids: Vec<&str> = registry.iter_descriptors().map(|d| d.id).collect();
    assert_eq!(ids, vec!["alpha/v1", "beta/v1", "gamma/v1"]);
}

#[test]
fn from_packs_rejects_duplicate_id_across_packs() {
    let pack_a = vec![descriptor("dup/v1", "PackA::Dup")];
    let pack_b = vec![descriptor("dup/v1", "PackB::Dup")];

    let err = HandRolledFactRegistry::from_packs(&[pack_a, pack_b]).unwrap_err();
    match err {
        RegistryError::DuplicateId {
            ref id,
            ref first_type_name,
            ref second_type_name,
        } => {
            assert_eq!(id, "dup/v1");
            assert_eq!(first_type_name, "PackA::Dup");
            assert_eq!(second_type_name, "PackB::Dup");
        }
        other => panic!("expected DuplicateId, got {other:?}"),
    }
    assert_eq!(err.diagnostic_code(), "TPX300");
    let display = format!("{err}");
    assert!(display.contains("TPX300"));
    assert!(display.contains("dup/v1"));
    assert!(display.contains("PackA::Dup"));
    assert!(display.contains("PackB::Dup"));
}

#[test]
fn from_packs_rejects_duplicate_id_within_single_pack() {
    let pack = vec![
        descriptor("collide/v1", "First"),
        descriptor("collide/v1", "Second"),
    ];
    let err = HandRolledFactRegistry::from_packs(&[pack]).unwrap_err();
    assert!(matches!(err, RegistryError::DuplicateId { .. }));
}

#[test]
fn from_packs_rejects_malformed_id() {
    let bad_cases: &[&str] = &[
        "",
        "Bad/v1",            // uppercase
        "missing-version",   // no /vN suffix
        "no-digits/v",       // /v but no digits
        "name/V1",           // capital V
        "name/v1.0",         // dot in version
        "1leading-digit/v1", // starts with digit
        "name with space/v1",
        "name_underscore/v1",
    ];
    for bad in bad_cases {
        let descriptors = vec![descriptor(bad, "Any")];
        let err = HandRolledFactRegistry::from_packs(&[descriptors]).unwrap_err();
        match err {
            RegistryError::InvalidIdFormat { ref id, .. } => {
                assert_eq!(id, bad, "rejected id should round-trip in error");
            }
            other => panic!("expected InvalidIdFormat for {bad:?}, got {other:?}"),
        }
        assert_eq!(err.diagnostic_code(), "TPX301");
        assert!(format!("{err}").contains("TPX301"));
    }
}

#[test]
fn registry_error_is_clonable_and_eq() {
    // Belt-and-suspenders: enable downstream emitters to compare /
    // forward errors without losing data.
    let a = RegistryError::DuplicateId {
        id: "id/v1".into(),
        first_type_name: "A".into(),
        second_type_name: "B".into(),
    };
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.diagnostic_code(), "TPX300");

    let c = RegistryError::InvalidIdFormat {
        id: "Bad".into(),
        type_name: "T".into(),
    };
    assert_eq!(c.clone(), c);
    assert_eq!(c.diagnostic_code(), "TPX301");
    assert_ne!(a, c);
}

#[test]
fn try_get_descriptor_by_type_name_returns_full_descriptor() {
    let pack = vec![descriptor("alpha/v1", "PackA::Alpha")];
    let registry = HandRolledFactRegistry::from_packs(&[pack]).unwrap();

    let descriptor = registry
        .try_get_descriptor_by_type_name("PackA::Alpha")
        .expect("registered type must resolve");
    assert_eq!(descriptor.id, "alpha/v1");
    assert_eq!(descriptor.crate_name, "test_pack");
}

#[test]
fn from_packs_with_empty_pack_list_is_empty() {
    let registry = HandRolledFactRegistry::from_packs(&[]).unwrap();
    assert!(registry.is_empty());
}

#[test]
fn from_packs_with_only_empty_packs_is_empty() {
    let registry = HandRolledFactRegistry::from_packs(&[vec![], vec![], vec![]]).unwrap();
    assert!(registry.is_empty());
}

#[test]
fn registry_error_implements_std_error() {
    fn assert_std_error<E: std::error::Error>(_e: &E) {}
    let err = RegistryError::InvalidIdFormat {
        id: "Bad".into(),
        type_name: "T".into(),
    };
    assert_std_error(&err);
}

#[test]
fn hand_rolled_registry_is_clone() {
    let pack = vec![descriptor("alpha/v1", "PackA::Alpha")];
    let registry = HandRolledFactRegistry::from_packs(&[pack]).unwrap();
    let cloned = registry.clone();
    assert_eq!(registry.len(), cloned.len());
    assert_eq!(
        registry.try_get_fact_type("alpha/v1"),
        cloned.try_get_fact_type("alpha/v1")
    );
}

#[test]
fn debug_formats_for_registry_and_error() {
    let registry = HandRolledFactRegistry::empty();
    let dbg = format!("{registry:?}");
    assert!(dbg.contains("HandRolledFactRegistry"));

    let err = RegistryError::DuplicateId {
        id: "id/v1".into(),
        first_type_name: "A".into(),
        second_type_name: "B".into(),
    };
    let dbg = format!("{err:?}");
    assert!(dbg.contains("DuplicateId"));
}
