// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage for `cose_sign1_validation_primitives::fact_id` —
//! the [`TrustFactWithId`] trait, the [`TrustFactDescriptor`] type,
//! [`validate_fact_id`], and [`register_facts!`] macro expansion.

use cose_sign1_validation_primitives::{
    register_facts, validate_fact_id, TrustFactDescriptor, TrustFactWithId,
};

// ---- Probe types so we can exercise register_facts! end-to-end -----

#[derive(Debug)]
struct ProbeAlphaFact;
impl TrustFactWithId for ProbeAlphaFact {
    const FACT_ID: &'static str = "probe-alpha/v1";
}

#[derive(Debug)]
struct ProbeBetaFact;
impl TrustFactWithId for ProbeBetaFact {
    const FACT_ID: &'static str = "probe-beta/v3";
}

// Belt-and-suspenders compile-time format check — proves the canonical
// pattern can be wired as a const-assert by callers.
const _: () = assert!(validate_fact_id(
    <ProbeAlphaFact as TrustFactWithId>::FACT_ID
));
const _: () = assert!(validate_fact_id(
    <ProbeBetaFact as TrustFactWithId>::FACT_ID
));

register_facts! {
    ProbeAlphaFact,
    ProbeBetaFact,
}

#[test]
fn register_facts_emits_expected_descriptors() {
    let descriptors = __cose_sign1_trust_facts();
    assert_eq!(descriptors.len(), 2, "macro must emit one entry per type");

    assert_eq!(descriptors[0].id, "probe-alpha/v1");
    assert_eq!(descriptors[1].id, "probe-beta/v3");

    // Both descriptors self-attribute to the integration-test crate.
    let crate_name = env!("CARGO_PKG_NAME");
    for d in &descriptors {
        assert_eq!(d.crate_name, crate_name);
        assert!(!d.type_name.is_empty(), "type_name populated by std::any::type_name");
    }

    // type_name uses the resolved std::any::type_name path; just check
    // that the concrete type fragment appears.
    assert!(descriptors[0].type_name.contains("ProbeAlphaFact"));
    assert!(descriptors[1].type_name.contains("ProbeBetaFact"));
}

#[test]
fn validate_fact_id_accepts_canonical_inputs() {
    let good = [
        "x509-chain-trusted/v1",
        "mst-receipt-issuer-host/v1",
        "x509-x5chain-cert-identity/v12",
        "a/v0",
        "abc/v999",
        "abc-def-ghi/v1",
        "abc123/v1",
    ];
    for s in good {
        assert!(validate_fact_id(s), "should match: {s:?}");
    }
}

#[test]
fn validate_fact_id_rejects_malformed_inputs() {
    let bad = [
        "",
        "X509",                 // uppercase
        "/v1",                  // empty id
        "name/v",               // no digits
        "name/V1",              // capital V
        "name",                 // no version
        "name/v1.0",            // dot in version
        "1leading-digit/v1",    // starts with digit
        "name with space/v1",   // space
        "name_underscore/v1",   // underscore
        "Bad/v1",               // mid-uppercase
        "name/u1",              // wrong version sigil
        "-leading-dash/v1",     // first char must be letter
        "name/v1a",             // non-digit after version digits
        "name/",                // truncated
        "name/v1/v2",           // second slash inside version
    ];
    for s in bad {
        assert!(!validate_fact_id(s), "should NOT match: {s:?}");
    }
}

#[test]
fn descriptor_is_clonable_and_carries_metadata() {
    let descriptor = TrustFactDescriptor::new(
        "test/v1",
        "core::ProbeFact",
        "probe_crate",
    );
    let clone = descriptor.clone();
    assert_eq!(descriptor, clone);
    assert_eq!(descriptor.id, "test/v1");
    assert_eq!(descriptor.type_name, "core::ProbeFact");
    assert_eq!(descriptor.crate_name, "probe_crate");

    // Debug format mentions all three fields.
    let dbg = format!("{descriptor:?}");
    assert!(dbg.contains("test/v1"));
    assert!(dbg.contains("ProbeFact"));
    assert!(dbg.contains("probe_crate"));
}

#[test]
fn descriptor_eq_compares_all_fields() {
    let a = TrustFactDescriptor::new("id/v1", "Type", "crate_a");
    let b = TrustFactDescriptor::new("id/v1", "Type", "crate_a");
    let c = TrustFactDescriptor::new("id/v2", "Type", "crate_a");
    let d = TrustFactDescriptor::new("id/v1", "Other", "crate_a");
    let e = TrustFactDescriptor::new("id/v1", "Type", "crate_b");

    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    assert_ne!(a, e);
}

#[test]
fn trust_fact_with_id_const_is_accessible_through_trait_bound() {
    // Exercises the `<T as TrustFactWithId>::FACT_ID` path the macro
    // expansion relies on.
    fn id_of<T: TrustFactWithId>() -> &'static str {
        <T as TrustFactWithId>::FACT_ID
    }
    assert_eq!(id_of::<ProbeAlphaFact>(), "probe-alpha/v1");
    assert_eq!(id_of::<ProbeBetaFact>(), "probe-beta/v3");
}
