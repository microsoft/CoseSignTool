// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Conformance tests for [`StaticFactRegistry`].
//!
//! Every registered fact id MUST match the canonical `^[a-z][a-z0-9-]*/v[0-9]+$` regex —
//! the version-suffix discipline that makes fact-id evolution composable across packs.
//!
//! Phase 3 will replace this static registry with a hand-rolled `register_facts!()` macro
//! per pack; the same regex check moves to the macro's compile-time emit step.

use cose_sign1_trust_policy_spec::{IFactRegistry, StaticFactRegistry};

/// Tiny hand-rolled validator (no `regex` dep — Phase 1 stays minimal). Mirrors the
/// shape: ASCII lowercase letter, then `[a-z0-9-]*`, then `/v` + at least one digit.
fn matches_id_pattern(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    // Find `/v` suffix.
    let Some(slash) = id.find('/') else {
        return false;
    };
    let (head, tail) = id.split_at(slash);
    if !head
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return false;
    }
    // tail is "/vNN..."
    let tail_bytes = tail.as_bytes();
    if tail_bytes.len() < 3 || tail_bytes[0] != b'/' || tail_bytes[1] != b'v' {
        return false;
    }
    let rest = &tail_bytes[2..];
    if rest.is_empty() {
        return false;
    }
    rest.iter().all(|b| b.is_ascii_digit())
}

#[test]
fn every_default_fact_id_matches_pattern() {
    let registry = StaticFactRegistry::default_mappings();
    let ids = registry.all_fact_ids();
    assert!(!ids.is_empty(), "default mappings non-empty");
    for id in ids {
        assert!(
            matches_id_pattern(id),
            "fact id {id:?} does not match ^[a-z][a-z0-9-]*/v[0-9]+$"
        );
    }
}

#[test]
fn forward_reverse_lookup_round_trips() {
    let registry = StaticFactRegistry::default_mappings();
    for id in registry.all_fact_ids() {
        let type_name = registry.try_get_fact_type(id).expect("forward lookup");
        let id_back = registry.try_get_fact_id(type_name).expect("reverse lookup");
        assert_eq!(id_back, id, "round-trip stable for {id}");
    }
}

#[test]
fn unknown_fact_id_returns_none() {
    let registry = StaticFactRegistry::default_mappings();
    assert!(registry.try_get_fact_type("nonexistent/v1").is_none());
    assert!(registry.try_get_fact_id("rust::path::DoesNotExist").is_none());
}

#[test]
fn empty_registry_round_trips() {
    let registry = StaticFactRegistry::empty();
    assert!(registry.all_fact_ids().is_empty());
    assert!(registry.try_get_fact_type("x509-chain-trusted/v1").is_none());
}

#[test]
fn registry_default_matches_default_mappings() {
    let by_default = StaticFactRegistry::default();
    let by_explicit = StaticFactRegistry::default_mappings();
    assert_eq!(by_default.all_fact_ids(), by_explicit.all_fact_ids());
}

#[test]
fn pattern_validator_self_check() {
    // Sanity-check the regex-stand-in itself.
    let good = [
        "x509-chain-trusted/v1",
        "mst-receipt-issuer-host/v1",
        "x509-x5chain-cert-identity/v12",
    ];
    for s in good {
        assert!(matches_id_pattern(s), "should match: {s}");
    }
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
        "name_underscore/v1",   // underscore not allowed
    ];
    for s in bad {
        assert!(!matches_id_pattern(s), "should NOT match: {s}");
    }
}

#[test]
fn ids_iterate_in_sorted_order() {
    let registry = StaticFactRegistry::default_mappings();
    let collected: Vec<&str> = registry.all_fact_ids().iter().map(String::as_str).collect();
    let mut sorted = collected.clone();
    sorted.sort();
    assert_eq!(collected, sorted, "BTreeSet → sorted iteration");
}

#[test]
fn registry_includes_expected_canonical_ids() {
    // Spot-check a few mandatory ids from the .NET parity list.
    let registry = StaticFactRegistry::default_mappings();
    let must_have = [
        "x509-chain-trusted/v1",
        "x509-cert-identity/v1",
        "x509-cert-eku/v1",
        "mst-receipt-present/v1",
        "mst-receipt-trusted/v1",
        "mst-receipt-issuer-host/v1",
        "content-type/v1",
        "counter-signature-subject/v1",
        "detached-payload-present/v1",
        "unknown-counter-signature-bytes/v1",
        "certificate-signing-key-trust/v1",
        "x509-chain-element-identity/v1",
        "x509-cert-basic-constraints/v1",
        "x509-cert-identity-allowed/v1",
        "x509-cert-key-usage/v1",
        "x509-x5chain-cert-identity/v1",
    ];
    for id in must_have {
        assert!(
            registry.try_get_fact_type(id).is_some(),
            "must-have id missing: {id}"
        );
    }
}
