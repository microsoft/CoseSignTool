// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `x5c` chain validation.

use cosesign1_x509::{
    validate_x5c_chain, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode,
};

#[test]
fn x5c_chain_validation_succeeds_with_custom_root() {
    // Use a self-signed cert as both leaf and trust anchor.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];

    let res = validate_x5c_chain("X509Chain", &[cert_der], &chain);
    assert!(res.is_valid);
    assert_eq!(
        res.metadata.get("x5c.chain_valid").map(|s| s.as_str()),
        Some("true")
    );
}

#[test]
fn x5c_chain_validation_fails_for_empty_chain() {
    let chain = X509ChainVerifyOptions::default();
    let res = validate_x5c_chain("X509Chain", &[], &chain);
    assert!(!res.is_valid);
    assert_eq!(
        res.metadata.get("x5c.chain_valid").map(|s| s.as_str()),
        Some("false")
    );
}

#[test]
fn x5c_chain_validation_fails_for_invalid_leaf_der() {
    let chain = X509ChainVerifyOptions::default();
    let res = validate_x5c_chain("X509Chain", &[vec![1, 2, 3]], &chain);
    assert!(!res.is_valid);
    assert_eq!(
        res.metadata.get("x5c.chain_valid").map(|s| s.as_str()),
        Some("false")
    );
}

#[test]
fn x5c_chain_custom_roots_requires_trust_anchors() {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![];

    let res = validate_x5c_chain("X509Chain", &[cert_der], &chain);
    assert!(!res.is_valid);
}

#[test]
fn x5c_chain_custom_roots_fails_if_root_der_is_empty() {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![vec![]];

    let res = validate_x5c_chain("X509Chain", &[cert_der], &chain);
    assert!(!res.is_valid);
}

#[test]
fn x5c_chain_system_trust_reports_untrusted_root_for_self_signed_leaf() {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    // System trust mode (default) will typically treat a random self-signed cert as untrusted.
    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::NoCheck;

    let res = validate_x5c_chain("X509Chain", &[cert_der], &chain);
    assert!(!res.is_valid);
    assert_eq!(
        res.metadata.get("x5c.chain_valid").map(|s| s.as_str()),
        Some("false")
    );
}

#[test]
fn x5c_chain_offline_revocation_mode_is_exercised() {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::Offline;

    // We don't assert exact failure code here; this is primarily to exercise the Offline flag path.
    let _ = validate_x5c_chain("X509Chain", &[cert_der], &chain);
}

#[test]
fn x5c_chain_custom_roots_requires_exact_root_match() {
    // In CustomRoots mode on Windows, the chain builder can still build a chain,
    // but we enforce that the chain root must be an exact DER match of one of
    // the caller-provided trusted roots.
    let leaf = rcgen::generate_simple_self_signed(["leaf.example".to_string()]).unwrap();
    let leaf_der = leaf.cert.der().to_vec();

    let other_root = rcgen::generate_simple_self_signed(["root.example".to_string()]).unwrap();
    let other_root_der = other_root.cert.der().to_vec();

    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![other_root_der];

    let res = validate_x5c_chain("X509Chain", &[leaf_der], &chain);
    assert!(!res.is_valid);
    assert_eq!(
        res.failures.first().and_then(|f| f.error_code.as_deref()),
        Some("CERT_CHAIN_NOT_AN_EXACT_TRUST_ANCHOR")
    );
}
