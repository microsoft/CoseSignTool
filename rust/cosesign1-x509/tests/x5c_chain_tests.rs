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
