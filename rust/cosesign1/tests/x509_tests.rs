// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for x509 verification helpers.
//!
//! These tests specifically cover the Windows x509 chain validation helper
//! error paths.

mod common;

use common::*;

/// Exercises error paths for Windows x509 chain validation.
#[test]
fn x5c_verifier_windows_error_paths_are_exercised() {
    use cosesign1_x509::{validate_x5c_chain, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};

    // Invalid leaf DER.
    let chain = X509ChainVerifyOptions::default();
    let res = validate_x5c_chain("X509Chain", &[vec![1, 2, 3]], &chain);
    assert!(!res.is_valid);

    // Custom roots but no trust anchors.
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    let res = validate_x5c_chain("X509Chain", &[vec![1, 2, 3]], &chain);
    assert!(!res.is_valid);

    // Custom roots but a bad root DER fails to add.
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![vec![1, 2, 3]];
    let (leaf_cert, _sk) = make_self_signed_p256_cert_and_key();
    let res = validate_x5c_chain("X509Chain", &[leaf_cert.clone()], &chain);
    assert!(!res.is_valid);

    // Custom roots but not an exact trust anchor.
    let (other_root, _sk2) = make_self_signed_p256_cert_and_key();
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![other_root];
    let res = validate_x5c_chain("X509Chain", &[leaf_cert], &chain);
    assert!(!res.is_valid);
}
