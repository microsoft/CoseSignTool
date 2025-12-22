// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Documents current revocation option behavior.
//!
//! Revocation behavior is platform-dependent; this test mainly ensures the API
//! accepts explicit revocation modes.

use cosesign1_x509::{validate_x5c_chain, X509ChainVerifyOptions, X509RevocationMode};

#[test]
fn revocation_modes_fail_fast_for_now() {
    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::Online;

    // Intentionally provide an empty chain; validation should fail before
    // any revocation-specific behavior matters.
    let res = validate_x5c_chain("X509Chain", &[], &chain);
    assert!(!res.is_valid);
}
