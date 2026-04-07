// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error types.

use cose_sign1_signing::SigningError;

#[test]
fn test_signing_error_variants() {
    let key_err = SigningError::KeyError {
        detail: "test key error".into(),
    };
    assert!(key_err.to_string().contains("Key error"));
    assert!(key_err.to_string().contains("test key error"));

    let header_err = SigningError::HeaderContributionFailed {
        detail: "header fail".into(),
    };
    assert!(header_err
        .to_string()
        .contains("Header contribution failed"));

    let signing_err = SigningError::SigningFailed {
        detail: "signing fail".into(),
    };
    assert!(signing_err.to_string().contains("Signing failed"));

    let verify_err = SigningError::VerificationFailed {
        detail: "verify fail".into(),
    };
    assert!(verify_err.to_string().contains("Verification failed"));

    let config_err = SigningError::InvalidConfiguration {
        detail: "config fail".into(),
    };
    assert!(config_err.to_string().contains("Invalid configuration"));
}

#[test]
fn test_signing_error_debug() {
    let err = SigningError::KeyError {
        detail: "test".into(),
    };
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("KeyError"));
}
