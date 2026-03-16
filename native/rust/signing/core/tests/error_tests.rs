// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error types.

use cose_sign1_signing::SigningError;

#[test]
fn test_signing_error_variants() {
    let key_err = SigningError::KeyError("test key error".to_string());
    assert!(key_err.to_string().contains("Key error"));
    assert!(key_err.to_string().contains("test key error"));

    let header_err = SigningError::HeaderContributionFailed("header fail".to_string());
    assert!(header_err.to_string().contains("Header contribution failed"));

    let signing_err = SigningError::SigningFailed("signing fail".to_string());
    assert!(signing_err.to_string().contains("Signing failed"));

    let verify_err = SigningError::VerificationFailed("verify fail".to_string());
    assert!(verify_err.to_string().contains("Verification failed"));

    let config_err = SigningError::InvalidConfiguration("config fail".to_string());
    assert!(config_err.to_string().contains("Invalid configuration"));
}

#[test]
fn test_signing_error_debug() {
    let err = SigningError::KeyError("test".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("KeyError"));
}
