// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for factory error types.

use cose_sign1_factories::FactoryError;
use cose_sign1_primitives::CoseSign1Error;
use cose_sign1_signing::SigningError;

#[test]
fn test_factory_error_display_signing_failed() {
    let error = FactoryError::SigningFailed("Test signing failure".to_string());
    assert_eq!(error.to_string(), "Signing failed: Test signing failure");
}

#[test]
fn test_factory_error_display_verification_failed() {
    let error = FactoryError::VerificationFailed("Test verification failure".to_string());
    assert_eq!(error.to_string(), "Verification failed: Test verification failure");
}

#[test]
fn test_factory_error_display_invalid_input() {
    let error = FactoryError::InvalidInput("Test invalid input".to_string());
    assert_eq!(error.to_string(), "Invalid input: Test invalid input");
}

#[test]
fn test_factory_error_display_cbor_error() {
    let error = FactoryError::CborError("Test CBOR error".to_string());
    assert_eq!(error.to_string(), "CBOR error: Test CBOR error");
}

#[test]
fn test_factory_error_display_transparency_failed() {
    let error = FactoryError::TransparencyFailed("Test transparency failure".to_string());
    assert_eq!(error.to_string(), "Transparency failed: Test transparency failure");
}

#[test]
fn test_factory_error_display_payload_too_large() {
    let error = FactoryError::PayloadTooLargeForEmbedding(100, 50);
    assert_eq!(error.to_string(), "Payload too large for embedding: 100 bytes (max 50)");
}

#[test]
fn test_factory_error_is_error_trait() {
    let error = FactoryError::SigningFailed("test".to_string());
    assert!(std::error::Error::source(&error).is_none());
}

#[test]
fn test_from_signing_error_verification_failed() {
    let signing_error = SigningError::VerificationFailed("verification failed".to_string());
    let factory_error: FactoryError = signing_error.into();
    
    match factory_error {
        FactoryError::VerificationFailed(msg) => {
            assert_eq!(msg, "verification failed");
        }
        _ => panic!("Expected VerificationFailed variant"),
    }
}

#[test]
fn test_from_signing_error_other_variants() {
    let signing_error = SigningError::InvalidConfiguration("test context error".to_string());
    let factory_error: FactoryError = signing_error.into();
    
    match factory_error {
        FactoryError::SigningFailed(msg) => {
            assert!(msg.contains("Invalid configuration"));
        }
        _ => panic!("Expected SigningFailed variant"),
    }
}

#[test]
fn test_from_cose_sign1_error() {
    let cose_error = CoseSign1Error::InvalidMessage("test payload error".to_string());
    let factory_error: FactoryError = cose_error.into();
    
    match factory_error {
        FactoryError::SigningFailed(msg) => {
            assert!(msg.contains("invalid message"));
        }
        _ => panic!("Expected SigningFailed variant"),
    }
}

#[test]
fn test_factory_error_debug_formatting() {
    let error = FactoryError::PayloadTooLargeForEmbedding(1024, 512);
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("PayloadTooLargeForEmbedding"));
    assert!(debug_str.contains("1024"));
    assert!(debug_str.contains("512"));
}
