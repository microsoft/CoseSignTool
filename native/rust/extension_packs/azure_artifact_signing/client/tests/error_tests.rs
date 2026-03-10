// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::AasClientError;
use std::error::Error;

#[test]
fn test_http_error_display() {
    let error = AasClientError::HttpError("Network timeout".to_string());
    assert!(error.to_string().contains("HTTP error"));
    assert!(error.to_string().contains("Network timeout"));
}

#[test]
fn test_authentication_failed_display() {
    let error = AasClientError::AuthenticationFailed("Token expired".to_string());
    assert!(error.to_string().contains("Authentication failed"));
    assert!(error.to_string().contains("Token expired"));
}

#[test]
fn test_service_error_display_with_target() {
    let error = AasClientError::ServiceError {
        code: "InvalidParam".to_string(),
        message: "Bad request".to_string(),
        target: Some("digest".to_string()),
    };
    let error_str = error.to_string();
    assert!(error_str.contains("InvalidParam"));
    assert!(error_str.contains("Bad request"));
    assert!(error_str.contains("digest"));
    assert!(error_str.contains("target"));
}

#[test]
fn test_service_error_display_without_target() {
    let error = AasClientError::ServiceError {
        code: "ServerError".to_string(),
        message: "Internal server error".to_string(),
        target: None,
    };
    let error_str = error.to_string();
    assert!(error_str.contains("ServerError"));
    assert!(error_str.contains("Internal server error"));
    assert!(!error_str.contains("target"));
}

#[test]
fn test_operation_failed_display() {
    let error = AasClientError::OperationFailed {
        operation_id: "op-12345".to_string(),
        status: "Failed".to_string(),
    };
    let error_str = error.to_string();
    assert!(error_str.contains("op-12345"));
    assert!(error_str.contains("Failed"));
}

#[test]
fn test_operation_timeout_display() {
    let error = AasClientError::OperationTimeout {
        operation_id: "op-67890".to_string(),
    };
    let error_str = error.to_string();
    assert!(error_str.contains("timed out"));
    assert!(error_str.contains("op-67890"));
}

#[test]
fn test_deserialization_error_display() {
    let error = AasClientError::DeserializationError("Invalid JSON".to_string());
    assert!(error.to_string().contains("Deserialization"));
    assert!(error.to_string().contains("Invalid JSON"));
}

#[test]
fn test_invalid_configuration_display() {
    let error = AasClientError::InvalidConfiguration("Missing endpoint".to_string());
    assert!(error.to_string().contains("Invalid configuration"));
    assert!(error.to_string().contains("Missing endpoint"));
}

#[test]
fn test_certificate_chain_not_available_display() {
    let error = AasClientError::CertificateChainNotAvailable("Chain expired".to_string());
    assert!(error.to_string().contains("Certificate chain"));
    assert!(error.to_string().contains("Chain expired"));
}

#[test]
fn test_sign_failed_display() {
    let error = AasClientError::SignFailed("Signing service unavailable".to_string());
    assert!(error.to_string().contains("Sign failed"));
    assert!(error.to_string().contains("Signing service unavailable"));
}

#[test]
fn test_error_trait_implementation() {
    let error = AasClientError::HttpError("Test error".to_string());
    
    // Test that it can be converted to Box<dyn Error>
    let boxed_error: Box<dyn Error> = Box::new(error);
    assert!(boxed_error.to_string().contains("HTTP error"));
    
    // Test that Error trait methods work
    assert!(boxed_error.source().is_none());
}

#[test]
fn test_all_variants_implement_error_trait() {
    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(AasClientError::HttpError("test".to_string())),
        Box::new(AasClientError::AuthenticationFailed("test".to_string())),
        Box::new(AasClientError::ServiceError {
            code: "test".to_string(),
            message: "test".to_string(),
            target: None,
        }),
        Box::new(AasClientError::OperationFailed {
            operation_id: "test".to_string(),
            status: "test".to_string(),
        }),
        Box::new(AasClientError::OperationTimeout {
            operation_id: "test".to_string(),
        }),
        Box::new(AasClientError::DeserializationError("test".to_string())),
        Box::new(AasClientError::InvalidConfiguration("test".to_string())),
        Box::new(AasClientError::CertificateChainNotAvailable("test".to_string())),
        Box::new(AasClientError::SignFailed("test".to_string())),
    ];
    
    // Verify all variants can be used as Error trait objects
    for error in errors {
        assert!(!error.to_string().is_empty());
    }
}