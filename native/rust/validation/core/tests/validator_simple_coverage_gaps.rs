// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple targeted coverage tests for validator gaps.
//! Focus on async paths and result helpers without complex mocks.

use cose_sign1_validation::fluent::{
    CoseSign1ValidationError, CoseSign1ValidationOptions, CoseSign1ValidationResult,
    CoseSign1Validator, CoseKeyResolutionResult,
    CounterSignatureResolutionResult,
    ValidationFailure, ValidationResult, ValidationResultKind,
};
use std::collections::BTreeMap;
use std::sync::Arc;

#[test]
fn test_validation_result_kind_comprehensive() {
    let kind_default = ValidationResultKind::default();
    assert_eq!(kind_default, ValidationResultKind::NotApplicable);
    
    let kind_success = ValidationResultKind::Success;
    let kind_failure = ValidationResultKind::Failure;
    let kind_na = ValidationResultKind::NotApplicable;
    
    // Test equality and inequality
    assert_eq!(kind_success, ValidationResultKind::Success);
    assert_ne!(kind_success, kind_failure);
    assert_ne!(kind_success, kind_na);
    assert_ne!(kind_failure, kind_na);
}

#[test]
fn test_validation_failure_fields() {
    let mut failure = ValidationFailure::default();
    assert!(failure.message.is_empty());
    assert!(failure.error_code.is_none());
    assert!(failure.property_name.is_none());
    assert!(failure.attempted_value.is_none());
    assert!(failure.exception.is_none());
    
    // Test field assignment
    failure.message = "Test message".to_string();
    failure.error_code = Some("TEST_CODE".to_string());
    failure.property_name = Some("test_prop".to_string());
    failure.attempted_value = Some("test_val".to_string());
    failure.exception = Some("test_exception".to_string());
    
    assert_eq!(failure.message, "Test message");
    assert_eq!(failure.error_code.as_deref(), Some("TEST_CODE"));
    assert_eq!(failure.property_name.as_deref(), Some("test_prop"));
    assert_eq!(failure.attempted_value.as_deref(), Some("test_val"));
    assert_eq!(failure.exception.as_deref(), Some("test_exception"));
}

#[test]
fn test_validation_result_methods() {
    // Test success result
    let success_result = ValidationResult::success("TestValidator".to_string(), None);
    assert!(success_result.is_valid());
    assert!(!success_result.is_failure());
    assert_eq!(success_result.kind, ValidationResultKind::Success);
    assert_eq!(success_result.validator_name, "TestValidator");
    
    // Test failure result
    let failure_result = ValidationResult::failure_message(
        "TestValidator",
        "Test failure message",
        Some("TEST_ERROR_CODE"),
    );
    assert!(!failure_result.is_valid());
    assert!(failure_result.is_failure());
    assert_eq!(failure_result.kind, ValidationResultKind::Failure);
    assert_eq!(failure_result.failures.len(), 1);
    assert_eq!(failure_result.failures[0].message, "Test failure message");
    assert_eq!(failure_result.failures[0].error_code.as_deref(), Some("TEST_ERROR_CODE"));
    
    // Test not applicable result
    let na_result = ValidationResult::not_applicable("TestValidator", Some("reason"));
    assert_eq!(na_result.kind, ValidationResultKind::NotApplicable);
    assert!(!na_result.is_valid());
    assert!(!na_result.is_failure());
    assert!(na_result.metadata.contains_key(ValidationResult::METADATA_REASON_KEY));
}

#[test]
fn test_validation_result_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("test_key".to_string(), "test_value".to_string());
    metadata.insert("another_key".to_string(), "another_value".to_string());
    
    let result = ValidationResult::success("TestValidator".to_string(), Some(metadata.clone()));
    assert!(result.is_valid());
    assert_eq!(result.metadata, metadata);
    assert_eq!(result.metadata.get("test_key").unwrap(), "test_value");
}

#[test]
fn test_cose_key_resolution_result_success() {
    use crypto_primitives::CryptoVerifier;
    
    // Simple mock verifier for testing
    struct TestVerifier;
    impl CryptoVerifier for TestVerifier {
        fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, crypto_primitives::CryptoError> {
            Ok(true)
        }
        fn algorithm(&self) -> i64 { -7 }  // ES256
    }
    
    let verifier = Arc::new(TestVerifier);
    let result = CoseKeyResolutionResult::success(verifier.clone());
    
    assert!(result.is_success);
    assert!(result.cose_key.is_some());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
    assert!(result.diagnostics.is_empty());
}

#[test]
fn test_cose_key_resolution_result_failure() {
    let result = CoseKeyResolutionResult::failure(
        Some("KEY_NOT_FOUND".to_string()),
        Some("Unable to resolve signing key".to_string())
    );
    
    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert_eq!(result.error_code.as_deref(), Some("KEY_NOT_FOUND"));
    assert_eq!(result.error_message.as_deref(), Some("Unable to resolve signing key"));
}

#[test]
fn test_counter_signature_resolution_result_success() {
    let result = CounterSignatureResolutionResult::success(vec![]);
    
    assert!(result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
}

#[test] 
fn test_counter_signature_resolution_result_failure() {
    let result = CounterSignatureResolutionResult::failure(
        Some("CS_ERROR".to_string()),
        Some("Counter signature resolution failed".to_string())
    );
    
    assert!(!result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert_eq!(result.error_code.as_deref(), Some("CS_ERROR"));
    assert_eq!(result.error_message.as_deref(), Some("Counter signature resolution failed"));
}

#[test]
fn test_validation_options_defaults() {
    let options = CoseSign1ValidationOptions::default();
    
    assert!(options.detached_payload.is_none());
    assert!(options.associated_data.is_none());
    assert!(!options.skip_post_signature_validation);
}

#[test]
fn test_validation_options_with_detached_payload() {
    let mut options = CoseSign1ValidationOptions::default();
    options.skip_post_signature_validation = true;
    
    assert!(options.detached_payload.is_none());
    assert!(options.skip_post_signature_validation);
}

#[test]
fn test_validation_error_types() {
    let decode_error = CoseSign1ValidationError::CoseDecode("Invalid CBOR".to_string());
    match decode_error {
        CoseSign1ValidationError::CoseDecode(msg) => assert_eq!(msg, "Invalid CBOR"),
        _ => panic!("Unexpected error type"),
    }
    
    let trust_error = CoseSign1ValidationError::Trust("Trust evaluation failed".to_string());
    match trust_error {
        CoseSign1ValidationError::Trust(msg) => assert_eq!(msg, "Trust evaluation failed"),
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_validation_result_metadata_reason_key() {
    assert_eq!(ValidationResult::METADATA_REASON_KEY, "Reason");
}

// Test Clone implementations for coverage
#[test] 
fn test_cloneable_types() {
    let failure = ValidationFailure {
        message: "test".to_string(),
        error_code: Some("CODE".to_string()),
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    let cloned_failure = failure.clone();
    assert_eq!(failure.message, cloned_failure.message);
    assert_eq!(failure.error_code, cloned_failure.error_code);
    
    let result = ValidationResult {
        kind: ValidationResultKind::Success,
        validator_name: "test".to_string(),
        failures: vec![failure],
        metadata: BTreeMap::new(),
    };
    let cloned_result = result.clone();
    assert_eq!(result.kind, cloned_result.kind);
    assert_eq!(result.validator_name, cloned_result.validator_name);
    
    let cs_result = CounterSignatureResolutionResult::success(vec![]);
    let cloned_cs = cs_result.clone();
    assert_eq!(cs_result.is_success, cloned_cs.is_success);
}

// Test PartialEq implementations for coverage
#[test]
fn test_partial_eq_implementations() {
    let failure1 = ValidationFailure::default();
    let failure2 = ValidationFailure::default();
    assert_eq!(failure1, failure2);
    
    let result1 = ValidationResult::success("test".to_string(), None);
    let result2 = ValidationResult::success("test".to_string(), None);
    assert_eq!(result1, result2);
    
    let result3 = ValidationResult::failure_message("test", "error", None);
    assert_ne!(result1, result3);
}

// Test Debug implementations for coverage  
#[test]
fn test_debug_implementations() {
    let failure = ValidationFailure::default();
    let debug_str = format!("{:?}", failure);
    assert!(debug_str.contains("ValidationFailure"));
    
    let result = ValidationResult::success("test".to_string(), None);
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("ValidationResult"));
    
    let kind = ValidationResultKind::Success;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("Success"));
}
