// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Final comprehensive coverage tests for validation core validator.
//! Targets uncovered async paths, error handling, and edge cases.

use cose_sign1_validation::fluent::{
    CoseSign1ValidationError, CoseSign1ValidationOptions, CoseSign1ValidationResult,
    CoseSign1Validator, CoseKeyResolutionResult,
    CounterSignatureResolutionResult,
    ValidationFailure, ValidationResult, ValidationResultKind,
    CoseSign1TrustPack,
    CoseSign1CompiledTrustPlan,
};

use std::collections::BTreeMap;
use std::sync::Arc;

// ============================================================================
// ValidationResultKind tests
// ============================================================================

#[test]
fn test_validation_result_kind_default() {
    let kind = ValidationResultKind::default();
    assert_eq!(kind, ValidationResultKind::NotApplicable);
}

#[test]
fn test_validation_result_kind_equality() {
    assert_eq!(ValidationResultKind::Success, ValidationResultKind::Success);
    assert_eq!(ValidationResultKind::Failure, ValidationResultKind::Failure);
    assert_eq!(ValidationResultKind::NotApplicable, ValidationResultKind::NotApplicable);
    
    assert_ne!(ValidationResultKind::Success, ValidationResultKind::Failure);
    assert_ne!(ValidationResultKind::Success, ValidationResultKind::NotApplicable);
    assert_ne!(ValidationResultKind::Failure, ValidationResultKind::NotApplicable);
}

// ============================================================================
// ValidationFailure tests
// ============================================================================

#[test]
fn test_validation_failure_default() {
    let failure = ValidationFailure::default();
    assert!(failure.message.is_empty());
    assert!(failure.error_code.is_none());
    assert!(failure.property_name.is_none());
    assert!(failure.attempted_value.is_none());
    assert!(failure.exception.is_none());
}

#[test]
fn test_validation_failure_with_all_fields() {
    let failure = ValidationFailure {
        message: "test message".to_string(),
        error_code: Some("ERR001".to_string()),
        property_name: Some("field_name".to_string()),
        attempted_value: Some("bad_value".to_string()),
        exception: Some("stack trace here".to_string()),
    };
    
    assert_eq!(failure.message, "test message");
    assert_eq!(failure.error_code.as_deref(), Some("ERR001"));
    assert_eq!(failure.property_name.as_deref(), Some("field_name"));
    assert_eq!(failure.attempted_value.as_deref(), Some("bad_value"));
    assert_eq!(failure.exception.as_deref(), Some("stack trace here"));
}

#[test]
fn test_validation_failure_clone() {
    let failure = ValidationFailure {
        message: "test".to_string(),
        error_code: Some("E1".to_string()),
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    
    let cloned = failure.clone();
    assert_eq!(cloned, failure);
}

#[test]
fn test_validation_failure_debug() {
    let failure = ValidationFailure {
        message: "test".to_string(),
        error_code: None,
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    
    let debug_str = format!("{:?}", failure);
    assert!(debug_str.contains("ValidationFailure"));
    assert!(debug_str.contains("test"));
}

// ============================================================================
// ValidationResult tests
// ============================================================================

#[test]
fn test_validation_result_default() {
    let result = ValidationResult::default();
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert!(result.validator_name.is_empty());
    assert!(result.failures.is_empty());
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_success() {
    let result = ValidationResult::success("TestValidator", None);
    
    assert!(result.is_valid());
    assert!(!result.is_failure());
    assert_eq!(result.validator_name, "TestValidator");
    assert!(result.failures.is_empty());
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_success_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key1".to_string(), "value1".to_string());
    metadata.insert("key2".to_string(), "value2".to_string());
    
    let result = ValidationResult::success("TestValidator", Some(metadata.clone()));
    
    assert!(result.is_valid());
    assert_eq!(result.metadata.len(), 2);
    assert_eq!(result.metadata.get("key1").unwrap(), "value1");
}

#[test]
fn test_validation_result_not_applicable_no_reason() {
    let result = ValidationResult::not_applicable("TestValidator", None);
    
    assert!(!result.is_valid());
    assert!(!result.is_failure());
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_not_applicable_with_reason() {
    let result = ValidationResult::not_applicable("TestValidator", Some("Prior stage failed"));
    
    assert!(!result.is_valid());
    assert!(!result.is_failure());
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert_eq!(
        result.metadata.get(ValidationResult::METADATA_REASON_KEY).unwrap(),
        "Prior stage failed"
    );
}

#[test]
fn test_validation_result_not_applicable_with_empty_reason() {
    let result = ValidationResult::not_applicable("TestValidator", Some("   "));
    
    // Empty/whitespace-only reason should not be stored
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_failure() {
    let failures = vec![
        ValidationFailure {
            message: "error 1".to_string(),
            ..ValidationFailure::default()
        },
        ValidationFailure {
            message: "error 2".to_string(),
            ..ValidationFailure::default()
        },
    ];
    
    let result = ValidationResult::failure("TestValidator", failures);
    
    assert!(!result.is_valid());
    assert!(result.is_failure());
    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.failures.len(), 2);
    assert_eq!(result.failures[0].message, "error 1");
    assert_eq!(result.failures[1].message, "error 2");
}

#[test]
fn test_validation_result_failure_message() {
    let result = ValidationResult::failure_message(
        "TestValidator",
        "Something went wrong",
        Some("ERR_CODE"),
    );
    
    assert!(result.is_failure());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].message, "Something went wrong");
    assert_eq!(result.failures[0].error_code.as_deref(), Some("ERR_CODE"));
}

#[test]
fn test_validation_result_failure_message_no_code() {
    let result = ValidationResult::failure_message("TestValidator", "Error", None);
    
    assert!(result.is_failure());
    assert_eq!(result.failures.len(), 1);
    assert!(result.failures[0].error_code.is_none());
}

#[test]
fn test_validation_result_clone() {
    let result = ValidationResult::success("Test", None);
    let cloned = result.clone();
    assert_eq!(cloned, result);
}

#[test]
fn test_validation_result_debug() {
    let result = ValidationResult::success("Test", None);
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("ValidationResult"));
}

// ============================================================================
// CoseKeyResolutionResult tests
// ============================================================================

#[test]
fn test_cose_key_resolution_result_default() {
    let result = CoseKeyResolutionResult::default();
    
    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert!(result.candidate_keys.is_empty());
    assert!(result.key_id.is_none());
    assert!(result.thumbprint.is_none());
    assert!(result.diagnostics.is_empty());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
}

#[test]
fn test_cose_key_resolution_result_failure() {
    let result = CoseKeyResolutionResult::failure(
        Some("KEY_NOT_FOUND".to_string()),
        Some("Could not find key".to_string()),
    );
    
    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert_eq!(result.error_code.as_deref(), Some("KEY_NOT_FOUND"));
    assert_eq!(result.error_message.as_deref(), Some("Could not find key"));
}

#[test]
fn test_cose_key_resolution_result_failure_no_details() {
    let result = CoseKeyResolutionResult::failure(None, None);
    
    assert!(!result.is_success);
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
}

// ============================================================================
// CounterSignatureResolutionResult tests
// ============================================================================

#[test]
fn test_counter_signature_resolution_result_default() {
    let result = CounterSignatureResolutionResult::default();
    
    assert!(!result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert!(result.diagnostics.is_empty());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
}

#[test]
fn test_counter_signature_resolution_result_success_empty() {
    let result = CounterSignatureResolutionResult::success(vec![]);
    
    assert!(result.is_success);
    assert!(result.counter_signatures.is_empty());
}

#[test]
fn test_counter_signature_resolution_result_failure() {
    let result = CounterSignatureResolutionResult::failure(
        Some("CS_NOT_FOUND".to_string()),
        Some("No counter signature found".to_string()),
    );
    
    assert!(!result.is_success);
    assert_eq!(result.error_code.as_deref(), Some("CS_NOT_FOUND"));
    assert_eq!(result.error_message.as_deref(), Some("No counter signature found"));
}

// ============================================================================
// CoseSign1ValidationOptions tests
// ============================================================================

#[test]
fn test_validation_options_default() {
    let options = CoseSign1ValidationOptions::default();
    
    assert!(options.detached_payload.is_none());
    assert!(options.associated_data.is_none());
    assert!(!options.skip_post_signature_validation);
}

#[test]
fn test_validation_options_debug() {
    let options = CoseSign1ValidationOptions::default();
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("CoseSign1ValidationOptions"));
}

// ============================================================================
// CoseSign1ValidationError tests
// ============================================================================

#[test]
fn test_validation_error_cose_decode_display() {
    let error = CoseSign1ValidationError::CoseDecode("invalid CBOR".to_string());
    let display = format!("{}", error);
    
    assert!(display.contains("COSE decode failed"));
    assert!(display.contains("invalid CBOR"));
}

#[test]
fn test_validation_error_trust_display() {
    let error = CoseSign1ValidationError::Trust("trust plan failed".to_string());
    let display = format!("{}", error);
    
    assert!(display.contains("trust evaluation failed"));
    assert!(display.contains("trust plan failed"));
}

#[test]
fn test_validation_error_debug() {
    let error = CoseSign1ValidationError::CoseDecode("test".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("CoseDecode"));
}

#[test]
fn test_validation_error_is_error_trait() {
    let error = CoseSign1ValidationError::Trust("test".to_string());
    
    // Should implement std::error::Error
    fn assert_error<T: std::error::Error>() {}
    assert_error::<CoseSign1ValidationError>();
}

// ============================================================================
// CoseSign1ValidatorInit tests - removed as type is not publicly exported
// ============================================================================

// ============================================================================
// CoseSign1Validator constants tests  
// ============================================================================

#[test]
fn test_validator_constants() {
    // Validator name constants
    assert!(!CoseSign1Validator::VALIDATOR_NAME_OVERALL.is_empty());
    assert!(!CoseSign1Validator::STAGE_NAME_KEY_MATERIAL_RESOLUTION.is_empty());
    assert!(!CoseSign1Validator::STAGE_NAME_KEY_MATERIAL_TRUST.is_empty());
    assert!(!CoseSign1Validator::STAGE_NAME_SIGNATURE.is_empty());
    assert!(!CoseSign1Validator::STAGE_NAME_POST_SIGNATURE.is_empty());
    
    // Not applicable reasons
    assert!(!CoseSign1Validator::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED.is_empty());
    assert!(!CoseSign1Validator::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED.is_empty());
    
    // Metadata prefixes
    assert!(!CoseSign1Validator::METADATA_PREFIX_RESOLUTION.is_empty());
    assert!(!CoseSign1Validator::METADATA_PREFIX_TRUST.is_empty());
    assert!(!CoseSign1Validator::METADATA_PREFIX_SIGNATURE.is_empty());
    assert!(!CoseSign1Validator::METADATA_KEY_SEPARATOR.is_empty());
    
    // Error codes
    assert!(!CoseSign1Validator::ERROR_CODE_TRUST_PLAN_NOT_SATISFIED.is_empty());
    assert!(!CoseSign1Validator::ERROR_CODE_NO_SIGNING_KEY_RESOLVED.is_empty());
    assert!(!CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.is_empty());
    assert!(!CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD.is_empty());
    assert!(!CoseSign1Validator::ERROR_CODE_ALGORITHM_MISMATCH.is_empty());
    
    // Streaming threshold
    assert!(CoseSign1Validator::LARGE_STREAM_THRESHOLD > 0);
}

// ============================================================================
// ValidationResult metadata constant tests
// ============================================================================

#[test]
fn test_validation_result_metadata_reason_key() {
    assert_eq!(ValidationResult::METADATA_REASON_KEY, "Reason");
}

// ============================================================================
// Validation result helpers - additional tests
// ============================================================================

#[test]
fn test_validation_result_is_valid_for_each_kind() {
    let success = ValidationResult {
        kind: ValidationResultKind::Success,
        validator_name: "test".into(),
        failures: vec![],
        metadata: BTreeMap::new(),
    };
    assert!(success.is_valid());
    assert!(!success.is_failure());
    
    let failure = ValidationResult {
        kind: ValidationResultKind::Failure,
        validator_name: "test".into(),
        failures: vec![],
        metadata: BTreeMap::new(),
    };
    assert!(!failure.is_valid());
    assert!(failure.is_failure());
    
    let not_applicable = ValidationResult {
        kind: ValidationResultKind::NotApplicable,
        validator_name: "test".into(),
        failures: vec![],
        metadata: BTreeMap::new(),
    };
    assert!(!not_applicable.is_valid());
    assert!(!not_applicable.is_failure());
}

// ============================================================================
// Additional edge case tests
// ============================================================================

#[test]
fn test_validation_result_equality() {
    let result1 = ValidationResult::success("Test", None);
    let result2 = ValidationResult::success("Test", None);
    assert_eq!(result1, result2);
    
    let result3 = ValidationResult::failure_message("Test", "error", None);
    assert_ne!(result1, result3);
}

#[test]
fn test_cose_key_resolution_result_clone() {
    let result = CoseKeyResolutionResult::failure(Some("ERR".into()), None);
    let cloned = result.clone();
    assert_eq!(cloned.error_code, result.error_code);
}

#[test]
fn test_counter_signature_resolution_result_clone() {
    let result = CounterSignatureResolutionResult::failure(Some("ERR".into()), None);
    let cloned = result.clone();
    assert_eq!(cloned.error_code, result.error_code);
}

#[test]
fn test_validation_failure_equality() {
    let f1 = ValidationFailure {
        message: "test".to_string(),
        error_code: Some("E1".to_string()),
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    
    let f2 = f1.clone();
    assert_eq!(f1, f2);
    
    let f3 = ValidationFailure::default();
    assert_ne!(f1, f3);
}

// ============================================================================
// CoseSign1ValidationResult tests
// ============================================================================

#[test]
fn test_cose_sign1_validation_result_debug() {
    let result = CoseSign1ValidationResult {
        resolution: ValidationResult::success("Resolution", None),
        trust: ValidationResult::success("Trust", None),
        signature: ValidationResult::success("Signature", None),
        post_signature_policy: ValidationResult::success("Post", None),
        overall: ValidationResult::success("Overall", None),
    };
    
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("CoseSign1ValidationResult"));
}

#[test]
fn test_cose_sign1_validation_result_equality() {
    let result1 = CoseSign1ValidationResult {
        resolution: ValidationResult::success("Resolution", None),
        trust: ValidationResult::success("Trust", None),
        signature: ValidationResult::success("Signature", None),
        post_signature_policy: ValidationResult::success("Post", None),
        overall: ValidationResult::success("Overall", None),
    };
    
    let result2 = result1.clone();
    assert_eq!(result1, result2);
}

#[test]
fn test_cose_sign1_validation_result_with_failures() {
    let result = CoseSign1ValidationResult {
        resolution: ValidationResult::failure_message("Resolution", "no key", Some("ERR1")),
        trust: ValidationResult::not_applicable("Trust", Some("Prior stage failed")),
        signature: ValidationResult::not_applicable("Signature", Some("Prior stage failed")),
        post_signature_policy: ValidationResult::not_applicable("Post", Some("Prior stage failed")),
        overall: ValidationResult::failure_message("Overall", "validation failed", Some("ERR_OVERALL")),
    };
    
    assert!(result.resolution.is_failure());
    assert!(!result.trust.is_failure());
    assert!(result.overall.is_failure());
}
