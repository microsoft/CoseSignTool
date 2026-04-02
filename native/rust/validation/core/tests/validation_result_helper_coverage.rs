// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple coverage tests for ValidationResult helper methods and defaults.

use cose_sign1_validation::fluent::{ValidationFailure, ValidationResult, ValidationResultKind};
use std::collections::BTreeMap;

#[test]
fn test_validation_result_kind_default() {
    let kind = ValidationResultKind::default();
    assert_eq!(kind, ValidationResultKind::NotApplicable);
}

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
fn test_validation_result_success_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key".to_string(), "value".to_string());

    let result = ValidationResult::success("test-validator", Some(metadata.clone()));
    assert_eq!(result.kind, ValidationResultKind::Success);
    assert_eq!(result.validator_name, "test-validator");
    assert!(result.failures.is_empty());
    assert_eq!(result.metadata, metadata);
}

#[test]
fn test_validation_result_success_no_metadata() {
    let result = ValidationResult::success("test-validator", None);
    assert_eq!(result.kind, ValidationResultKind::Success);
    assert_eq!(result.validator_name, "test-validator");
    assert!(result.failures.is_empty());
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_not_applicable_with_reason() {
    let result = ValidationResult::not_applicable("test-validator", Some("no certificates"));
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert_eq!(result.validator_name, "test-validator");
    assert!(result.failures.is_empty());

    // Should have reason in metadata
    let reason = result.metadata.get(ValidationResult::METADATA_REASON_KEY);
    assert_eq!(reason, Some(&"no certificates".to_string()));
}

#[test]
fn test_validation_result_not_applicable_empty_reason() {
    let result = ValidationResult::not_applicable("test-validator", Some("   "));
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert_eq!(result.validator_name, "test-validator");
    assert!(result.failures.is_empty());

    // Empty/whitespace reason should not be stored
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_not_applicable_no_reason() {
    let result = ValidationResult::not_applicable("test-validator", None);
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert_eq!(result.validator_name, "test-validator");
    assert!(result.failures.is_empty());
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_failure_multiple() {
    let failures = vec![
        ValidationFailure {
            message: "error 1".to_string(),
            error_code: Some("E001".to_string()),
            property_name: Some("prop1".to_string()),
            attempted_value: Some("val1".to_string()),
            exception: Some("ex1".to_string()),
        },
        ValidationFailure {
            message: "error 2".to_string(),
            error_code: None,
            property_name: None,
            attempted_value: None,
            exception: None,
        },
    ];

    let result = ValidationResult::failure("test-validator", failures.clone());
    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.validator_name, "test-validator");
    assert_eq!(result.failures, failures);
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_failure_message_with_code() {
    let result = ValidationResult::failure_message("test-validator", "test error", Some("ERR123"));

    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.validator_name, "test-validator");
    assert_eq!(result.failures.len(), 1);

    let failure = &result.failures[0];
    assert_eq!(failure.message, "test error");
    assert_eq!(failure.error_code, Some("ERR123".to_string()));
    assert!(failure.property_name.is_none());
    assert!(failure.attempted_value.is_none());
    assert!(failure.exception.is_none());
}

#[test]
fn test_validation_result_failure_message_no_code() {
    let result = ValidationResult::failure_message("test-validator", "test error", None);

    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.validator_name, "test-validator");
    assert_eq!(result.failures.len(), 1);

    let failure = &result.failures[0];
    assert_eq!(failure.message, "test error");
    assert_eq!(failure.error_code, None);
    assert!(failure.property_name.is_none());
    assert!(failure.attempted_value.is_none());
    assert!(failure.exception.is_none());
}

#[test]
fn test_validation_result_kind_debug() {
    let kind = ValidationResultKind::Success;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("Success"));

    let kind = ValidationResultKind::Failure;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("Failure"));

    let kind = ValidationResultKind::NotApplicable;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("NotApplicable"));
}

#[test]
fn test_validation_failure_debug() {
    let failure = ValidationFailure {
        message: "test message".to_string(),
        error_code: Some("TEST".to_string()),
        property_name: Some("field".to_string()),
        attempted_value: Some("value".to_string()),
        exception: Some("Exception info".to_string()),
    };

    let debug_str = format!("{:?}", failure);
    assert!(debug_str.contains("test message"));
    assert!(debug_str.contains("TEST"));
    assert!(debug_str.contains("field"));
    assert!(debug_str.contains("value"));
    assert!(debug_str.contains("Exception info"));
}

#[test]
fn test_validation_result_debug() {
    let result = ValidationResult::success("test", None);
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("ValidationResult"));
    assert!(debug_str.contains("Success"));
    assert!(debug_str.contains("test"));
}

#[test]
fn test_validation_result_is_valid() {
    let success_result = ValidationResult::success("test", None);
    assert!(success_result.is_valid());

    let failure_result = ValidationResult::failure_message("test", "error", None);
    assert!(!failure_result.is_valid());

    let not_applicable_result = ValidationResult::not_applicable("test", None);
    assert!(!not_applicable_result.is_valid());
}

#[test]
fn test_validation_failure_clone() {
    let failure = ValidationFailure {
        message: "test message".to_string(),
        error_code: Some("TEST".to_string()),
        property_name: Some("field".to_string()),
        attempted_value: Some("value".to_string()),
        exception: Some("Exception info".to_string()),
    };

    let cloned = failure.clone();
    assert_eq!(failure, cloned);
    assert_eq!(failure.message, cloned.message);
    assert_eq!(failure.error_code, cloned.error_code);
}

#[test]
fn test_validation_result_clone() {
    let result = ValidationResult::failure_message("test", "error", Some("ERR"));
    let cloned = result.clone();
    assert_eq!(result, cloned);
    assert_eq!(result.validator_name, cloned.validator_name);
    assert_eq!(result.kind, cloned.kind);
    assert_eq!(result.failures, cloned.failures);
    assert_eq!(result.metadata, cloned.metadata);
}
