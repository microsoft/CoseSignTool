// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use code_transparency_client::CodeTransparencyError;

#[test]
fn test_mst_client_error_http_error_display() {
    let error = CodeTransparencyError::HttpError("connection refused".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "HTTP error: connection refused");
}

#[test]
fn test_mst_client_error_cbor_parse_error_display() {
    let error = CodeTransparencyError::CborParseError("invalid encoding".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "CBOR parse error: invalid encoding");
}

#[test]
fn test_mst_client_error_operation_timeout_display() {
    let error = CodeTransparencyError::OperationTimeout {
        operation_id: "op-123".to_string(),
        retries: 5,
    };
    let display = format!("{}", error);
    assert_eq!(display, "Operation op-123 timed out after 5 retries");
}

#[test]
fn test_mst_client_error_operation_failed_display() {
    let error = CodeTransparencyError::OperationFailed {
        operation_id: "op-456".to_string(),
        status: "Failed".to_string(),
    };
    let display = format!("{}", error);
    assert_eq!(display, "Operation op-456 failed with status: Failed");
}

#[test]
fn test_mst_client_error_missing_field_display() {
    let error = CodeTransparencyError::MissingField {
        field: "EntryId".to_string(),
    };
    let display = format!("{}", error);
    assert_eq!(display, "Missing required field: EntryId");
}

#[test]
fn test_mst_client_error_debug() {
    let error = CodeTransparencyError::HttpError("test message".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("HttpError"));
    assert!(debug_str.contains("test message"));
}

#[test]
fn test_mst_client_error_is_std_error() {
    let error = CodeTransparencyError::OperationTimeout {
        operation_id: "test".to_string(),
        retries: 3,
    };
    
    // Test that it implements std::error::Error
    let error_trait: &dyn std::error::Error = &error;
    assert!(error_trait.to_string().contains("Operation test timed out after 3 retries"));
}