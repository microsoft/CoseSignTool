// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for COSE error types.

use cose_primitives::CoseError;
use std::error::Error;

#[test]
fn test_cbor_error_display() {
    let error = CoseError::CborError("failed to decode array".to_string());
    assert_eq!(error.to_string(), "CBOR error: failed to decode array");
}

#[test]
fn test_invalid_message_error_display() {
    let error = CoseError::InvalidMessage("missing required header".to_string());
    assert_eq!(
        error.to_string(),
        "invalid message: missing required header"
    );
}

#[test]
fn test_error_is_error_trait() {
    let error = CoseError::CborError("test".to_string());

    // Should implement Error trait
    let _err: &dyn Error = &error;

    // Should have no source by default (since we implement Error but not source())
    assert!(error.source().is_none());
}

#[test]
fn test_error_debug_format() {
    let cbor_error = CoseError::CborError("decode failed".to_string());
    let debug_str = format!("{:?}", cbor_error);
    assert!(debug_str.contains("CborError"));
    assert!(debug_str.contains("decode failed"));

    let invalid_error = CoseError::InvalidMessage("bad format".to_string());
    let debug_str = format!("{:?}", invalid_error);
    assert!(debug_str.contains("InvalidMessage"));
    assert!(debug_str.contains("bad format"));
}

#[test]
fn test_error_variants_equality() {
    // Ensure different error types produce different strings
    let cbor_err = CoseError::CborError("test".to_string());
    let msg_err = CoseError::InvalidMessage("test".to_string());

    assert_ne!(cbor_err.to_string(), msg_err.to_string());
    assert!(cbor_err.to_string().starts_with("CBOR error:"));
    assert!(msg_err.to_string().starts_with("invalid message:"));
}

#[test]
fn test_empty_error_messages() {
    let cbor_err = CoseError::CborError(String::new());
    assert_eq!(cbor_err.to_string(), "CBOR error: ");

    let msg_err = CoseError::InvalidMessage(String::new());
    assert_eq!(msg_err.to_string(), "invalid message: ");
}

#[test]
fn test_error_with_special_characters() {
    let error = CoseError::CborError("message with\nnewline and\ttab".to_string());
    let display_str = error.to_string();
    assert!(display_str.contains("newline"));
    assert!(display_str.contains("tab"));
    assert!(display_str.starts_with("CBOR error:"));
}
