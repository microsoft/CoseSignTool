// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_headers::HeaderError;

#[test]
fn test_cbor_encoding_error_display() {
    let error = HeaderError::CborEncodingError("test encoding error".into());
    assert_eq!(
        error.to_string(),
        "CBOR encoding error: test encoding error"
    );
}

#[test]
fn test_cbor_decoding_error_display() {
    let error = HeaderError::CborDecodingError("test decoding error".into());
    assert_eq!(
        error.to_string(),
        "CBOR decoding error: test decoding error"
    );
}

#[test]
fn test_invalid_claim_type_display() {
    let error = HeaderError::InvalidClaimType {
        label: 42,
        expected: "string".into(),
        actual: "integer".into(),
    };
    assert_eq!(
        error.to_string(),
        "Invalid CWT claim type for label 42: expected string, got integer"
    );
}

#[test]
fn test_missing_required_claim_display() {
    let error = HeaderError::MissingRequiredClaim("issuer".into());
    assert_eq!(error.to_string(), "Missing required claim: issuer");
}

#[test]
fn test_invalid_timestamp_display() {
    let error = HeaderError::InvalidTimestamp("timestamp out of range".into());
    assert_eq!(
        error.to_string(),
        "Invalid timestamp value: timestamp out of range"
    );
}

#[test]
fn test_complex_claim_value_display() {
    let error = HeaderError::ComplexClaimValue("nested object not supported".into());
    assert_eq!(
        error.to_string(),
        "Custom claim value too complex: nested object not supported"
    );
}

#[test]
fn test_header_error_is_error_trait() {
    let error = HeaderError::CborEncodingError("test".into());
    assert!(std::error::Error::source(&error).is_none());
}
