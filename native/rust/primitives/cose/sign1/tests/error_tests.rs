// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error types: Display, Error, and From conversions.

use cose_sign1_primitives::error::{CoseKeyError, CoseSign1Error, PayloadError};
use crypto_primitives::CryptoError;
use std::error::Error;

#[test]
fn test_cose_key_error_display_crypto() {
    let crypto_err = CryptoError::SigningFailed("test failure".to_string());
    let err = CoseKeyError::Crypto(crypto_err);
    assert!(format!("{}", err).contains("test failure"));
}

#[test]
fn test_cose_key_error_display_sig_structure_failed() {
    let err = CoseKeyError::SigStructureFailed("bad structure".to_string());
    assert_eq!(format!("{}", err), "sig_structure failed: bad structure");
}

#[test]
fn test_cose_key_error_display_cbor_error() {
    let err = CoseKeyError::CborError("bad cbor".to_string());
    assert_eq!(format!("{}", err), "CBOR error: bad cbor");
}

#[test]
fn test_cose_key_error_display_io_error() {
    let err = CoseKeyError::IoError("io fail".to_string());
    assert_eq!(format!("{}", err), "I/O error: io fail");
}

#[test]
fn test_cose_key_error_is_std_error() {
    let err = CoseKeyError::IoError("test".to_string());
    let _: &dyn Error = &err;
}

#[test]
fn test_payload_error_display_open_failed() {
    let err = PayloadError::OpenFailed("not found".to_string());
    assert_eq!(format!("{}", err), "failed to open payload: not found");
}

#[test]
fn test_payload_error_display_read_failed() {
    let err = PayloadError::ReadFailed("read err".to_string());
    assert_eq!(format!("{}", err), "failed to read payload: read err");
}

#[test]
fn test_payload_error_is_std_error() {
    let err = PayloadError::OpenFailed("test".to_string());
    let _: &dyn Error = &err;
}

#[test]
fn test_cose_sign1_error_display_cbor_error() {
    let err = CoseSign1Error::CborError("bad cbor".to_string());
    assert_eq!(format!("{}", err), "CBOR error: bad cbor");
}

#[test]
fn test_cose_sign1_error_display_key_error() {
    let inner = CoseKeyError::IoError("key err".to_string());
    let err = CoseSign1Error::KeyError(inner);
    assert_eq!(format!("{}", err), "key error: I/O error: key err");
}

#[test]
fn test_cose_sign1_error_display_payload_error() {
    let inner = PayloadError::ReadFailed("payload err".to_string());
    let err = CoseSign1Error::PayloadError(inner);
    assert_eq!(
        format!("{}", err),
        "payload error: failed to read payload: payload err"
    );
}

#[test]
fn test_cose_sign1_error_display_invalid_message() {
    let err = CoseSign1Error::InvalidMessage("bad msg".to_string());
    assert_eq!(format!("{}", err), "invalid message: bad msg");
}

#[test]
fn test_cose_sign1_error_display_payload_missing() {
    let err = CoseSign1Error::PayloadMissing;
    assert_eq!(
        format!("{}", err),
        "payload is detached but none provided"
    );
}

#[test]
fn test_cose_sign1_error_display_signature_mismatch() {
    let err = CoseSign1Error::SignatureMismatch;
    assert_eq!(format!("{}", err), "signature verification failed");
}

#[test]
fn test_cose_sign1_error_source_key_error() {
    let inner = CoseKeyError::CborError("bad".to_string());
    let err = CoseSign1Error::KeyError(inner);
    assert!(err.source().is_some());
}

#[test]
fn test_cose_sign1_error_source_payload_error() {
    let inner = PayloadError::OpenFailed("fail".to_string());
    let err = CoseSign1Error::PayloadError(inner);
    assert!(err.source().is_some());
}

#[test]
fn test_cose_sign1_error_source_none_for_others() {
    assert!(CoseSign1Error::CborError("x".to_string()).source().is_none());
    assert!(CoseSign1Error::InvalidMessage("x".to_string()).source().is_none());
    assert!(CoseSign1Error::PayloadMissing.source().is_none());
    assert!(CoseSign1Error::SignatureMismatch.source().is_none());
}

#[test]
fn test_from_cose_key_error_to_cose_sign1_error() {
    let key_err = CoseKeyError::IoError("fail".to_string());
    let err: CoseSign1Error = key_err.into();
    match err {
        CoseSign1Error::KeyError(_) => {}
        _ => panic!("expected KeyError variant"),
    }
}

#[test]
fn test_from_payload_error_to_cose_sign1_error() {
    let pay_err = PayloadError::OpenFailed("fail".to_string());
    let err: CoseSign1Error = pay_err.into();
    match err {
        CoseSign1Error::PayloadError(_) => {}
        _ => panic!("expected PayloadError variant"),
    }
}

#[test]
fn test_payload_error_display_length_mismatch() {
    let err = PayloadError::LengthMismatch {
        expected: 100,
        actual: 42,
    };
    assert_eq!(
        format!("{}", err),
        "payload length mismatch: expected 100 bytes, got 42"
    );
}

#[test]
fn test_cose_sign1_error_display_io_error() {
    let err = CoseSign1Error::IoError("disk full".to_string());
    assert_eq!(format!("{}", err), "I/O error: disk full");
}

#[test]
fn test_cose_sign1_error_source_none_for_io_error() {
    assert!(CoseSign1Error::IoError("x".to_string()).source().is_none());
}
