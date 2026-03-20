// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for CoseSign1 error types, message parsing edge cases,
//! Sig_structure encoding, FilePayload errors, and constants.

use cose_primitives::CoseError;
use cose_sign1_primitives::error::{CoseKeyError, CoseSign1Error, PayloadError};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::FilePayload;
use cose_sign1_primitives::sig_structure::{
    build_sig_structure, build_sig_structure_prefix, SIG_STRUCTURE_CONTEXT,
};
use cose_sign1_primitives::{
    COSE_SIGN1_TAG, DEFAULT_CHUNK_SIZE, LARGE_PAYLOAD_THRESHOLD, MAX_EMBED_PAYLOAD_SIZE,
};
use crypto_primitives::CryptoError;
use std::error::Error;

#[test]
fn cose_sign1_error_display_all_variants() {
    assert_eq!(
        CoseSign1Error::CborError("bad".into()).to_string(),
        "CBOR error: bad"
    );
    assert_eq!(
        CoseSign1Error::InvalidMessage("nope".into()).to_string(),
        "invalid message: nope"
    );
    assert_eq!(
        CoseSign1Error::PayloadMissing.to_string(),
        "payload is detached but none provided"
    );
    assert_eq!(
        CoseSign1Error::SignatureMismatch.to_string(),
        "signature verification failed"
    );
    assert_eq!(
        CoseSign1Error::IoError("disk".into()).to_string(),
        "I/O error: disk"
    );
    assert_eq!(
        CoseSign1Error::PayloadTooLargeForEmbedding(100, 50).to_string(),
        "payload too large for embedding: 100 bytes (max 50)"
    );
}

#[test]
fn cose_sign1_error_source_some_for_key_and_payload() {
    let key_err = CoseSign1Error::KeyError(CoseKeyError::IoError("k".into()));
    assert!(key_err.source().is_some());

    let pay_err = CoseSign1Error::PayloadError(PayloadError::OpenFailed("p".into()));
    assert!(pay_err.source().is_some());
}

#[test]
fn cose_sign1_error_source_none_for_other_variants() {
    assert!(CoseSign1Error::CborError("x".into()).source().is_none());
    assert!(CoseSign1Error::InvalidMessage("x".into())
        .source()
        .is_none());
    assert!(CoseSign1Error::PayloadMissing.source().is_none());
    assert!(CoseSign1Error::SignatureMismatch.source().is_none());
    assert!(CoseSign1Error::IoError("x".into()).source().is_none());
    assert!(CoseSign1Error::PayloadTooLargeForEmbedding(1, 2)
        .source()
        .is_none());
}

#[test]
fn cose_sign1_error_from_cose_key_error() {
    let inner = CoseKeyError::CborError("cbor".into());
    let err: CoseSign1Error = inner.into();
    assert!(matches!(err, CoseSign1Error::KeyError(_)));
}

#[test]
fn cose_sign1_error_from_payload_error() {
    let inner = PayloadError::ReadFailed("read".into());
    let err: CoseSign1Error = inner.into();
    assert!(matches!(err, CoseSign1Error::PayloadError(_)));
}

#[test]
fn cose_sign1_error_from_cose_error() {
    let cbor: CoseSign1Error = CoseError::CborError("c".into()).into();
    assert!(matches!(cbor, CoseSign1Error::CborError(_)));

    let inv: CoseSign1Error = CoseError::InvalidMessage("m".into()).into();
    assert!(matches!(inv, CoseSign1Error::InvalidMessage(_)));
}

#[test]
fn cose_key_error_display_all_variants() {
    let crypto = CoseKeyError::Crypto(CryptoError::SigningFailed("sf".into()));
    assert!(crypto.to_string().contains("sf"));
    assert_eq!(
        CoseKeyError::SigStructureFailed("s".into()).to_string(),
        "sig_structure failed: s"
    );
    assert_eq!(
        CoseKeyError::IoError("io".into()).to_string(),
        "I/O error: io"
    );
    assert_eq!(
        CoseKeyError::CborError("cb".into()).to_string(),
        "CBOR error: cb"
    );
}

#[test]
fn payload_error_display_all_variants() {
    assert_eq!(
        PayloadError::OpenFailed("o".into()).to_string(),
        "failed to open payload: o"
    );
    assert_eq!(
        PayloadError::ReadFailed("r".into()).to_string(),
        "failed to read payload: r"
    );
    assert_eq!(
        PayloadError::LengthMismatch {
            expected: 10,
            actual: 5
        }
        .to_string(),
        "payload length mismatch: expected 10 bytes, got 5"
    );
}

#[test]
fn parse_empty_bytes_is_error() {
    assert!(CoseSign1Message::parse(&[]).is_err());
}

#[test]
fn parse_random_garbage_is_error() {
    assert!(CoseSign1Message::parse(&[0xFF, 0xFE, 0x01, 0x02]).is_err());
}

#[test]
fn parse_too_short_data_is_error() {
    assert!(CoseSign1Message::parse(&[0x84]).is_err());
}

#[test]
fn build_sig_structure_empty_protected_and_payload() {
    let result = build_sig_structure(&[], None, &[]);
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert!(!bytes.is_empty());
    assert_eq!(bytes[0], 0x84); // CBOR array(4)
}

#[test]
fn build_sig_structure_with_external_aad() {
    let without_aad = build_sig_structure(b"\xa1\x01\x26", None, b"data").unwrap();
    let with_aad = build_sig_structure(b"\xa1\x01\x26", Some(b"aad".as_slice()), b"data").unwrap();
    assert_ne!(without_aad, with_aad);
}

#[test]
fn build_sig_structure_prefix_various_lengths() {
    for len in [0u64, 1, 255, 65536, 100_000] {
        let result = build_sig_structure_prefix(b"\xa1\x01\x26", None, len);
        assert!(result.is_ok(), "failed for payload_len={}", len);
    }
}

#[test]
fn file_payload_nonexistent_path_is_open_failed() {
    let result = FilePayload::new("/this/path/does/not/exist/at/all.bin");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, PayloadError::OpenFailed(_)));
}

#[test]
fn constants_have_expected_values() {
    assert_eq!(COSE_SIGN1_TAG, 18);
    assert_eq!(LARGE_PAYLOAD_THRESHOLD, 85_000);
    assert_eq!(MAX_EMBED_PAYLOAD_SIZE, 2 * 1024 * 1024 * 1024);
    assert_eq!(DEFAULT_CHUNK_SIZE, 64 * 1024);
    assert_eq!(SIG_STRUCTURE_CONTEXT, "Signature1");
}
