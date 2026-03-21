// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_primitives to reach 90%.
//!
//! Focuses on:
//! - verify_streamed for buffered messages
//! - verify_payload_streaming fallback for non-streaming verifiers
//! - payload_reader for streamed messages
//! - parse_stream round-trip
//! - verify_detached_read
//! - error Display paths

use std::io::{Cursor, Read};

use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::error::{CoseKeyError, PayloadError};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::sig_structure::{
    sized_from_bytes, sized_from_read_buffered, sized_from_reader, SizedRead,
};
use cose_sign1_primitives::CoseSign1Error;
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier, VerifyingContext};

// ============================================================================
// Helpers
// ============================================================================

/// Mock signer that produces a deterministic signature.
struct MockSigner;

impl CryptoSigner for MockSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0xAA; 32])
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
}

/// Mock verifier that accepts our deterministic signature.
struct MockVerifier;

impl CryptoVerifier for MockVerifier {
    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(signature == vec![0xAA; 32].as_slice())
    }
    fn algorithm(&self) -> i64 {
        -7
    }
}

/// A mock verifier that does NOT support streaming, to exercise fallback paths.
struct NonStreamingVerifier;

impl CryptoVerifier for NonStreamingVerifier {
    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(signature == vec![0xAA; 32].as_slice())
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn supports_streaming(&self) -> bool {
        false
    }
    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        Err(CryptoError::UnsupportedOperation("not supported".into()))
    }
}

/// Build a CoseSign1 message with embedded payload.
fn build_test_message(payload: &[u8]) -> Vec<u8> {
    CoseSign1Builder::new().sign(&MockSigner, payload).unwrap()
}

/// Build a detached CoseSign1 message.
fn build_detached_message(payload: &[u8]) -> Vec<u8> {
    CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, payload)
        .unwrap()
}

// ============================================================================
// verify_streamed on buffered message
// ============================================================================

#[test]
fn verify_streamed_buffered_with_payload() {
    let payload = b"hello streamed verify";
    let encoded = build_test_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();

    let verifier = MockVerifier;
    let result = msg.verify_streamed(&verifier, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn verify_streamed_buffered_detached_errors() {
    let payload = b"detached payload";
    let encoded = build_detached_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();

    let verifier = MockVerifier;
    let result = msg.verify_streamed(&verifier, None);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadMissing => {}
        other => panic!("expected PayloadMissing, got: {:?}", other),
    }
}

// ============================================================================
// verify_payload_streaming with non-streaming verifier (fallback path)
// ============================================================================

#[test]
fn verify_payload_streaming_fallback() {
    let payload = b"fallback verify test";
    let encoded = build_test_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();

    let non_streaming = NonStreamingVerifier;

    let mut cursor = Cursor::new(payload.to_vec());
    let result =
        msg.verify_payload_streaming(&non_streaming, &mut cursor, payload.len() as u64, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ============================================================================
// verify_detached_read
// ============================================================================

#[test]
fn verify_detached_read() {
    let payload = b"detached read verify test";
    let encoded = build_detached_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();

    let verifier = MockVerifier;
    let mut reader = Cursor::new(payload.to_vec());
    let result = msg.verify_detached_read(&verifier, &mut reader, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

// ============================================================================
// parse_stream and verify_streamed on streamed message
// ============================================================================

#[test]
fn parse_stream_and_verify() {
    let payload = b"stream parsed verify test payload";
    let encoded = build_test_message(payload);

    // Parse from a stream
    let cursor = Cursor::new(encoded.clone());
    let msg = CoseSign1Message::parse_stream(cursor).unwrap();

    assert!(msg.is_streamed());

    // payload() should return None for streamed messages
    assert!(msg.payload().is_none());

    // payload_reader() should work
    let mut reader = msg.payload_reader().unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, payload);

    // verify_streamed should work
    let verifier = MockVerifier;
    let valid = msg.verify_streamed(&verifier, None).unwrap();
    assert!(valid);
}

#[test]
fn parse_stream_detached_payload() {
    let payload = b"detached";
    let encoded = build_detached_message(payload);

    let cursor = Cursor::new(encoded.clone());
    let msg = CoseSign1Message::parse_stream(cursor).unwrap();

    assert!(msg.is_streamed());
    // For detached streamed messages, payload_reader returns None
    assert!(msg.payload_reader().is_none());

    // verify_streamed should fail with PayloadMissing
    let verifier = MockVerifier;
    let result = msg.verify_streamed(&verifier, None);
    assert!(result.is_err());
}

// ============================================================================
// payload_reader for buffered detached
// ============================================================================

#[test]
fn payload_reader_buffered_detached() {
    let payload = b"detached";
    let encoded = build_detached_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();
    assert!(msg.payload_reader().is_none());
}

#[test]
fn payload_reader_buffered_embedded() {
    let payload = b"embedded payload data";
    let encoded = build_test_message(payload);
    let msg = CoseSign1Message::parse(&encoded).unwrap();

    let mut reader = msg.payload_reader().unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, payload);
}

// ============================================================================
// Error Display coverage
// ============================================================================

#[test]
fn cose_sign1_error_display_all_variants() {
    let err = CoseSign1Error::CborError("bad cbor".into());
    assert!(format!("{}", err).contains("CBOR error"));

    let err = CoseSign1Error::InvalidMessage("bad msg".into());
    assert!(format!("{}", err).contains("invalid message"));

    let err = CoseSign1Error::PayloadMissing;
    assert!(format!("{}", err).contains("payload is detached"));

    let err = CoseSign1Error::SignatureMismatch;
    assert!(format!("{}", err).contains("signature verification failed"));

    let err = CoseSign1Error::PayloadTooLargeForEmbedding(1000, 500);
    let msg = format!("{}", err);
    assert!(msg.contains("1000"));
    assert!(msg.contains("500"));

    let err = CoseSign1Error::IoError("disk error".into());
    assert!(format!("{}", err).contains("I/O error"));
}

#[test]
fn cose_sign1_error_source() {
    let key_err = CoseSign1Error::KeyError(CoseKeyError::SigStructureFailed("test".into()));
    let source = std::error::Error::source(&key_err);
    assert!(source.is_some());

    let payload_err = CoseSign1Error::PayloadError(PayloadError::OpenFailed("test".into()));
    let source = std::error::Error::source(&payload_err);
    assert!(source.is_some());

    let cbor_err = CoseSign1Error::CborError("test".into());
    let source = std::error::Error::source(&cbor_err);
    assert!(source.is_none());
}

#[test]
fn cose_key_error_display() {
    let err = CoseKeyError::SigStructureFailed("bad sig".into());
    assert!(format!("{}", err).contains("sig_structure failed"));

    let err = CoseKeyError::IoError("io err".into());
    assert!(format!("{}", err).contains("I/O error"));

    let err = CoseKeyError::CborError("cbor err".into());
    assert!(format!("{}", err).contains("CBOR error"));

    let err = CoseKeyError::Crypto(CryptoError::SigningFailed("sign fail".into()));
    assert!(format!("{}", err).contains("sign fail"));
}

#[test]
fn payload_error_display() {
    let err = PayloadError::OpenFailed("not found".into());
    assert!(format!("{}", err).contains("open payload"));

    let err = PayloadError::ReadFailed("read err".into());
    assert!(format!("{}", err).contains("read payload"));

    let err = PayloadError::LengthMismatch {
        expected: 100,
        actual: 50,
    };
    let msg = format!("{}", err);
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

#[test]
fn cose_sign1_error_from_cose_error() {
    use cose_primitives::CoseError;

    let e1: CoseSign1Error = CoseError::CborError("test".into()).into();
    assert!(matches!(e1, CoseSign1Error::CborError(_)));

    let e2: CoseSign1Error = CoseError::InvalidMessage("test".into()).into();
    assert!(matches!(e2, CoseSign1Error::InvalidMessage(_)));

    let e3: CoseSign1Error = CoseError::IoError("test".into()).into();
    assert!(matches!(e3, CoseSign1Error::IoError(_)));
}

// ============================================================================
// SizedRead helpers
// ============================================================================

#[test]
fn sized_from_bytes_works() {
    let data = b"hello";
    let sized = sized_from_bytes(data);
    let len = sized.len().unwrap();
    assert_eq!(len, 5);
}

#[test]
fn sized_from_reader_works() {
    let data = b"hello sized reader";
    let cursor = Cursor::new(data.to_vec());
    let sized = sized_from_reader(cursor, data.len() as u64);
    let len = sized.len().unwrap();
    assert_eq!(len, data.len() as u64);
}

#[test]
fn sized_from_read_buffered_works() {
    let data = b"buffered reader test";
    let cursor = Cursor::new(data.to_vec());
    let sized = sized_from_read_buffered(cursor).unwrap();
    let len = sized.len().unwrap();
    assert_eq!(len, data.len() as u64);
}
