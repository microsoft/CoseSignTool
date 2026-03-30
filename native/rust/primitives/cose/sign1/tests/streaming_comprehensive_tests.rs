// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for streaming parse/verify methods in CoseSign1Message.
//! Covers parse_stream, verify_payload_streaming, verify_streamed,
//! payload_reader, and is_streamed.

use std::io::{Cursor, Read};
use std::sync::Arc;

use cose_sign1_primitives::sig_structure::{build_sig_structure, SizedReader};
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Builder, CoseSign1Message};
use crypto_primitives::{
    CryptoError, CryptoSigner, CryptoVerifier, SigningContext, VerifyingContext,
};

// ============================================================================
// Mock crypto types for testing
// ============================================================================

/// Mock signer: signature = HMAC-like (just XOR data with a key byte).
struct TestSigner {
    key_byte: u8,
}

impl TestSigner {
    fn new(key_byte: u8) -> Self {
        Self { key_byte }
    }
}

impl CryptoSigner for TestSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Simple "signature": XOR each byte with key
        Ok(data.iter().map(|b| b ^ self.key_byte).collect())
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_type(&self) -> &str {
        "Test"
    }

    fn supports_streaming(&self) -> bool {
        true
    }

    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Ok(Box::new(TestSigningContext {
            key_byte: self.key_byte,
            buffer: Vec::new(),
        }))
    }
}

struct TestSigningContext {
    key_byte: u8,
    buffer: Vec<u8>,
}

impl SigningContext for TestSigningContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        Ok(self.buffer.iter().map(|b| b ^ self.key_byte).collect())
    }
}

/// Mock verifier matching TestSigner.
struct TestVerifier {
    key_byte: u8,
    streaming: bool,
}

impl TestVerifier {
    fn new(key_byte: u8) -> Self {
        Self {
            key_byte,
            streaming: true,
        }
    }

    fn non_streaming(key_byte: u8) -> Self {
        Self {
            key_byte,
            streaming: false,
        }
    }
}

impl CryptoVerifier for TestVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        let expected: Vec<u8> = data.iter().map(|b| b ^ self.key_byte).collect();
        Ok(signature == expected.as_slice())
    }

    fn algorithm(&self) -> i64 {
        -7
    }

    fn supports_streaming(&self) -> bool {
        self.streaming
    }

    fn verify_init(&self, signature: &[u8]) -> Result<Box<dyn VerifyingContext>, CryptoError> {
        if !self.streaming {
            return Err(CryptoError::UnsupportedOperation("not streaming".into()));
        }
        Ok(Box::new(TestVerifyingContext {
            key_byte: self.key_byte,
            buffer: Vec::new(),
            expected_signature: signature.to_vec(),
        }))
    }
}

struct TestVerifyingContext {
    key_byte: u8,
    buffer: Vec<u8>,
    expected_signature: Vec<u8>,
}

impl VerifyingContext for TestVerifyingContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.buffer.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        let expected: Vec<u8> = self.buffer.iter().map(|b| b ^ self.key_byte).collect();
        Ok(self.expected_signature == expected)
    }
}

// ============================================================================
// Helper: build a signed message
// ============================================================================

fn build_signed_message(payload: &[u8], key_byte: u8) -> Vec<u8> {
    let signer = TestSigner::new(key_byte);
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    CoseSign1Builder::new()
        .protected(protected)
        .sign(&signer, payload)
        .expect("sign should succeed")
}

// ============================================================================
// parse_stream tests
// ============================================================================

#[test]
fn parse_stream_basic() {
    let payload = b"stream parse test payload";
    let msg_bytes = build_signed_message(payload, 0x42);
    let cursor = Cursor::new(msg_bytes.clone());

    let streamed = CoseSign1Message::parse_stream(cursor).expect("parse_stream should succeed");
    assert!(streamed.is_streamed());

    // Compare headers with buffered parse
    let buffered = CoseSign1Message::parse(&msg_bytes).expect("parse should succeed");
    assert!(!buffered.is_streamed());
    assert_eq!(streamed.alg(), buffered.alg());
}

#[test]
fn parse_stream_preserves_protected_headers() {
    let payload = b"header test";
    let msg_bytes = build_signed_message(payload, 0x55);
    let cursor = Cursor::new(msg_bytes);

    let msg = CoseSign1Message::parse_stream(cursor).expect("parse_stream should succeed");
    assert_eq!(msg.alg(), Some(-7));
}

#[test]
fn parse_stream_signature_matches_buffered() {
    let payload = b"signature check";
    let msg_bytes = build_signed_message(payload, 0x33);

    let buffered = CoseSign1Message::parse(&msg_bytes).unwrap();
    let streamed = CoseSign1Message::parse_stream(Cursor::new(msg_bytes)).unwrap();

    assert_eq!(buffered.signature(), streamed.signature());
}

// ============================================================================
// is_streamed tests
// ============================================================================

#[test]
fn is_streamed_true_for_stream_parsed() {
    let msg_bytes = build_signed_message(b"test", 0x11);
    let msg = CoseSign1Message::parse_stream(Cursor::new(msg_bytes)).unwrap();
    assert!(msg.is_streamed());
}

#[test]
fn is_streamed_false_for_buffered() {
    let msg_bytes = build_signed_message(b"test", 0x11);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(!msg.is_streamed());
}

// ============================================================================
// payload_reader tests
// ============================================================================

#[test]
fn payload_reader_buffered_returns_payload() {
    let payload = b"readable payload";
    let msg_bytes = build_signed_message(payload, 0x22);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();

    let mut reader = msg
        .payload_reader()
        .expect("payload_reader should return Some");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, payload);
}

#[test]
fn payload_reader_streamed_returns_payload() {
    let payload = b"streamed payload data";
    let msg_bytes = build_signed_message(payload, 0x44);
    let msg = CoseSign1Message::parse_stream(Cursor::new(msg_bytes)).unwrap();

    let mut reader = msg
        .payload_reader()
        .expect("payload_reader should return Some");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, payload);
}

// ============================================================================
// verify_payload_streaming tests
// ============================================================================

#[test]
fn verify_payload_streaming_with_streaming_verifier() {
    let payload = b"verify streaming test";
    let key_byte = 0x77;
    let msg_bytes = build_signed_message(payload, key_byte);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();

    let verifier = TestVerifier::new(key_byte);
    let mut cursor = Cursor::new(payload.to_vec());
    let valid = msg
        .verify_payload_streaming(&verifier, &mut cursor, payload.len() as u64, None)
        .expect("verify should succeed");
    assert!(valid);
}

#[test]
fn verify_payload_streaming_with_non_streaming_verifier() {
    let payload = b"non-streaming verify";
    let key_byte = 0x88;
    let msg_bytes = build_signed_message(payload, key_byte);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();

    let verifier = TestVerifier::non_streaming(key_byte);
    let mut cursor = Cursor::new(payload.to_vec());
    let valid = msg
        .verify_payload_streaming(&verifier, &mut cursor, payload.len() as u64, None)
        .expect("verify should succeed");
    assert!(valid);
}

#[test]
fn verify_payload_streaming_wrong_key_fails() {
    let payload = b"wrong key test";
    let msg_bytes = build_signed_message(payload, 0xAA);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();

    let verifier = TestVerifier::new(0xBB); // wrong key
    let mut cursor = Cursor::new(payload.to_vec());
    let valid = msg
        .verify_payload_streaming(&verifier, &mut cursor, payload.len() as u64, None)
        .expect("verify should succeed (but return false)");
    assert!(!valid);
}

// ============================================================================
// verify_streamed tests
// ============================================================================

// NOTE: verify_streamed with stream-parsed messages requires a payload-bounded
// reader, which our mock setup doesn't provide correctly. The existing
// stream_parse_tests.rs and message_advanced_coverage.rs cover these paths.

#[test]
fn verify_streamed_buffered_message_delegates_to_verify() {
    let payload = b"buffered verify";
    let key_byte = 0xEE;
    let msg_bytes = build_signed_message(payload, key_byte);
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();

    let verifier = TestVerifier::new(key_byte);
    let valid = msg
        .verify_streamed(&verifier, None)
        .expect("should succeed");
    assert!(valid);
}

// ============================================================================
// Edge cases
// ============================================================================

#[test]
fn parse_stream_empty_payload() {
    let payload = b"";
    let msg_bytes = build_signed_message(payload, 0x11);

    // Buffered should have payload
    let buffered = CoseSign1Message::parse(&msg_bytes).unwrap();
    let p = buffered.payload();
    assert!(p.is_some());
    assert!(p.unwrap().is_empty());

    // Streamed with empty payload
    let streamed = CoseSign1Message::parse_stream(Cursor::new(msg_bytes)).unwrap();
    // For streamed with 0-length payload, payload_reader may return None
    // depending on implementation
    assert!(streamed.is_streamed());
}

#[test]
fn verify_detached_streaming_with_sized_reader() {
    let payload = b"detached streaming verify";
    let key_byte = 0x55;

    // Build message without embedded payload (detached)
    let signer = TestSigner::new(key_byte);
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&signer, payload)
        .expect("sign should succeed");

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(msg.payload().is_none());

    let verifier = TestVerifier::new(key_byte);
    let mut sized = SizedReader::new(Cursor::new(payload.to_vec()), payload.len() as u64);
    let valid = msg
        .verify_detached_streaming(&verifier, &mut sized, None)
        .expect("should succeed");
    assert!(valid);
}
