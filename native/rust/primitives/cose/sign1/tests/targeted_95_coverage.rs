// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_primitives gaps.
//!
//! Targets: builder.rs (streaming sign, detached, untagged, max embed),
//!          message.rs (verify_detached_streaming, verify_detached_read, encode, parse edge cases),
//!          sig_structure.rs (streaming sig structure, SizedReader),
//!          payload.rs (StreamingPayload trait).

use std::io::Cursor;
use std::sync::Arc;

use cbor_primitives::CborEncoder;
use cose_sign1_primitives::error::CoseSign1Error;
use cose_sign1_primitives::sig_structure::SizedReader;
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Builder, CoseSign1Message};
use crypto_primitives::CryptoSigner;

/// Mock signer that produces a deterministic signature.
struct MockSigner;

impl CryptoSigner for MockSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        // Return a hash-like deterministic signature
        Ok(vec![0xAA; 64])
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_id(&self) -> Option<&[u8]> {
        None
    }

    fn key_type(&self) -> &str {
        "EC"
    }
}

/// Mock verifier that always succeeds.
struct MockVerifier;

impl crypto_primitives::CryptoVerifier for MockVerifier {
    fn verify(
        &self,
        _data: &[u8],
        _signature: &[u8],
    ) -> Result<bool, crypto_primitives::CryptoError> {
        Ok(true)
    }

    fn algorithm(&self) -> i64 {
        -7
    }
}

// ============================================================================
// builder.rs — sign with embedded payload (untagged)
// ============================================================================

#[test]
fn builder_sign_untagged() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .tagged(false)
        .sign(&MockSigner, b"hello")
        .unwrap();

    // Untagged messages should parse correctly
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert_eq!(msg.payload(), Some(b"hello".as_slice()));
}

// ============================================================================
// builder.rs — sign with detached payload
// ============================================================================

#[test]
fn builder_sign_detached() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&MockSigner, b"detached-payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(msg.is_detached());
    assert!(msg.payload().is_none());
}

// ============================================================================
// builder.rs — sign with unprotected headers
// ============================================================================

#[test]
fn builder_sign_with_unprotected_headers() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test-kid");

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .sign(&MockSigner, b"payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(msg.unprotected_headers().kid().is_some());
}

// ============================================================================
// builder.rs — sign with external AAD
// ============================================================================

#[test]
fn builder_sign_with_external_aad() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"extra-data".to_vec())
        .sign(&MockSigner, b"payload")
        .unwrap();

    // Should produce a valid message
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(msg.payload().is_some());
}

// ============================================================================
// message.rs — verify with embedded payload
// ============================================================================

#[test]
fn message_verify_embedded() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"test-payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let result = msg.verify(&MockVerifier, None).unwrap();
    assert!(result);
}

// ============================================================================
// message.rs — verify_detached
// ============================================================================

#[test]
fn message_verify_detached() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&MockSigner, b"detached")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let result = msg
        .verify_detached(&MockVerifier, b"detached", None)
        .unwrap();
    assert!(result);
}

// ============================================================================
// message.rs — verify_detached_streaming with SizedReader
// ============================================================================

#[test]
fn message_verify_detached_streaming() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&MockSigner, b"streaming-payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let data = b"streaming-payload";
    let cursor = Cursor::new(data.to_vec());
    let mut reader = SizedReader::new(Box::new(cursor), data.len() as u64);
    let result = msg
        .verify_detached_streaming(&MockVerifier, &mut reader, None)
        .unwrap();
    assert!(result);
}

// ============================================================================
// message.rs — verify_detached_read
// ============================================================================

#[test]
fn message_verify_detached_read() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&MockSigner, b"read-payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let data = b"read-payload";
    let mut cursor = Cursor::new(data.to_vec());
    let result = msg
        .verify_detached_read(&MockVerifier, &mut cursor, None)
        .unwrap();
    assert!(result);
}

// ============================================================================
// message.rs — encode roundtrip (tagged and untagged)
// ============================================================================

#[test]
fn message_encode_tagged_roundtrip() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"encode-test")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let re_encoded = msg.encode(true).unwrap();
    let re_parsed = CoseSign1Message::parse(&re_encoded).unwrap();
    assert_eq!(re_parsed.payload(), msg.payload());
}

#[test]
fn message_encode_untagged_roundtrip() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .tagged(false)
        .sign(&MockSigner, b"untagged-encode")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let re_encoded = msg.encode(false).unwrap();
    let re_parsed = CoseSign1Message::parse(&re_encoded).unwrap();
    assert_eq!(re_parsed.payload(), msg.payload());
}

// ============================================================================
// message.rs — parse with wrong COSE tag
// ============================================================================

#[test]
fn parse_wrong_cose_tag_returns_error() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    // Tag 99 instead of 18
    enc.encode_tag(99).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(b"signature").unwrap();
    let bytes = enc.into_bytes();

    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
}

// ============================================================================
// message.rs — parse indefinite-length array returns error
// ============================================================================

#[test]
fn parse_wrong_element_count_returns_error() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    // Array of 3 instead of 4
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    let bytes = enc.into_bytes();

    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
}

// ============================================================================
// message.rs — sig_structure_bytes
// ============================================================================

#[test]
fn message_sig_structure_bytes() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"test")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let sig_bytes = msg.sig_structure_bytes(b"test", None).unwrap();
    assert!(!sig_bytes.is_empty());
}

// ============================================================================
// message.rs — verify on detached message returns PayloadMissing
// ============================================================================

#[test]
fn verify_embedded_on_detached_returns_error() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&MockSigner, b"detached")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let result = msg.verify(&MockVerifier, None);
    assert!(matches!(result, Err(CoseSign1Error::PayloadMissing)));
}

// ============================================================================
// message.rs — Debug impl
// ============================================================================

#[test]
fn message_debug_impl() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"debug-test")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
}

// ============================================================================
// builder.rs — sign with empty protected headers
// ============================================================================

#[test]
fn builder_sign_empty_protected() {
    let msg_bytes = CoseSign1Builder::new()
        .sign(&MockSigner, b"no-protected")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert!(msg.protected_headers().is_empty());
}

// ============================================================================
// message.rs — provider() accessor
// ============================================================================

#[test]
fn message_provider_accessor() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"test")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    // Just verify the provider is accessible (returns a reference)
    let _provider = msg.provider();
}

// ============================================================================
// message.rs — helper accessors
// ============================================================================

#[test]
fn message_accessors() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg_bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"test")
        .unwrap();

    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    assert_eq!(msg.alg(), Some(-7));
    assert!(!msg.protected_header_bytes().is_empty());
    assert!(!msg.is_detached());
    let _ = msg.protected_headers();
}
