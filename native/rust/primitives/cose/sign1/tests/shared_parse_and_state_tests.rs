// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for parse_from_shared, parse_from_arc_slice, MessageState,
//! is_dirty, encode fast-path/dirty-path, encode_and_persist, and
//! sign_to_message.

use std::sync::Arc;

use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_primitives::message::{CoseSign1Message, MessageState};
use cose_sign1_primitives::ArcSlice;
use crypto_primitives::{CryptoError, CryptoSigner};

// ---------------------------------------------------------------------------
// Deterministic test signer
// ---------------------------------------------------------------------------

struct TestSigner;

impl CryptoSigner for TestSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Produce a deterministic 32-byte signature (COSE ES256 size)
        let mut sig = vec![0u8; 64];
        for (i, b) in data.iter().enumerate() {
            sig[i % 64] ^= b;
        }
        Ok(sig)
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_type(&self) -> &str {
        "test"
    }
}

/// Helper: build a signed COSE_Sign1 message (tagged).
fn build_signed_bytes(payload: &[u8]) -> Vec<u8> {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .sign(&TestSigner, payload)
        .expect("sign should succeed")
}

// ---------------------------------------------------------------------------
// parse_from_shared — zero-copy sub-message parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_from_shared_parses_sub_range() {
    let payload = b"shared parsing test";
    let msg_bytes = build_signed_bytes(payload);

    // Embed the message bytes inside a larger buffer (prefix + message + suffix)
    let prefix = b"PREFIX_GARBAGE_";
    let suffix = b"_SUFFIX_GARBAGE";
    let mut full_buf = Vec::new();
    full_buf.extend_from_slice(prefix);
    full_buf.extend_from_slice(&msg_bytes);
    full_buf.extend_from_slice(suffix);

    let arc: Arc<[u8]> = Arc::from(full_buf);
    let range = prefix.len()..prefix.len() + msg_bytes.len();

    let msg = CoseSign1Message::parse_from_shared(arc.clone(), range)
        .expect("parse_from_shared should succeed");

    // Verify it parsed correctly
    assert_eq!(msg.state(), &MessageState::Signed);
    assert!(!msg.is_dirty());

    let parsed_payload = msg.payload().expect("payload should be present");
    assert_eq!(parsed_payload, payload);
}

#[test]
fn parse_from_shared_shares_same_arc() {
    let msg_bytes = build_signed_bytes(b"arc sharing");
    let arc: Arc<[u8]> = Arc::from(msg_bytes.clone());
    let len = arc.len();

    let msg =
        CoseSign1Message::parse_from_shared(arc.clone(), 0..len).expect("parse should succeed");

    // The internal data should share the same Arc allocation
    let internal_bytes = msg.as_bytes();
    assert_eq!(internal_bytes, &msg_bytes[..]);
}

// ---------------------------------------------------------------------------
// parse_from_arc_slice — convenience wrapper
// ---------------------------------------------------------------------------

#[test]
fn parse_from_arc_slice_convenience_wrapper() {
    let payload = b"arc_slice convenience";
    let msg_bytes = build_signed_bytes(payload);

    let arc: Arc<[u8]> = Arc::from(msg_bytes.clone());
    let len = arc.len();
    let arc_slice = ArcSlice::new(arc, 0..len);

    let msg = CoseSign1Message::parse_from_arc_slice(&arc_slice)
        .expect("parse_from_arc_slice should succeed");

    assert_eq!(msg.state(), &MessageState::Signed);
    let parsed_payload = msg.payload().expect("payload should be present");
    assert_eq!(parsed_payload, payload);
}

// ---------------------------------------------------------------------------
// MessageState — parsed vs builder
// ---------------------------------------------------------------------------

#[test]
fn parsed_message_is_signed_state() {
    let bytes = build_signed_bytes(b"state check");
    let msg = CoseSign1Message::parse(&bytes).expect("parse should succeed");
    assert_eq!(msg.state(), &MessageState::Signed);
}

#[test]
fn sign_to_message_produces_signed_state() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let msg = CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .sign_to_message(&TestSigner, b"builder state test")
        .expect("sign_to_message should succeed");

    assert_eq!(msg.state(), &MessageState::Signed);
    assert!(!msg.is_dirty());

    let payload = msg.payload().expect("payload should be present");
    assert_eq!(payload, b"builder state test");
}

// ---------------------------------------------------------------------------
// is_dirty — false after parse, true after set_unprotected_header
// ---------------------------------------------------------------------------

#[test]
fn is_dirty_false_after_parse() {
    let bytes = build_signed_bytes(b"dirty check");
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(!msg.is_dirty());
}

#[test]
fn is_dirty_true_after_set_unprotected_header() {
    let bytes = build_signed_bytes(b"dirty check 2");
    let mut msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(!msg.is_dirty());

    msg.set_unprotected_header(
        CoseHeaderLabel::Int(99),
        CoseHeaderValue::Text("added".into()),
    );
    assert!(msg.is_dirty());
}

// ---------------------------------------------------------------------------
// encode — fast-path (clean, same bytes)
// ---------------------------------------------------------------------------

#[test]
fn encode_fast_path_returns_same_bytes() {
    let original = build_signed_bytes(b"fast path");
    let msg = CoseSign1Message::parse(&original).unwrap();

    // Not dirty, tagged matches → fast path
    let encoded = msg.encode(true).expect("encode should succeed");
    assert_eq!(
        encoded, original,
        "fast-path encode should return identical bytes"
    );
}

#[test]
fn encode_fast_path_different_tag_triggers_reserialize() {
    let original_tagged = build_signed_bytes(b"tag mismatch");
    let msg = CoseSign1Message::parse(&original_tagged).unwrap();

    // Original is tagged(true). Requesting untagged forces re-serialization.
    let encoded_untagged = msg.encode(false).expect("encode should succeed");
    assert_ne!(
        encoded_untagged, original_tagged,
        "different tag should produce different bytes"
    );
    // Untagged should not start with 0xD2 (CBOR tag 18)
    assert_ne!(encoded_untagged.first(), Some(&0xD2));
}

// ---------------------------------------------------------------------------
// encode — dirty path (modified unprotected header, new bytes)
// ---------------------------------------------------------------------------

#[test]
fn encode_dirty_path_produces_new_bytes() {
    let original = build_signed_bytes(b"dirty encode");
    let mut msg = CoseSign1Message::parse(&original).unwrap();

    msg.set_unprotected_header(CoseHeaderLabel::Int(42), CoseHeaderValue::Int(12345));
    assert!(msg.is_dirty());

    let encoded = msg.encode(true).expect("dirty encode should succeed");
    assert_ne!(
        encoded, original,
        "dirty encode should produce different bytes"
    );

    // Re-parse and verify the new header is present
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    let val = reparsed
        .unprotected
        .get(&CoseHeaderLabel::Int(42))
        .expect("added header should be present");
    assert_eq!(*val, CoseHeaderValue::Int(12345));
}

// ---------------------------------------------------------------------------
// encode_and_persist — clears dirty flag
// ---------------------------------------------------------------------------

#[test]
fn encode_and_persist_clears_dirty_flag() {
    let original = build_signed_bytes(b"persist test");
    let mut msg = CoseSign1Message::parse(&original).unwrap();

    msg.set_unprotected_header(
        CoseHeaderLabel::Int(50),
        CoseHeaderValue::Text("persist-val".into()),
    );
    assert!(msg.is_dirty());

    let persisted = msg
        .encode_and_persist(true)
        .expect("persist should succeed");
    assert!(
        !msg.is_dirty(),
        "dirty flag should be cleared after persist"
    );

    // Subsequent encode should use fast path and return same bytes
    let encoded_again = msg.encode(true).unwrap();
    assert_eq!(encoded_again, persisted);
}

#[test]
fn encode_and_persist_fast_path_when_clean() {
    let original = build_signed_bytes(b"clean persist");
    let mut msg = CoseSign1Message::parse(&original).unwrap();
    assert!(!msg.is_dirty());

    let persisted = msg
        .encode_and_persist(true)
        .expect("persist should succeed");
    assert_eq!(
        persisted, original,
        "clean persist should return same bytes"
    );
}
