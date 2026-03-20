// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoseSign1Message parsing and operations.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;
use cose_sign1_primitives::error::CoseSign1Error;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::MemoryPayload;
use cose_sign1_primitives::StreamingPayload;
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier};
use std::sync::Arc;

#[test]
fn test_message_parse_minimal() {
    let provider = EverParseCborProvider;

    // Minimal COSE_Sign1: [h'', {}, null, h'']
    // Array of 4 elements
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0) - empty protected header
        0xa0, // map(0) - empty unprotected header
        0xf6, // null - no payload
        0x40, // bstr(0) - empty signature
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(msg.protected_headers().is_empty());
    assert!(msg.unprotected_headers().is_empty());
    assert!(msg.payload().is_none());
    assert_eq!(msg.signature().len(), 0);
    assert!(msg.is_detached());
}

#[test]
fn test_message_parse_with_protected_header() {
    let provider = EverParseCborProvider;

    // Protected header: {1: -7}
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    // COSE_Sign1: [h'a10126', {}, null, h'']
    let mut data = vec![
        0x84, // Array(4)
        0x43, // bstr(3)
    ];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[
        0xa0, // map(0) - empty unprotected
        0xf6, // null
        0x40, // bstr(0)
    ]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.protected_header_bytes(), &protected_map[..]);
}

#[test]
fn test_message_parse_with_unprotected_header() {
    let provider = EverParseCborProvider;

    // COSE_Sign1 with unprotected header {4: h'keyid'}
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0) - empty protected
        0xa1, 0x04, 0x45, 0x6b, 0x65, 0x79, 0x69, 0x64, // map {4: "keyid"}
        0xf6, // null payload
        0x40, // bstr(0) signature
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.unprotected_headers().kid(), Some(b"keyid".as_slice()));
}

#[test]
fn test_message_parse_with_embedded_payload() {
    let provider = EverParseCborProvider;

    let payload = b"test payload";

    // COSE_Sign1: [h'', {}, h'test payload', h'']
    let mut data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa0, // map(0)
        0x4c, // bstr(12)
    ];
    data.extend_from_slice(payload);
    data.push(0x40); // bstr(0) signature

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.payload(), Some(payload.as_slice()));
    assert!(!msg.is_detached());
}

#[test]
fn test_message_parse_with_signature() {
    let provider = EverParseCborProvider;

    let signature = vec![0xaa, 0xbb, 0xcc, 0xdd];

    // COSE_Sign1: [h'', {}, null, h'aabbccdd']
    let mut data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa0, // map(0)
        0xf6, // null
        0x44, // bstr(4)
    ];
    data.extend_from_slice(&signature);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.signature(), signature);
}

#[test]
fn test_message_parse_with_tag() {
    let provider = EverParseCborProvider;

    // Tagged COSE_Sign1: 18([h'', {}, null, h''])
    let data = vec![
        0xd2, // tag(18)
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa0, // map(0)
        0xf6, // null
        0x40, // bstr(0)
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(msg.protected_headers().is_empty());
}

#[test]
fn test_message_parse_wrong_tag_fails() {
    let provider = EverParseCborProvider;

    // Wrong tag: 99([...])
    let data = vec![
        0xd8, 0x63, // tag(99)
        0x84, // Array(4)
        0x40, 0xa0, 0xf6, 0x40,
    ];

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());

    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("unexpected COSE tag"));
        }
        _ => panic!("Expected InvalidMessage error"),
    }
}

#[test]
fn test_message_parse_wrong_array_length_fails() {
    let provider = EverParseCborProvider;

    // Array with 3 elements instead of 4
    let data = vec![
        0x83, // Array(3)
        0x40, 0xa0, 0xf6,
    ];

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());

    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("must have 4 elements"));
        }
        _ => panic!("Expected InvalidMessage error"),
    }
}

#[test]
fn test_message_parse_indefinite_array_fails() {
    let provider = EverParseCborProvider;

    // Indefinite-length array
    let data = vec![
        0x9f, // Array(indefinite)
        0x40, 0xa0, 0xf6, 0x40, 0xff, // break
    ];

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());

    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("definite-length"));
        }
        _ => panic!("Expected InvalidMessage error"),
    }
}

#[test]
fn test_message_protected_header_bytes() {
    let provider = EverParseCborProvider;

    let protected_bytes = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_bytes);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.protected_header_bytes(), &protected_bytes[..]);
}

#[test]
fn test_message_alg() {
    let provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.alg(), Some(-7));
}

#[test]
fn test_message_alg_none() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.alg(), None);
}

#[test]
fn test_message_is_detached_true() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(msg.is_detached());
}

#[test]
fn test_message_is_detached_false() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0x43, 0x61, 0x62, 0x63, 0x40]; // payload: "abc"

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(!msg.is_detached());
}

#[test]
fn test_message_encode_minimal() {
    let provider = EverParseCborProvider;

    // Parse a minimal message
    let original_data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&original_data).expect("parse failed");

    // Encode without tag
    let encoded = msg.encode(false).expect("encode failed");

    assert_eq!(encoded, original_data);
}

#[test]
fn test_message_encode_with_tag() {
    let provider = EverParseCborProvider;

    let original_data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&original_data).expect("parse failed");

    // Encode with tag
    let encoded = msg.encode(true).expect("encode failed");

    // Should start with tag 18 (0xd2)
    assert_eq!(encoded[0], 0xd2);
    // Rest should match original
    assert_eq!(&encoded[1..], &original_data[..]);
}

#[test]
fn test_message_encode_decode_roundtrip() {
    let provider = EverParseCborProvider;

    // Create a message with various headers
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[
        0xa1, 0x04, 0x42, 0xaa, 0xbb, // unprotected: {4: h'aabb'}
        0x44, 0x01, 0x02, 0x03, 0x04, // payload: h'01020304'
        0x43, 0xaa, 0xbb, 0xcc, // signature: h'aabbcc'
    ]);

    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");

    let encoded = msg1.encode(false).expect("encode failed");
    let msg2 = CoseSign1Message::parse(&encoded).expect("parse failed");

    assert_eq!(msg2.alg(), Some(-7));
    assert_eq!(msg2.unprotected_headers().kid(), Some(&[0xaa, 0xbb][..]));
    assert_eq!(msg2.payload(), Some(&[0x01, 0x02, 0x03, 0x04][..]));
    assert_eq!(msg2.signature(), &[0xaa, 0xbb, 0xcc]);
}

#[test]
fn test_message_encode_with_empty_protected() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let encoded = msg.encode(false).expect("encode failed");

    // Should encode empty protected as h'' (0x40)
    assert_eq!(encoded[1], 0x40);
}

#[test]
fn test_message_encode_with_detached_payload() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let encoded = msg.encode(false).expect("encode failed");

    // Payload should be encoded as null (0xf6)
    assert_eq!(encoded[3], 0xf6);
}

#[test]
fn test_message_parse_with_complex_unprotected() {
    let provider = EverParseCborProvider;

    // Unprotected header with multiple entries
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa2, 0x04, 0x42, 0x01, 0x02, // {4: h'0102',
        0x18, 0x20, 0x18, 0x2a, //  32: 42}
        0xf6, // null
        0x40, // bstr(0)
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.unprotected_headers().kid(), Some(&[0x01, 0x02][..]));
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(32)),
        Some(&CoseHeaderValue::Int(42))
    );
}

#[test]
fn test_message_parse_unprotected_with_text_label() {
    let provider = EverParseCborProvider;

    // Unprotected: {"custom": 123}
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa1, 0x66, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x18, 0x7b, // {"custom": 123}
        0xf6, // null
        0x40, // bstr(0)
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Text("custom".to_string())),
        Some(&CoseHeaderValue::Int(123))
    );
}

#[test]
fn test_message_parse_unprotected_with_array() {
    let provider = EverParseCborProvider;

    // Unprotected: {10: [1, 2, 3]}
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xa1, 0x0a, 0x83, 0x01, 0x02, 0x03, // {10: [1, 2, 3]}
        0xf6, // null
        0x40, // bstr(0)
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Int(2));
            assert_eq!(arr[2], CoseHeaderValue::Int(3));
        }
        _ => panic!("Expected array value"),
    }
}

#[test]
fn test_message_clone() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0x44, 0x01, 0x02, 0x03, 0x04, 0x40];
    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");

    let msg2 = msg1.clone();

    assert_eq!(msg2.payload(), msg1.payload());
    assert_eq!(msg2.signature(), msg1.signature());
    assert_eq!(msg2.protected_header_bytes(), msg1.protected_header_bytes());
}

#[test]
fn test_message_parse_large_payload() {
    let provider = EverParseCborProvider;

    let payload_size = 10_000;
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();

    // Build COSE_Sign1 message manually
    let mut data = vec![0x84, 0x40, 0xa0];
    // bstr with 2-byte length
    data.push(0x59);
    data.push((payload_size >> 8) as u8);
    data.push((payload_size & 0xff) as u8);
    data.extend_from_slice(&payload);
    data.push(0x40); // empty signature

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.payload(), Some(payload.as_slice()));
}

#[test]
fn test_message_parse_empty_payload() {
    let provider = EverParseCborProvider;

    // Embedded empty payload (not detached)
    let data = vec![0x84, 0x40, 0xa0, 0x40, 0x40]; // payload: h''

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.payload(), Some(&[][..]));
    assert!(!msg.is_detached());
}

#[test]
fn test_message_parse_protected_with_multiple_headers() {
    let provider = EverParseCborProvider;

    // Protected: {1: -7, 3: 50}
    let protected_map = vec![0xa2, 0x01, 0x26, 0x03, 0x18, 0x32];

    let mut data = vec![0x84, 0x46]; // Array(4), bstr(6)
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(
        msg.protected_headers().get(&CoseHeaderLabel::Int(3)),
        Some(&CoseHeaderValue::Int(50))
    );
}

#[test]
fn test_message_encode_preserves_protected_bytes() {
    let provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26];

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let encoded = msg.encode(false).expect("encode failed");
    let msg2 = CoseSign1Message::parse(&encoded).expect("parse failed");

    assert_eq!(msg2.protected_header_bytes(), &protected_map[..]);
}

#[test]
fn test_message_parse_unprotected_indefinite_length_map() {
    let provider = EverParseCborProvider;

    // Unprotected with indefinite-length map: {_ 4: h'01'}
    let data = vec![
        0x84, // Array(4)
        0x40, // bstr(0)
        0xbf, 0x04, 0x41, 0x01, 0xff, // {_ 4: h'01', break}
        0xf6, // null
        0x40, // bstr(0)
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.unprotected_headers().kid(), Some(&[0x01][..]));
}

#[test]
fn test_message_encode_with_unprotected_empty() {
    let provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let encoded = msg.encode(false).expect("encode failed");

    // Unprotected should be encoded as empty map (0xa0)
    assert_eq!(encoded[2], 0xa0);
}

#[test]
fn test_message_parse_signature_various_sizes() {
    let provider = EverParseCborProvider;

    // 64-byte signature (typical ECDSA)
    let signature = vec![0xaa; 64];

    let mut data = vec![0x84, 0x40, 0xa0, 0xf6, 0x58, 0x40]; // bstr(64)
    data.extend_from_slice(&signature);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.signature(), signature);
}

#[test]
fn test_cose_sign1_tag_constant() {
    assert_eq!(COSE_SIGN1_TAG, 18);
}

// --- Mock signer and verifier for verify tests ---

struct MockSigner;

impl CryptoSigner for MockSigner {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0xaa, 0xbb])
    }
}

struct MockVerifier;

impl CryptoVerifier for MockVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(signature == &[0xaa, 0xbb])
    }
}

struct FailVerifier;

impl CryptoVerifier for FailVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::VerificationFailed("fail".to_string()))
    }
}

// --- verify embedded payload ---

#[test]
fn test_message_verify_embedded_payload() {
    let provider = EverParseCborProvider;
    // [h'', {}, h'test', h'\xaa\xbb']
    let data = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let result = msg.verify(&MockVerifier, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_message_verify_detached_payload_missing() {
    let provider = EverParseCborProvider;
    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let result = msg.verify(&MockVerifier, None);
    assert!(result.is_err());
    match result {
        Err(CoseSign1Error::PayloadMissing) => {}
        _ => panic!("expected PayloadMissing"),
    }
}

#[test]
fn test_message_verify_detached() {
    let provider = EverParseCborProvider;
    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let result = msg.verify_detached(&MockVerifier, b"any payload", None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_message_verify_detached_streaming() {
    let provider = EverParseCborProvider;
    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let payload_data = b"streaming payload";
    // Cursor implements SizedRead, so we can pass it directly (length is derived from inner buffer)
    let mut reader = std::io::Cursor::new(payload_data.to_vec());
    let result = msg.verify_detached_streaming(&MockVerifier, &mut reader, None);
    assert!(result.is_ok());
}

#[test]
fn test_message_verify_streaming_with_streaming_payload() {
    let provider = EverParseCborProvider;
    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"streaming test".to_vec()));
    let result = msg.verify_streaming(&MockVerifier, payload, None);
    assert!(result.is_ok());
}

// --- decode_header_value: NegativeInt in unprotected ---

#[test]
fn test_message_parse_unprotected_negative_int_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: -7}  =>  0xa1 0x0a 0x26
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0x26, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Int(-7))
    );
}

// --- decode_header_value: ByteString ---

#[test]
fn test_message_parse_unprotected_bstr_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: h'deadbeef'}  =>  0xa1 0x0a 0x44 0xde 0xad 0xbe 0xef
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0x44, 0xde, 0xad, 0xbe, 0xef, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef].into()))
    );
}

// --- decode_header_value: TextString ---

#[test]
fn test_message_parse_unprotected_text_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: "hello"}  =>  0xa1 0x0a 0x65 h e l l o
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Text("hello".to_string().into()))
    );
}

// --- decode_header_value: Map ---

#[test]
fn test_message_parse_unprotected_map_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: {1: 42}}  =>  0xa1 0x0a 0xa1 0x01 0x18 0x2a
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xa1, 0x01, 0x18, 0x2a, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
            assert_eq!(pairs[0].1, CoseHeaderValue::Int(42));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

// --- decode_header_value: Tag ---

#[test]
fn test_message_parse_unprotected_tagged_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: tag(100, 42)}  =>  0xa1 0x0a 0xd8 0x64 0x18 0x2a
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xd8, 0x64, 0x18, 0x2a, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Tagged(tag, inner)) => {
            assert_eq!(*tag, 100);
            assert_eq!(**inner, CoseHeaderValue::Int(42));
        }
        other => panic!("expected Tagged, got {:?}", other),
    }
}

// --- decode_header_value: Bool ---

#[test]
fn test_message_parse_unprotected_bool_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: true}  =>  0xa1 0x0a 0xf5
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xf5, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Bool(true))
    );
}

// --- decode_header_value: Null ---

#[test]
fn test_message_parse_unprotected_null_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: null}  =>  0xa1 0x0a 0xf6
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xf6, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Null)
    );
}

// --- decode_header_value: Undefined ---

#[test]
fn test_message_parse_unprotected_undefined_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: undefined}  =>  0xa1 0x0a 0xf7
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xf7, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Undefined)
    );
}

// --- decode_header_value: Float ---

#[test]
fn test_message_parse_unprotected_float_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: 3.14}
    // float64: 0xfb 0x40 0x09 0x1e 0xb8 0x51 0xeb 0x85 0x1f (3.14 in IEEE754)
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0xfb, 0x40, 0x09, 0x1e, 0xb8, 0x51, 0xeb, 0x85, 0x1f, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Float(f)) => {
            assert!((f - 3.14).abs() < 0.001);
        }
        other => panic!("expected Float, got {:?}", other),
    }
}

// --- decode_header_value: Indefinite-length map ---

#[test]
fn test_message_parse_unprotected_indefinite_map_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: {_ 1: 42, break}}
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0xbf, 0x01, 0x18, 0x2a, 0xff, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

// --- decode_header_value: Indefinite-length array ---

#[test]
fn test_message_parse_unprotected_indefinite_array_value() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: [_ 1, 2, break]}
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0x9f, 0x01, 0x02, 0xff, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 2);
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

// --- decode_header_label: invalid label type (bstr as label) ---

#[test]
fn test_message_parse_unprotected_invalid_label_type() {
    let provider = EverParseCborProvider;
    // Unprotected: {h'01': 42}  → A1 41 01 18 2A
    let data = vec![0x84, 0x40, 0xa1, 0x41, 0x01, 0x18, 0x2a, 0xf6, 0x40];
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("invalid header label type"));
        }
        _ => panic!("expected InvalidMessage error"),
    }
}

// --- decode_header_value: Uint > i64::MAX ---

#[test]
fn test_message_parse_unprotected_uint_over_i64_max() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: 0xFFFFFFFFFFFFFFFF}
    // A1 0A 1B FF FF FF FF FF FF FF FF
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );
}

// --- decode_header_value: Simple value (skipped as unknown type) ---

#[test]
fn test_message_parse_unprotected_simple_value_skipped() {
    let provider = EverParseCborProvider;
    // Unprotected: {10: simple(16), 11: 42}
    // A2 0A F0 0B 18 2A
    // simple(16) = 0xf0 should be skipped; next entry should be parsed
    let data = vec![0x84, 0x40, 0xa2, 0x0a, 0xf0, 0x0b, 0x18, 0x2a, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    // The simple value should have been skipped and replaced with Null
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Null)
    );
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(11)),
        Some(&CoseHeaderValue::Int(42))
    );
}

// ====== NEW TESTS FOR UNCOVERED PATHS ======

// --- Test parse_inner() method ---

#[test]
fn test_message_parse_inner() {
    let _provider = EverParseCborProvider;

    // Create two nested COSE_Sign1 messages
    let inner_data = vec![0x84, 0x40, 0xa0, 0x43, 0x01, 0x02, 0x03, 0x40];

    // Outer message with inner as payload (simplified test)
    let msg = CoseSign1Message::parse(&inner_data).expect("parse failed");

    // parse_inner should parse the same format
    let inner_msg = msg.parse_inner(&inner_data).expect("parse_inner failed");

    assert_eq!(inner_msg.payload(), Some(&[0x01, 0x02, 0x03][..]));
}

// --- Test provider() method ---

#[test]
fn test_message_provider() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Verify provider is accessible
    let provider = msg.provider();
    assert!(!std::any::type_name_of_val(provider).is_empty());
}

// --- Test protected_headers() method ---

#[test]
fn test_message_protected_headers() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Get protected headers
    let headers = msg.protected_headers();

    assert_eq!(headers.alg(), Some(-7));
    assert!(headers.get(&CoseHeaderLabel::Int(1)).is_some());
}

// --- Test sig_structure_bytes() method ---

#[test]
fn test_message_sig_structure_bytes() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Get sig structure bytes
    let payload = b"test payload";
    let sig_structure = msg
        .sig_structure_bytes(payload, None)
        .expect("sig_structure_bytes failed");

    // Sig_structure should contain the protected header bytes
    assert!(sig_structure.len() > 0);
    // Should contain "Signature1" context string
    assert!(sig_structure.windows(10).any(|w| w == b"Signature1"));
}

// --- Test sig_structure_bytes with external_aad ---

#[test]
fn test_message_sig_structure_bytes_with_aad() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26];

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let payload = b"test payload";
    let external_aad = b"external aad";

    let sig_structure = msg
        .sig_structure_bytes(payload, Some(external_aad))
        .expect("sig_structure_bytes failed");

    assert!(sig_structure.len() > 0);
}

// --- Test verify with external_aad (mock with known data) ---

#[test]
fn test_message_verify_with_external_aad() {
    let _provider = EverParseCborProvider;

    // Create a message
    let data = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Mock verifier that accepts signature [0xaa, 0xbb]
    let result = msg.verify(&MockVerifier, Some(b"external aad"));
    assert!(result.is_ok());
}

// --- Test verify_detached with external_aad ---

#[test]
fn test_message_verify_detached_with_external_aad() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let result = msg.verify_detached(&MockVerifier, b"payload", Some(b"external aad"));
    assert!(result.is_ok());
}

// --- Test verify_detached_streaming with external_aad ---

#[test]
fn test_message_verify_detached_streaming_with_external_aad() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let payload_data = b"streaming payload";
    let mut reader = std::io::Cursor::new(payload_data.to_vec());

    let result = msg.verify_detached_streaming(&MockVerifier, &mut reader, Some(b"external aad"));
    assert!(result.is_ok());
}

// --- Test verify_detached_read with external_aad ---

#[test]
fn test_message_verify_detached_read_with_external_aad() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let payload_data = b"read payload";
    let mut reader = std::io::Cursor::new(payload_data.to_vec());

    let result = msg.verify_detached_read(&MockVerifier, &mut reader, Some(b"external aad"));
    assert!(result.is_ok());
}

// --- Test verify_streaming with external_aad ---

#[test]
fn test_message_verify_streaming_with_external_aad() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"streaming test".to_vec()));
    let result = msg.verify_streaming(&MockVerifier, payload, Some(b"external aad"));
    assert!(result.is_ok());
}

// --- Test verify failure with FailVerifier ---

#[test]
fn test_message_verify_fails_verification() {
    let _provider = EverParseCborProvider;

    let data = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let result = msg.verify(&FailVerifier, None);
    assert!(result.is_err());
}

// --- Test verify_detached fails ---

#[test]
fn test_message_verify_detached_fails_verification() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let result = msg.verify_detached(&FailVerifier, b"payload", None);
    assert!(result.is_err());
}

// --- Test verify_detached_streaming fails ---

#[test]
fn test_message_verify_detached_streaming_fails() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let payload_data = b"payload";
    let mut reader = std::io::Cursor::new(payload_data.to_vec());

    let result = msg.verify_detached_streaming(&FailVerifier, &mut reader, None);
    assert!(result.is_err());
}

// --- Test array length edge cases ---

#[test]
fn test_message_parse_array_length_0() {
    let _provider = EverParseCborProvider;

    // Array with 0 elements
    let data = vec![0x80]; // Array(0)

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("must have 4 elements"));
        }
        _ => panic!("Expected InvalidMessage error"),
    }
}

#[test]
fn test_message_parse_array_length_1() {
    let _provider = EverParseCborProvider;

    let data = vec![0x81, 0x40]; // Array(1)

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
}

#[test]
fn test_message_parse_array_length_2() {
    let _provider = EverParseCborProvider;

    let data = vec![0x82, 0x40, 0xa0]; // Array(2)

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
}

#[test]
fn test_message_parse_array_length_5() {
    let _provider = EverParseCborProvider;

    let data = vec![0x85, 0x40, 0xa0, 0xf6, 0x40, 0x40]; // Array(5)

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("must have 4 elements"));
        }
        _ => panic!("Expected InvalidMessage error"),
    }
}

// --- Test array type validation (must be array, not map, string, etc) ---

#[test]
fn test_message_parse_not_array() {
    let _provider = EverParseCborProvider;

    // A map instead of array
    let data = vec![0xa0]; // map(0)

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
}

// --- Test header label edge cases ---

#[test]
fn test_message_parse_unprotected_negative_int_label() {
    let _provider = EverParseCborProvider;

    // Unprotected: {-1: 42}  =>  0xa1 0x20 0x18 0x2a
    let data = vec![0x84, 0x40, 0xa1, 0x20, 0x18, 0x2a, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(-1)),
        Some(&CoseHeaderValue::Int(42))
    );
}

// --- Test header value with nested arrays ---

#[test]
fn test_message_parse_unprotected_nested_array() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: [[1, 2], [3, 4]]}
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0x82, 0x82, 0x01, 0x02, 0x82, 0x03, 0x04, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(outer)) => {
            assert_eq!(outer.len(), 2);
            assert!(matches!(&outer[0], CoseHeaderValue::Array(_)));
            assert!(matches!(&outer[1], CoseHeaderValue::Array(_)));
        }
        _ => panic!("Expected nested array"),
    }
}

// --- Test nested maps in headers ---

#[test]
fn test_message_parse_unprotected_nested_map() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: {1: {2: 3}}}
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0xa1, 0x01, 0xa1, 0x02, 0x03, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Map(outer)) => {
            assert_eq!(outer.len(), 1);
        }
        _ => panic!("Expected map"),
    }
}

// --- Test deeply nested structures ---

#[test]
fn test_message_parse_deeply_nested_array_in_map() {
    let _provider = EverParseCborProvider;

    // Unprotected: {1: {2: [3, [4, 5]]}}
    let data = vec![
        0x84, 0x40, 0xa1, 0x01, 0xa1, 0x02, 0x82, 0x03, 0x82, 0x04, 0x05, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(!msg.unprotected_headers().is_empty());
}

// --- Test encode with various inputs ---

#[test]
fn test_message_encode_with_large_signature() {
    let _provider = EverParseCborProvider;

    // Large signature (256 bytes)
    let signature = vec![0xaa; 256];
    let mut data = vec![0x84, 0x40, 0xa0, 0xf6, 0x59, 0x01, 0x00]; // bstr(256)
    data.extend_from_slice(&signature);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    let encoded = msg.encode(false).expect("encode failed");

    // Should roundtrip successfully
    let msg2 = CoseSign1Message::parse(&encoded).expect("parse encoded");
    assert_eq!(msg2.signature(), signature);
}

// --- Test parse with complex real-world-like structure ---

#[test]
fn test_message_parse_complex_structure() {
    let _provider = EverParseCborProvider;

    // Protected: {1: -7, 3: 50}
    // Unprotected: {4: h'0102', 32: 100}
    // Payload: h'deadbeefcafe'
    // Signature: h'aabbccdd'

    let protected_map = vec![0xa2, 0x01, 0x26, 0x03, 0x18, 0x32]; // {1: -7, 3: 50}

    let mut data = vec![
        0x84, // Array(4)
        0x46, // bstr(6) - protected header size
    ];
    data.extend_from_slice(&protected_map);

    // Unprotected map
    data.extend_from_slice(&[
        0xa2, // map(2)
        0x04, 0x42, 0x01, 0x02, // 4: h'0102'
        0x18, 0x20, 0x18, 0x64, // 32: 100
    ]);

    // Payload
    data.extend_from_slice(&[
        0x46, // bstr(6)
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
    ]);

    // Signature
    data.extend_from_slice(&[
        0x44, 0xaa, 0xbb, 0xcc, 0xdd, // bstr(4)
    ]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(
        msg.payload(),
        Some(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe][..])
    );
    assert_eq!(msg.signature(), &[0xaa, 0xbb, 0xcc, 0xdd]);
}

// --- Test encode/decode with complex structure ---

#[test]
fn test_message_encode_complex_structure() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa2, 0x01, 0x26, 0x03, 0x18, 0x32];

    let mut data = vec![
        0x84, // Array(4)
        0x46, // bstr(6)
    ];
    data.extend_from_slice(&protected_map);

    data.extend_from_slice(&[
        0xa2, // map(2)
        0x04, 0x42, 0x01, 0x02, 0x18, 0x20, 0x18, 0x64, 0x46, // bstr(6)
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
    ]);

    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");
    let encoded = msg1.encode(false).expect("encode failed");
    let msg2 = CoseSign1Message::parse(&encoded).expect("reparse failed");

    assert_eq!(msg2.alg(), msg1.alg());
    assert_eq!(msg2.payload(), msg1.payload());
    assert_eq!(msg2.signature(), msg1.signature());
}

// --- Test message debug trait ---

#[test]
fn test_message_debug() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
    assert!(debug_str.contains("protected"));
    assert!(debug_str.contains("unprotected"));
    assert!(debug_str.contains("payload"));
    assert!(debug_str.contains("signature"));
}

// --- Test multiple unprotected header entries with mixed types ---

#[test]
fn test_message_parse_unprotected_mixed_types() {
    let _provider = EverParseCborProvider;

    // Unprotected: {4: h'01', 10: 42, "key": "value", -1: true}
    let data = vec![
        0x84, 0x40, // Array, empty protected
        0xa4, // map(4)
        0x04, 0x41, 0x01, // 4: h'01'
        0x0a, 0x18, 0x2a, // 10: 42
        0x63, 0x6b, 0x65, 0x79, 0x65, 0x76, 0x61, 0x6c, 0x75, 0x65, // "key": "value"
        0x20, 0xf5, // -1: true
        0xf6, 0x40, // null payload, empty signature
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.unprotected_headers().kid(), Some(&[0x01][..]));
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Int(42))
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Text("key".to_string())),
        Some(&CoseHeaderValue::Text("value".to_string().into()))
    );
    assert_eq!(
        msg.unprotected_headers().get(&CoseHeaderLabel::Int(-1)),
        Some(&CoseHeaderValue::Bool(true))
    );
}

// --- Test parse with indefinite-length unprotected array in value ---

#[test]
fn test_message_parse_unprotected_indefinite_nested_array() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: [_ 1, 2, [_ 3, 4, break], break]}
    let data = vec![
        0x84, 0x40, 0xa1, 0x0a, 0x9f, 0x01, 0x02, 0x9f, 0x03, 0x04, 0xff, 0xff, 0xf6, 0x40,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 3);
            assert!(matches!(&arr[2], CoseHeaderValue::Array(_)));
        }
        _ => panic!("Expected array"),
    }
}

// --- Test large protected header ---

#[test]
fn test_message_parse_large_protected_header() {
    let _provider = EverParseCborProvider;

    // Protected: {1: -7, 50: 100} - simple but with a larger key
    let protected_map = vec![0xa2, 0x01, 0x26, 0x18, 0x32, 0x18, 0x64]; // {1: -7, 50: 100}

    let mut data = vec![
        0x84, // Array(4)
        0x47, // bstr(7)
    ];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert_eq!(msg.alg(), Some(-7));
}

// --- Test encode with tagged option ---

#[test]
fn test_message_encode_tagged_twice() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Encode with tag
    let encoded_tagged = msg.encode(true).expect("encode failed");

    // First byte should be tag 18 (0xd2)
    assert_eq!(encoded_tagged[0], 0xd2);

    // Parse back and encode without tag
    let parsed = CoseSign1Message::parse(&encoded_tagged).expect("parse failed");
    let encoded_untagged = parsed.encode(false).expect("encode failed");

    // Should match original untagged
    assert_eq!(encoded_untagged, data);
}

// --- Test payload variations ---

#[test]
fn test_message_parse_payload_with_special_bytes() {
    let _provider = EverParseCborProvider;

    // Payload with 0x00, 0xff, and other special bytes
    let payload = vec![0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f];

    let mut data = vec![0x84, 0x40, 0xa0, 0x46]; // bstr(6)
    data.extend_from_slice(&payload);
    data.push(0x40);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.payload(), Some(payload.as_slice()));
}

// --- Test signature with various byte patterns ---

#[test]
fn test_message_parse_signature_all_zeros() {
    let _provider = EverParseCborProvider;

    let signature = vec![0x00; 32];
    let mut data = vec![0x84, 0x40, 0xa0, 0xf6, 0x58, 0x20]; // bstr(32)
    data.extend_from_slice(&signature);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.signature(), signature);
}

#[test]
fn test_message_parse_signature_all_ones() {
    let _provider = EverParseCborProvider;

    let signature = vec![0xff; 32];
    let mut data = vec![0x84, 0x40, 0xa0, 0xf6, 0x58, 0x20]; // bstr(32)
    data.extend_from_slice(&signature);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert_eq!(msg.signature(), signature);
}

// --- Test protected header access methods ---

#[test]
fn test_message_protected_header_access() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[0xa0, 0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Test protected headers method
    let headers = msg.protected_headers();
    assert_eq!(headers.alg(), Some(-7));

    // Test protected_header_bytes method
    let raw_bytes = msg.protected_header_bytes();
    assert_eq!(raw_bytes, &protected_map[..]);
}

// --- Test header values with zero-length collections ---

#[test]
fn test_message_parse_unprotected_empty_array_value() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: []}
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0x80, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 0);
        }
        _ => panic!("Expected empty array"),
    }
}

#[test]
fn test_message_parse_unprotected_empty_map_value() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: {}}
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 0);
        }
        _ => panic!("Expected empty map"),
    }
}

// --- Test roundtrip with all header value types ---

#[test]
fn test_message_encode_decode_all_header_types() {
    let _provider = EverParseCborProvider;

    // Message with mixed header types
    let data = vec![
        0x84, 0x40, 0xa4, // map(4) - unprotected
        0x04, 0x42, 0x01, 0x02, // 4: h'0102' (bytes)
        0x0a, 0x18, 0x2a, // 10: 42 (int)
        0x0b, 0x65, 0x68, 0x65, 0x6c, 0x6c, 0x6f, // 11: "hello" (text)
        0x0c, 0xf5, // 12: true (bool)
        0xf6, 0x40,
    ];

    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");
    let encoded = msg1.encode(false).expect("encode failed");
    let msg2 = CoseSign1Message::parse(&encoded).expect("reparse failed");

    // Verify all types are preserved
    assert_eq!(msg2.unprotected_headers().kid(), Some(&[0x01, 0x02][..]));
    assert_eq!(
        msg2.unprotected_headers().get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Int(42))
    );
    assert_eq!(
        msg2.unprotected_headers().get(&CoseHeaderLabel::Int(11)),
        Some(&CoseHeaderValue::Text("hello".to_string().into()))
    );
}

// --- Test maximum array nesting levels ---

#[test]
fn test_message_parse_deeply_nested_mixed_collections() {
    let _provider = EverParseCborProvider;

    // Unprotected: {1: [42, 99]}
    let data = vec![
        0x84, 0x40, 0xa1, 0x01, 0x82, 0x18, 0x2a, 0x18, 0x63, 0xf6, 0x40,
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");
    assert!(!msg.unprotected_headers().is_empty());
}

// --- Test integration: parse with external_aad for all verify methods ---

#[test]
fn test_message_verify_all_methods_with_aad() {
    let _provider = EverParseCborProvider;

    let data = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Test embedded payload verify with AAD
    let result1 = msg.verify(&MockVerifier, Some(b"aad1"));
    assert!(result1.is_ok());

    // Test detached payload verify with AAD
    let result2 = msg.verify_detached(&MockVerifier, b"payload", Some(b"aad2"));
    assert!(result2.is_ok());

    // Test sig_structure_bytes with AAD
    let result3 = msg.sig_structure_bytes(b"payload", Some(b"aad3"));
    assert!(result3.is_ok());
}

// --- Test error recovery in parsing ---

#[test]
fn test_message_parse_invalid_cbor_array_type() {
    let _provider = EverParseCborProvider;

    // Not an array at all - just a bare integer
    let data = vec![0x18, 0x0a]; // integer 10

    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
}

// --- Test encode preserves all data ---

#[test]
fn test_message_encode_preserves_all_data() {
    let _provider = EverParseCborProvider;

    // Test with all fields populated
    let protected_map = vec![0xa1, 0x01, 0x26];
    let mut data = vec![0x84, 0x43];
    data.extend_from_slice(&protected_map);
    data.extend_from_slice(&[
        0xa2, 0x04, 0x42, 0x01, 0x02, 0x18, 0x20, 0x18, 0x64, 0x46, 0xde, 0xad, 0xbe, 0xef, 0xca,
        0xfe, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
    ]);

    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");

    // Encode both with and without tag
    let encoded_no_tag = msg1.encode(false).expect("encode failed");
    let encoded_with_tag = msg1.encode(true).expect("encode failed");

    // Parse them back
    let msg2 = CoseSign1Message::parse(&encoded_no_tag).expect("reparse untagged");
    let msg3 = CoseSign1Message::parse(&encoded_with_tag).expect("reparse tagged");

    // All should have same data
    assert_eq!(msg2.signature(), msg1.signature());
    assert_eq!(msg3.payload(), msg1.payload());
}

// --- Test unprotected header with large negative integers ---

#[test]
fn test_message_parse_unprotected_large_negative() {
    let _provider = EverParseCborProvider;

    // Unprotected: {10: -1000}
    // -1000 in CBOR: 0x39 0x03e7 (negative(999))
    let data = vec![0x84, 0x40, 0xa1, 0x0a, 0x39, 0x03, 0xe7, 0xf6, 0x40];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    match msg.unprotected_headers().get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Int(v)) => {
            assert_eq!(*v, -1000);
        }
        _ => panic!("Expected large negative integer"),
    }
}

// --- Test encode tag edge cases ---

#[test]
fn test_message_encode_tag_and_untagged_differ() {
    let _provider = EverParseCborProvider;

    let data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    let tagged = msg.encode(true).expect("encode tagged");
    let untagged = msg.encode(false).expect("encode untagged");

    // Tagged version should be longer (by at least 1 byte for the tag)
    assert!(tagged.len() > untagged.len());

    // First byte should differ
    assert_ne!(tagged[0], untagged[0]);

    // Tagged should start with tag 18
    assert_eq!(tagged[0], 0xd2);
}

// --- Test parse_inner with error ---

#[test]
fn test_message_parse_inner_with_invalid_data() {
    let _provider = EverParseCborProvider;

    let valid_data = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&valid_data).expect("parse failed");

    // Try to parse invalid data using parse_inner
    let invalid_data = vec![0x18, 0x0a]; // Just an integer
    let result = msg.parse_inner(&invalid_data);

    assert!(result.is_err());
}

// --- Test verify with different verifier behaviors ---

#[test]
fn test_message_verify_success_vs_failure() {
    let _provider = EverParseCborProvider;

    let data = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    // Should succeed
    let result1 = msg.verify(&MockVerifier, None);
    assert!(result1.is_ok());
    assert!(result1.unwrap());

    // Should fail with FailVerifier
    let result2 = msg.verify(&FailVerifier, None);
    assert!(result2.is_err());
}

// --- Test message with only protected headers (no unprotected) ---

#[test]
fn test_message_protected_only() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa2, 0x01, 0x26, 0x03, 0x18, 0x32];

    let mut data = vec![0x84, 0x46];
    data.extend_from_slice(&protected_map);
    data.push(0xa0); // Empty unprotected
    data.extend_from_slice(&[0xf6, 0x40]);

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(!msg.protected_headers().is_empty());
    assert!(msg.unprotected_headers().is_empty());
}

// --- Test message with only unprotected headers (empty protected) ---

#[test]
fn test_message_unprotected_only() {
    let _provider = EverParseCborProvider;

    let data = vec![
        0x84, 0x40, // Empty protected
        0xa2, 0x04, 0x42, 0x01, 0x02, 0x18, 0x20, 0x18, 0x64, 0xf6, 0x40,
    ];

    let msg = CoseSign1Message::parse(&data).expect("parse failed");

    assert!(msg.protected_headers().is_empty());
    assert!(!msg.unprotected_headers().is_empty());
}

#[test]
fn test_message_clone_complex() {
    let _provider = EverParseCborProvider;

    let protected_map = vec![0xa2, 0x01, 0x26, 0x03, 0x18, 0x32];

    let mut data = vec![
        0x84, // Array(4)
        0x46, // bstr(6)
    ];
    data.extend_from_slice(&protected_map);

    data.extend_from_slice(&[
        0xa2, // map(2)
        0x04, 0x42, 0x01, 0x02, 0x18, 0x20, 0x18, 0x64, 0x46, // bstr(6)
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x44, 0xaa, 0xbb, 0xcc, 0xdd,
    ]);

    let msg1 = CoseSign1Message::parse(&data).expect("parse failed");
    let msg2 = msg1.clone();

    assert_eq!(msg2.alg(), msg1.alg());
    assert_eq!(msg2.payload(), msg1.payload());
    assert_eq!(msg2.signature(), msg1.signature());
    assert_eq!(msg2.protected_header_bytes(), msg1.protected_header_bytes());

    // Verify they're independent clones by checking values match
    assert_eq!(msg1.payload(), msg2.payload());
    assert_eq!(msg1.signature(), msg2.signature());
}
