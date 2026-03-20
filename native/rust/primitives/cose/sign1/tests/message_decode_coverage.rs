// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for `CoseSign1Message` decode paths in `message.rs`.
//!
//! Focuses on `decode_header_value_dyn()` branches (floats, tags, maps, arrays,
//! bool, null, undefined, negative int, unknown CBOR types), error paths in
//! parsing, the `parse_dyn()` method, `sig_structure_bytes()`, and
//! encode/decode roundtrips with complex headers.

use std::sync::Arc;

use cbor_primitives::CborEncoder;
use cbor_primitives_everparse::{EverParseCborProvider, EverparseCborEncoder};
use cose_sign1_primitives::error::CoseSign1Error;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_primitives::message::CoseSign1Message;
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier};

// ---------------------------------------------------------------------------
// Mock signer and verifier
// ---------------------------------------------------------------------------

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
    fn verify(&self, _data: &[u8], sig: &[u8]) -> Result<bool, CryptoError> {
        Ok(sig == &[0xaa, 0xbb])
    }
}

// ---------------------------------------------------------------------------
// Helper: build a COSE_Sign1 array with custom unprotected header bytes.
//
// Layout: 84               -- array(4)
//         40               -- bstr(0) (empty protected)
//         <unprotected_raw> -- pre-encoded map
//         44 74657374       -- bstr "test"
//         42 aabb           -- bstr signature
// ---------------------------------------------------------------------------

fn build_cose_with_unprotected(unprotected_raw: &[u8]) -> Vec<u8> {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap(); // protected: empty
    enc.encode_raw(unprotected_raw).unwrap();
    enc.encode_bstr(b"test").unwrap(); // payload
    enc.encode_bstr(&[0xaa, 0xbb]).unwrap(); // signature
    enc.into_bytes()
}

/// Encode a single-entry unprotected map { label => <raw_value_bytes> }.
fn map_with_int_key_raw_value(label: i64, value_bytes: &[u8]) -> Vec<u8> {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_map(1).unwrap();
    enc.encode_i64(label).unwrap();
    enc.encode_raw(value_bytes).unwrap();
    enc.into_bytes()
}

// ===========================================================================
// 1. Float header values (Float16 / Float32 / Float64)
// ===========================================================================

#[test]
fn test_header_value_float64() {
    // CBOR float64: 0xfb + 8 bytes (IEEE 754 double for 3.14)
    let val: f64 = 3.14;
    let mut venc = EverparseCborEncoder::new();
    venc.encode_f64(val).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(99, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse float64");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(99))
        .unwrap();
    match v {
        CoseHeaderValue::Float(f) => assert!((f - 3.14).abs() < 1e-10),
        other => panic!("expected Float, got {:?}", other),
    }
}

#[test]
fn test_header_value_float32_errors_with_everparse() {
    // CBOR float32 (0xfa) — EverParse decode_f64 only accepts 0xfb, so the
    // Float32 branch in decode_header_value_dyn reaches decode_f64() which
    // returns an error. This exercises the Float16/Float32/Float64 match arm
    // and the error-mapping path.
    let mut venc = EverparseCborEncoder::new();
    venc.encode_f32(1.5f32).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(100, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::CborError(_) => {}
        other => panic!("expected CborError, got {:?}", other),
    }
}

#[test]
fn test_header_value_float16_errors_with_everparse() {
    // CBOR float16 (0xf9) — same limitation as float32 above.
    let mut venc = EverparseCborEncoder::new();
    venc.encode_f16(1.0f32).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(101, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::CborError(_) => {}
        other => panic!("expected CborError, got {:?}", other),
    }
}

// ===========================================================================
// 2. Tagged header values
// ===========================================================================

#[test]
fn test_header_value_tagged() {
    // tag(1) wrapping unsigned int 1000
    let mut venc = EverparseCborEncoder::new();
    venc.encode_tag(1).unwrap();
    venc.encode_u64(1000).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(200, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse tagged");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(200))
        .unwrap();
    match v {
        CoseHeaderValue::Tagged(tag, inner) => {
            assert_eq!(*tag, 1);
            assert_eq!(**inner, CoseHeaderValue::Int(1000));
        }
        other => panic!("expected Tagged, got {:?}", other),
    }
}

#[test]
fn test_header_value_tagged_nested() {
    // tag(42) wrapping tag(7) wrapping text "hello"
    let mut venc = EverparseCborEncoder::new();
    venc.encode_tag(42).unwrap();
    venc.encode_tag(7).unwrap();
    venc.encode_tstr("hello").unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(201, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse nested tag");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(201))
        .unwrap();
    match v {
        CoseHeaderValue::Tagged(42, inner) => match inner.as_ref() {
            CoseHeaderValue::Tagged(7, inner2) => {
                assert_eq!(**inner2, CoseHeaderValue::Text("hello".to_string().into()));
            }
            other => panic!("expected inner Tagged(7, ..), got {:?}", other),
        },
        other => panic!("expected Tagged(42, ..), got {:?}", other),
    }
}

// ===========================================================================
// 3. Array header values (definite and indefinite length)
// ===========================================================================

#[test]
fn test_header_value_array_definite() {
    // [1, "two", h'03']
    let mut venc = EverparseCborEncoder::new();
    venc.encode_array(3).unwrap();
    venc.encode_u64(1).unwrap();
    venc.encode_tstr("two").unwrap();
    venc.encode_bstr(&[0x03]).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(300, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse array");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(300))
        .unwrap();
    match v {
        CoseHeaderValue::Array(arr) => {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Text("two".to_string().into()));
            assert_eq!(arr[2], CoseHeaderValue::Bytes(vec![0x03].into()));
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

#[test]
fn test_header_value_array_indefinite() {
    // indefinite-length array: 0x9f, items, 0xff
    let mut venc = EverparseCborEncoder::new();
    venc.encode_array_indefinite_begin().unwrap();
    venc.encode_u64(10).unwrap();
    venc.encode_u64(20).unwrap();
    venc.encode_break().unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(301, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse indefinite array");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(301))
        .unwrap();
    match v {
        CoseHeaderValue::Array(arr) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], CoseHeaderValue::Int(10));
            assert_eq!(arr[1], CoseHeaderValue::Int(20));
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

#[test]
fn test_header_value_array_nested() {
    // [[1, 2], [3]]
    let mut venc = EverparseCborEncoder::new();
    venc.encode_array(2).unwrap();
    // inner [1, 2]
    venc.encode_array(2).unwrap();
    venc.encode_u64(1).unwrap();
    venc.encode_u64(2).unwrap();
    // inner [3]
    venc.encode_array(1).unwrap();
    venc.encode_u64(3).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(302, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse nested array");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(302))
        .unwrap();
    match v {
        CoseHeaderValue::Array(outer) => {
            assert_eq!(outer.len(), 2);
            match &outer[0] {
                CoseHeaderValue::Array(inner) => assert_eq!(inner.len(), 2),
                other => panic!("expected inner Array, got {:?}", other),
            }
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

// ===========================================================================
// 4. Map header values (definite and indefinite length)
// ===========================================================================

#[test]
fn test_header_value_map_definite() {
    // {1: "a", 2: h'bb'}
    let mut venc = EverparseCborEncoder::new();
    venc.encode_map(2).unwrap();
    venc.encode_i64(1).unwrap();
    venc.encode_tstr("a").unwrap();
    venc.encode_i64(2).unwrap();
    venc.encode_bstr(&[0xbb]).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(400, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse map value");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(400))
        .unwrap();
    match v {
        CoseHeaderValue::Map(pairs) => {
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
            assert_eq!(pairs[0].1, CoseHeaderValue::Text("a".to_string().into()));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

#[test]
fn test_header_value_map_indefinite() {
    // indefinite map: 0xbf, key, value, ..., 0xff
    let mut venc = EverparseCborEncoder::new();
    venc.encode_map_indefinite_begin().unwrap();
    venc.encode_i64(5).unwrap();
    venc.encode_bool(true).unwrap();
    venc.encode_break().unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(401, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse indefinite map value");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(401))
        .unwrap();
    match v {
        CoseHeaderValue::Map(pairs) => {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(5));
            assert_eq!(pairs[0].1, CoseHeaderValue::Bool(true));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

// ===========================================================================
// 5. Bool / Null / Undefined / NegativeInt header values
// ===========================================================================

#[test]
fn test_header_value_bool_null_undefined() {
    // unprotected: {10: true, 11: null, 12: undefined}
    let mut map_enc = EverparseCborEncoder::new();
    map_enc.encode_map(3).unwrap();
    map_enc.encode_i64(10).unwrap();
    map_enc.encode_bool(true).unwrap();
    map_enc.encode_i64(11).unwrap();
    map_enc.encode_null().unwrap();
    map_enc.encode_i64(12).unwrap();
    map_enc.encode_undefined().unwrap();
    let unprotected = map_enc.into_bytes();
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse bool/null/undefined");

    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(10))
            .unwrap(),
        &CoseHeaderValue::Bool(true)
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(11))
            .unwrap(),
        &CoseHeaderValue::Null
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(12))
            .unwrap(),
        &CoseHeaderValue::Undefined
    );
}

#[test]
fn test_header_value_negative_int() {
    // {20: -100}
    let mut venc = EverparseCborEncoder::new();
    venc.encode_i64(-100).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(20, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse negative int");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(20))
        .unwrap();
    assert_eq!(*v, CoseHeaderValue::Int(-100));
}

#[test]
fn test_header_value_large_uint() {
    // u64 value > i64::MAX to exercise the Uint branch
    let big: u64 = (i64::MAX as u64) + 1;
    let mut venc = EverparseCborEncoder::new();
    venc.encode_u64(big).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(21, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse large uint");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(21))
        .unwrap();
    assert_eq!(*v, CoseHeaderValue::Uint(big));
}

// ===========================================================================
// 6. Text string header label
// ===========================================================================

#[test]
fn test_header_label_text() {
    let mut map_enc = EverparseCborEncoder::new();
    map_enc.encode_map(1).unwrap();
    map_enc.encode_tstr("my-label").unwrap();
    map_enc.encode_i64(42).unwrap();
    let unprotected = map_enc.into_bytes();
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse text label");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Text("my-label".to_string()))
        .unwrap();
    assert_eq!(*v, CoseHeaderValue::Int(42));
}

// ===========================================================================
// 7. Indefinite-length unprotected header map
// ===========================================================================

#[test]
fn test_unprotected_map_indefinite() {
    let mut map_enc = EverparseCborEncoder::new();
    map_enc.encode_map_indefinite_begin().unwrap();
    map_enc.encode_i64(1).unwrap();
    map_enc.encode_i64(-7).unwrap();
    map_enc.encode_break().unwrap();
    let unprotected = map_enc.into_bytes();
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse indefinite unprotected map");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(1))
        .unwrap();
    assert_eq!(*v, CoseHeaderValue::Int(-7));
}

// ===========================================================================
// 8. parse_dyn() directly
// ===========================================================================

#[test]
fn test_parse_dyn() {
    // provider not needed  using singleton
    // Minimal COSE_Sign1: [h'', {}, h'test', h'\xaa\xbb']
    let data: Vec<u8> = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse_dyn");
    assert_eq!(msg.payload(), Some(b"test".as_slice()));
    assert_eq!(msg.signature(), &[0xaa, 0xbb]);
}

#[test]
fn test_parse_dyn_tagged() {
    // provider not needed  using singleton
    // Tag(18) + [h'', {}, null, h'']
    let data: Vec<u8> = vec![0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse_dyn tagged");
    assert!(msg.is_detached());
}

// ===========================================================================
// 9. Error paths in parse
// ===========================================================================

#[test]
fn test_parse_wrong_tag() {
    // Tag(99) + array(4) ...
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tag(99).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    let data = enc.into_bytes();

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::InvalidMessage(msg) => assert!(msg.contains("unexpected COSE tag")),
        other => panic!("expected InvalidMessage, got {:?}", other),
    }
}

#[test]
fn test_parse_wrong_array_len() {
    // array(3) instead of 4
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(&[]).unwrap();
    let data = enc.into_bytes();

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::InvalidMessage(msg) => assert!(msg.contains("4 elements")),
        other => panic!("expected InvalidMessage, got {:?}", other),
    }
}

#[test]
fn test_parse_indefinite_array_rejected() {
    // indefinite-length top-level array
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array_indefinite_begin().unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_break().unwrap();
    let data = enc.into_bytes();

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::InvalidMessage(msg) => assert!(msg.contains("definite-length")),
        other => panic!("expected InvalidMessage, got {:?}", other),
    }
}

#[test]
fn test_parse_empty_data() {
    let err = CoseSign1Message::parse(&[]).unwrap_err();
    match err {
        CoseSign1Error::CborError(_) => {}
        other => panic!("expected CborError, got {:?}", other),
    }
}

#[test]
fn test_parse_truncated_data() {
    // Only array header, no elements
    let data: Vec<u8> = vec![0x84, 0x40];
    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::CborError(_) => {}
        other => panic!("expected CborError, got {:?}", other),
    }
}

#[test]
fn test_parse_invalid_header_label_type() {
    // unprotected map with a bstr key (invalid for header labels)
    let mut map_enc = EverparseCborEncoder::new();
    map_enc.encode_map(1).unwrap();
    map_enc.encode_bstr(&[0x01]).unwrap(); // bstr key — invalid
    map_enc.encode_i64(1).unwrap();
    let unprotected = map_enc.into_bytes();
    let data = build_cose_with_unprotected(&unprotected);

    let err = CoseSign1Message::parse(&data).unwrap_err();
    match err {
        CoseSign1Error::InvalidMessage(msg) => assert!(msg.contains("invalid header label")),
        other => panic!("expected InvalidMessage, got {:?}", other),
    }
}

// ===========================================================================
// 10. sig_structure_bytes on parsed message
// ===========================================================================

#[test]
fn test_sig_structure_bytes_with_protected_headers() {
    let provider = EverParseCborProvider;

    // protected: {1: -7} = a10126
    let mut data: Vec<u8> = vec![0x84, 0x43, 0xa1, 0x01, 0x26];
    data.extend_from_slice(&[0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb]);

    let msg = CoseSign1Message::parse(&data).expect("parse");

    let sig_bytes = msg
        .sig_structure_bytes(b"test", None)
        .expect("sig_structure_bytes");
    assert!(!sig_bytes.is_empty());

    let sig_bytes_aad = msg
        .sig_structure_bytes(b"test", Some(b"aad"))
        .expect("sig_structure_bytes aad");
    assert_ne!(sig_bytes, sig_bytes_aad);
}

// ===========================================================================
// 11. Encode/decode roundtrip with complex headers
// ===========================================================================

#[test]
fn test_encode_decode_roundtrip_tagged() {
    let data: Vec<u8> = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse");

    let encoded = msg.encode(true).expect("encode tagged");
    // Tagged encoding starts with 0xd2 (tag 18)
    assert_eq!(encoded[0], 0xd2);

    let msg2 = CoseSign1Message::parse(&encoded).expect("re-parse");
    assert_eq!(msg2.payload(), msg.payload());
    assert_eq!(msg2.signature(), msg.signature());
}

#[test]
fn test_encode_decode_roundtrip_untagged() {
    let data: Vec<u8> = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse");

    let encoded = msg.encode(false).expect("encode untagged");
    assert_ne!(encoded[0], 0xd2);

    let msg2 = CoseSign1Message::parse(&encoded).expect("re-parse");
    assert_eq!(msg2.payload(), msg.payload());
    assert_eq!(msg2.signature(), msg.signature());
}

#[test]
fn test_encode_decode_roundtrip_detached() {
    // [h'', {}, null, h'\xaa\xbb']
    let data: Vec<u8> = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse");
    assert!(msg.is_detached());

    let encoded = msg.encode(false).expect("encode detached");
    let msg2 = CoseSign1Message::parse(&encoded).expect("re-parse");
    assert!(msg2.is_detached());
    assert_eq!(msg2.signature(), msg.signature());
}

// ===========================================================================
// 12. Multiple header types in one unprotected map
// ===========================================================================

#[test]
fn test_multiple_types_in_unprotected() {
    let mut map_enc = EverparseCborEncoder::new();
    map_enc.encode_map(5).unwrap();

    // int key 1 -> negative int
    map_enc.encode_i64(1).unwrap();
    map_enc.encode_i64(-42).unwrap();

    // int key 2 -> bstr
    map_enc.encode_i64(2).unwrap();
    map_enc.encode_bstr(&[0xde, 0xad]).unwrap();

    // int key 3 -> text
    map_enc.encode_i64(3).unwrap();
    map_enc.encode_tstr("value").unwrap();

    // int key 4 -> bool false
    map_enc.encode_i64(4).unwrap();
    map_enc.encode_bool(false).unwrap();

    // int key 5 -> tag(1) wrapping int 0
    map_enc.encode_i64(5).unwrap();
    map_enc.encode_tag(1).unwrap();
    map_enc.encode_u64(0).unwrap();

    let unprotected = map_enc.into_bytes();
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse multi-type headers");

    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(1))
            .unwrap(),
        &CoseHeaderValue::Int(-42)
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(2))
            .unwrap(),
        &CoseHeaderValue::Bytes(vec![0xde, 0xad].into())
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(3))
            .unwrap(),
        &CoseHeaderValue::Text("value".to_string().into())
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Int(4))
            .unwrap(),
        &CoseHeaderValue::Bool(false)
    );
    match msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(5))
        .unwrap()
    {
        CoseHeaderValue::Tagged(1, inner) => {
            assert_eq!(**inner, CoseHeaderValue::Int(0));
        }
        other => panic!("expected Tagged, got {:?}", other),
    }
}

// ===========================================================================
// 13. Verify on embedded vs detached
// ===========================================================================

#[test]
fn test_verify_embedded_ok() {
    let data: Vec<u8> = vec![
        0x84, 0x40, 0xa0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x42, 0xaa, 0xbb,
    ];
    let msg = CoseSign1Message::parse(&data).expect("parse");
    assert!(msg.verify(&MockVerifier, None).expect("verify"));
}

#[test]
fn test_verify_detached_payload_missing() {
    let data: Vec<u8> = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse");

    let err = msg.verify(&MockVerifier, None).unwrap_err();
    match err {
        CoseSign1Error::PayloadMissing => {}
        other => panic!("expected PayloadMissing, got {:?}", other),
    }
}

#[test]
fn test_verify_detached() {
    let data: Vec<u8> = vec![0x84, 0x40, 0xa0, 0xf6, 0x42, 0xaa, 0xbb];
    let msg = CoseSign1Message::parse(&data).expect("parse");
    assert!(msg
        .verify_detached(&MockVerifier, b"payload", None)
        .expect("verify_detached"));
}

// ===========================================================================
// 14. Empty unprotected map (zero-length fast path)
// ===========================================================================

#[test]
fn test_empty_unprotected_map() {
    // a0 = map(0)
    let data: Vec<u8> = vec![0x84, 0x40, 0xa0, 0xf6, 0x40];
    let msg = CoseSign1Message::parse(&data).expect("parse empty map");
    assert!(msg.unprotected_headers().is_empty());
}

// ===========================================================================
// 15. Array containing a map inside a header value
// ===========================================================================

#[test]
fn test_header_value_array_containing_map() {
    // [{1: 2}]
    let mut venc = EverparseCborEncoder::new();
    venc.encode_array(1).unwrap();
    venc.encode_map(1).unwrap();
    venc.encode_i64(1).unwrap();
    venc.encode_i64(2).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(500, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse array with map");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(500))
        .unwrap();
    match v {
        CoseHeaderValue::Array(arr) => {
            assert_eq!(arr.len(), 1);
            match &arr[0] {
                CoseHeaderValue::Map(pairs) => {
                    assert_eq!(pairs.len(), 1);
                    assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
                    assert_eq!(pairs[0].1, CoseHeaderValue::Int(2));
                }
                other => panic!("expected Map, got {:?}", other),
            }
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

// ===========================================================================
// 16. Map with text string keys inside header value
// ===========================================================================

#[test]
fn test_header_value_map_with_text_keys() {
    // {"a": 1, "b": 2}
    let mut venc = EverparseCborEncoder::new();
    venc.encode_map(2).unwrap();
    venc.encode_tstr("a").unwrap();
    venc.encode_i64(1).unwrap();
    venc.encode_tstr("b").unwrap();
    venc.encode_i64(2).unwrap();
    let val_bytes = venc.into_bytes();

    let unprotected = map_with_int_key_raw_value(600, &val_bytes);
    let data = build_cose_with_unprotected(&unprotected);

    let msg = CoseSign1Message::parse(&data).expect("parse map with text keys");
    let v = msg
        .unprotected_headers()
        .get(&CoseHeaderLabel::Int(600))
        .unwrap();
    match v {
        CoseHeaderValue::Map(pairs) => {
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Text("a".to_string()));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}
