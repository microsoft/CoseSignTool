// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for COSE headers — targets remaining uncovered lines.
//!
//! Focuses on:
//! - Display impls for Array, Map, Tagged, Bool, Null, Undefined, Float, Raw variants
//! - CoseHeaderMap encode/decode for all CoseHeaderValue variants
//! - ProtectedHeader::encode round-trip
//! - Decode paths for NegativeInt, ByteString, TextString, Array, Map, Tag, Bool,
//!   Null, Undefined value types in CoseHeaderMap::decode_value

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::{
    CoseError, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ContentType, ProtectedHeader,
};

// ===========================================================================
// Display coverage for CoseHeaderValue variants (lines 137-158)
// ===========================================================================

#[test]
fn display_array_empty() {
    let val = CoseHeaderValue::Array(vec![]);
    assert_eq!(format!("{}", val), "[]");
}

#[test]
fn display_array_single() {
    let val = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]);
    assert_eq!(format!("{}", val), "[1]");
}

#[test]
fn display_array_multiple() {
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("two".to_string()),
        CoseHeaderValue::Bytes(vec![3]),
    ]);
    assert_eq!(format!("{}", val), "[1, \"two\", bytes(1)]");
}

#[test]
fn display_map_empty() {
    let val = CoseHeaderValue::Map(vec![]);
    assert_eq!(format!("{}", val), "{}");
}

#[test]
fn display_map_single() {
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Text("v".to_string()),
    )]);
    assert_eq!(format!("{}", val), "{1: \"v\"}");
}

#[test]
fn display_map_multiple() {
    let val = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10)),
        (
            CoseHeaderLabel::Text("k".to_string()),
            CoseHeaderValue::Bool(true),
        ),
    ]);
    assert_eq!(format!("{}", val), "{1: 10, k: true}");
}

#[test]
fn display_tagged() {
    let val = CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(42)));
    assert_eq!(format!("{}", val), "tag(18, 42)");
}

#[test]
fn display_bool_null_undefined_float_raw() {
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
    assert_eq!(format!("{}", CoseHeaderValue::Bool(false)), "false");
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
    assert_eq!(format!("{}", CoseHeaderValue::Float(3.14)), "3.14");
    assert_eq!(format!("{}", CoseHeaderValue::Raw(vec![0xA0])), "raw(1)");
}

// ===========================================================================
// CoseHeaderMap::encode then decode roundtrip for CoseHeaderValue variants
// that go through encode_value / decode_value. (lines 415-540, 575-695)
// ===========================================================================

#[test]
fn encode_decode_int_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(100), CoseHeaderValue::Int(-42));
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(100)),
        Some(&CoseHeaderValue::Int(-42))
    );
}

#[test]
fn encode_decode_uint_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(101), CoseHeaderValue::Uint(999));
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    // Uint(999) fits in i64 so decoder returns Int(999)
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(101)),
        Some(&CoseHeaderValue::Int(999))
    );
}

#[test]
fn encode_decode_bytes_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(102),
        CoseHeaderValue::Bytes(vec![0xDE, 0xAD]),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(102)),
        Some(&CoseHeaderValue::Bytes(vec![0xDE, 0xAD]))
    );
}

#[test]
fn encode_decode_text_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(103),
        CoseHeaderValue::Text("hello".to_string()),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(103)),
        Some(&CoseHeaderValue::Text("hello".to_string()))
    );
}

#[test]
fn encode_decode_array_of_ints() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(104),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(10),
            CoseHeaderValue::Int(-20),
        ]),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    if let Some(CoseHeaderValue::Array(arr)) = decoded.get(&CoseHeaderLabel::Int(104)) {
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], CoseHeaderValue::Int(10));
        assert_eq!(arr[1], CoseHeaderValue::Int(-20));
    } else {
        panic!("expected Array");
    }
}

#[test]
fn encode_decode_nested_map_value() {
    let inner = vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42)),
        (
            CoseHeaderLabel::Text("x".to_string()),
            CoseHeaderValue::Bytes(vec![1]),
        ),
    ];
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(105), CoseHeaderValue::Map(inner));
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    if let Some(CoseHeaderValue::Map(pairs)) = decoded.get(&CoseHeaderLabel::Int(105)) {
        assert_eq!(pairs.len(), 2);
    } else {
        panic!("expected Map");
    }
}

#[test]
fn encode_decode_tagged_int() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(106),
        CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(7))),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    if let Some(CoseHeaderValue::Tagged(tag, inner)) = decoded.get(&CoseHeaderLabel::Int(106)) {
        assert_eq!(*tag, 42);
        assert_eq!(**inner, CoseHeaderValue::Int(7));
    } else {
        panic!("expected Tagged");
    }
}

#[test]
fn encode_decode_bool_values() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(107), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(108), CoseHeaderValue::Bool(false));
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(107)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(108)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

#[test]
fn encode_decode_null() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(109), CoseHeaderValue::Null);
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(109)),
        Some(&CoseHeaderValue::Null)
    );
}

#[test]
fn encode_decode_undefined() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(110), CoseHeaderValue::Undefined);
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(110)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn encode_decode_raw_passthrough() {
    // Encode an integer as raw CBOR bytes and insert as Raw variant
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_i64(99).unwrap();
    let raw_cbor = enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(111),
        CoseHeaderValue::Raw(raw_cbor.clone()),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    // Raw bytes are decoded as their underlying CBOR type
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(111)),
        Some(&CoseHeaderValue::Int(99))
    );
}

#[test]
fn encode_decode_text_label() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderValue::Int(1),
    );
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom".to_string())),
        Some(&CoseHeaderValue::Int(1))
    );
}

// ===========================================================================
// ProtectedHeader::encode round-trip (line 722)
// ===========================================================================

#[test]
fn protected_header_encode_roundtrip() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"kid-1".to_vec());

    let protected = ProtectedHeader::encode(headers).unwrap();
    assert!(!protected.as_bytes().is_empty());
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"kid-1".as_slice()));
}

#[test]
fn protected_header_encode_empty() {
    let headers = CoseHeaderMap::new();
    let protected = ProtectedHeader::encode(headers).unwrap();
    // Empty map still produces CBOR bytes for an empty map
    assert!(!protected.as_bytes().is_empty());
    assert!(protected.headers().is_empty());
}

// ===========================================================================
// Decode negative integers in header values (NegativeInt path, line 592)
// ===========================================================================

#[test]
fn decode_negative_int_value() {
    // Manually encode a map { 1: -42 } using CBOR
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(-42).unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-42))
    );
}

// ===========================================================================
// Decode text string label (line 560) — the decode_label TextString path
// ===========================================================================

#[test]
fn decode_text_string_label() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("my-header").unwrap();
    enc.encode_i64(100).unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("my-header".to_string())),
        Some(&CoseHeaderValue::Int(100))
    );
}

// ===========================================================================
// Decode text string value (line 604)
// ===========================================================================

#[test]
fn decode_text_string_value_via_cbor() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(200).unwrap();
    enc.encode_tstr("value-text").unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(200)),
        Some(&CoseHeaderValue::Text("value-text".to_string()))
    );
}

// ===========================================================================
// Multiple entry map encode/decode (exercises the full loop, lines 415-421)
// ===========================================================================

#[test]
fn encode_decode_multi_entry_map() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(b"kid".to_vec()),
    );
    map.insert(
        CoseHeaderLabel::Text("x".to_string()),
        CoseHeaderValue::Text("val".to_string()),
    );

    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(decoded.len(), 3);
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-7))
    );
}

// ===========================================================================
// Array-of-arrays inside a header map value (decode Array path, lines 610-631)
// ===========================================================================

#[test]
fn decode_array_containing_array() {
    let mut map = CoseHeaderMap::new();
    let nested = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Int(2),
        ]),
        CoseHeaderValue::Int(3),
    ]);
    map.insert(CoseHeaderLabel::Int(300), nested.clone());
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();

    if let Some(CoseHeaderValue::Array(outer)) = decoded.get(&CoseHeaderLabel::Int(300)) {
        assert_eq!(outer.len(), 2);
        if let CoseHeaderValue::Array(inner) = &outer[0] {
            assert_eq!(inner.len(), 2);
        } else {
            panic!("expected inner array");
        }
    } else {
        panic!("expected outer array");
    }
}

// ===========================================================================
// Map value inside a map (decode Map path, lines 637-661)
// ===========================================================================

#[test]
fn decode_map_value_containing_map() {
    let inner = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(10), CoseHeaderValue::Int(20)),
    ]);
    let outer = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), inner),
    ]);
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(400), outer);
    let bytes = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();

    if let Some(CoseHeaderValue::Map(pairs)) = decoded.get(&CoseHeaderLabel::Int(400)) {
        assert_eq!(pairs.len(), 1);
        if let CoseHeaderValue::Map(inner_pairs) = &pairs[0].1 {
            assert_eq!(inner_pairs.len(), 1);
        } else {
            panic!("expected inner map");
        }
    } else {
        panic!("expected outer map");
    }
}

// ===========================================================================
// Tagged value decode (lines 668-669)
// ===========================================================================

#[test]
fn decode_tagged_value_from_cbor() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(500).unwrap();
    enc.encode_tag(18).unwrap();
    enc.encode_bstr(&[0xAB, 0xCD]).unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    if let Some(CoseHeaderValue::Tagged(tag, inner)) = decoded.get(&CoseHeaderLabel::Int(500)) {
        assert_eq!(*tag, 18);
        assert_eq!(**inner, CoseHeaderValue::Bytes(vec![0xAB, 0xCD]));
    } else {
        panic!("expected Tagged");
    }
}

// ===========================================================================
// Bool value decode (line 675)
// ===========================================================================

#[test]
fn decode_bool_values_from_cbor() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(2).unwrap();
    enc.encode_i64(600).unwrap();
    enc.encode_bool(true).unwrap();
    enc.encode_i64(601).unwrap();
    enc.encode_bool(false).unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(600)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(601)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

// ===========================================================================
// Null value decode (line 681)
// ===========================================================================

#[test]
fn decode_null_value_from_cbor() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(700).unwrap();
    enc.encode_null().unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(700)),
        Some(&CoseHeaderValue::Null)
    );
}

// ===========================================================================
// Undefined value decode (line 687)
// ===========================================================================

#[test]
fn decode_undefined_value_from_cbor() {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(800).unwrap();
    enc.encode_undefined().unwrap();
    let bytes = enc.into_bytes();

    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(800)),
        Some(&CoseHeaderValue::Undefined)
    );
}
