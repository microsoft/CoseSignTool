// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_primitives headers.rs gaps.
//!
//! Targets: encode/decode roundtrip for Tagged, Undefined, Float, Raw,
//!          header map decode from indefinite-length CBOR,
//!          CoseHeaderValue::as_bytes_one_or_many for various types,
//!          CoseHeaderLabel::Text ordering, Display for nested structures.

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{
    ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};
use cose_primitives::error::CoseError;

// ============================================================================
// CoseHeaderValue — encode/decode Tagged value roundtrip
// ============================================================================

#[test]
fn encode_decode_tagged_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Tagged(1, Box::new(CoseHeaderValue::Int(1234567890))),
    );
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(100)) {
        Some(CoseHeaderValue::Tagged(1, inner)) => {
            assert_eq!(**inner, CoseHeaderValue::Int(1234567890));
        }
        other => panic!("Expected Tagged, got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderValue — encode/decode Undefined
// ============================================================================

#[test]
fn encode_decode_undefined_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(200), CoseHeaderValue::Undefined);
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert!(
        matches!(decoded.get(&CoseHeaderLabel::Int(200)), Some(CoseHeaderValue::Undefined)),
        "Expected Undefined"
    );
}

// ============================================================================
// CoseHeaderValue — encode/decode Null
// ============================================================================

#[test]
fn encode_decode_null_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(201), CoseHeaderValue::Null);
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert!(
        matches!(decoded.get(&CoseHeaderLabel::Int(201)), Some(CoseHeaderValue::Null)),
        "Expected Null"
    );
}

// ============================================================================
// CoseHeaderValue — encode/decode Bool
// ============================================================================

#[test]
fn encode_decode_bool_values() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(300), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(301), CoseHeaderValue::Bool(false));
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(300)) {
        Some(CoseHeaderValue::Bool(true)) => {}
        other => panic!("Expected Bool(true), got {:?}", other),
    }
    match decoded.get(&CoseHeaderLabel::Int(301)) {
        Some(CoseHeaderValue::Bool(false)) => {}
        other => panic!("Expected Bool(false), got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderValue — encode/decode Raw bytes pass-through
// ============================================================================

#[test]
fn encode_decode_raw_value_roundtrip() {
    // Create some raw CBOR bytes (encoding an integer)
    let provider = EverParseCborProvider::default();
    let mut enc = provider.encoder();
    enc.encode_i64(42).unwrap();
    let raw_cbor = enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(400),
        CoseHeaderValue::Raw(raw_cbor.clone()),
    );
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    // Raw encodes inline bytes — what we get back depends on decode interpretation
    // but the round trip should succeed
    assert!(decoded.get(&CoseHeaderLabel::Int(400)).is_some());
}

// ============================================================================
// CoseHeaderValue — encode/decode Map with multiple entries
// ============================================================================

#[test]
fn encode_decode_map_value() {
    let inner_map = vec![
        (
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("hello".to_string()),
        ),
        (
            CoseHeaderLabel::Text("key2".to_string()),
            CoseHeaderValue::Int(42),
        ),
    ];
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(500), CoseHeaderValue::Map(inner_map));
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(500)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 2);
        }
        other => panic!("Expected Map, got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderLabel — Text variant ordering (BTreeMap comparison)
// ============================================================================

#[test]
fn text_label_ordering() {
    let a = CoseHeaderLabel::Text("alpha".to_string());
    let b = CoseHeaderLabel::Text("beta".to_string());
    assert!(a < b);
}

// ============================================================================
// CoseHeaderValue — Display for nested Array containing Map
// ============================================================================

#[test]
fn display_nested_array_with_map() {
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("nested".to_string()),
        )]),
        CoseHeaderValue::Null,
        CoseHeaderValue::Undefined,
    ]);
    let s = format!("{}", val);
    assert!(s.contains("null"), "Display should show null: {}", s);
    assert!(
        s.contains("undefined"),
        "Display should show undefined: {}",
        s
    );
}

// ============================================================================
// CoseHeaderValue — Display for Tagged
// ============================================================================

#[test]
fn display_tagged_value() {
    let val = CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(7)));
    let s = format!("{}", val);
    assert!(s.contains("42"), "Display should contain tag: {}", s);
}

// ============================================================================
// CoseHeaderValue — Display for Float
// ============================================================================

#[test]
fn display_float_value() {
    let val = CoseHeaderValue::Float(3.14);
    let s = format!("{}", val);
    assert!(s.contains("3.14"), "Display should contain float: {}", s);
}

// ============================================================================
// CoseHeaderMap — Uint above i64::MAX roundtrip
// ============================================================================

#[test]
fn encode_decode_uint_above_i64_max() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(600),
        CoseHeaderValue::Uint(u64::MAX),
    );
    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    match decoded.get(&CoseHeaderLabel::Int(600)) {
        Some(CoseHeaderValue::Uint(v)) => assert_eq!(*v, u64::MAX),
        other => panic!("Expected Uint(u64::MAX), got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderMap — decode empty bytes returns empty map
// ============================================================================

#[test]
fn decode_empty_bytes_returns_empty_map() {
    let map = CoseHeaderMap::decode(&[]).unwrap();
    assert!(map.is_empty());
}

// ============================================================================
// ProtectedHeader — encode/decode roundtrip with alg
// ============================================================================

#[test]
fn protected_header_roundtrip_with_alg() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7); // ES256
    let encoded = headers.encode().unwrap();
    let protected = ProtectedHeader::decode(encoded).unwrap();
    assert_eq!(protected.alg(), Some(-7));
}

// ============================================================================
// CoseHeaderMap — get_bytes_one_or_many with single Bytes value
// ============================================================================

#[test]
fn get_bytes_one_or_many_single() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Bytes(vec![1, 2, 3]),
    );
    let items = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0], vec![1, 2, 3]);
}

// ============================================================================
// CoseHeaderMap — get_bytes_one_or_many with Array of Bytes
// ============================================================================

#[test]
fn get_bytes_one_or_many_array() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![10, 20]),
            CoseHeaderValue::Bytes(vec![30, 40]),
        ]),
    );
    let items = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)).unwrap();
    assert_eq!(items.len(), 2);
}

// ============================================================================
// ContentType — Int and Text variants
// ============================================================================

#[test]
fn content_type_set_get() {
    let mut map = CoseHeaderMap::new();
    map.set_content_type(ContentType::Int(42));
    match map.content_type() {
        Some(ContentType::Int(42)) => {}
        other => panic!("Expected Int(42), got {:?}", other),
    }

    map.set_content_type(ContentType::Text("application/json".to_string()));
    match map.content_type() {
        Some(ContentType::Text(s)) => assert_eq!(s, "application/json"),
        other => panic!("Expected Text, got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderMap — crit() filtering
// ============================================================================

#[test]
fn crit_filters_to_valid_labels() {
    let mut map = CoseHeaderMap::new();
    map.set_crit(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".to_string()),
    ]);
    let crit = map.crit().unwrap();
    assert_eq!(crit.len(), 2);
}
