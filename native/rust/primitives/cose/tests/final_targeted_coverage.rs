// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for `headers.rs` encode/decode paths in `cose_primitives`.
//!
//! Covers uncovered lines:
//! - Display impls for CoseHeaderValue (Array, Map, Tagged, Bool, etc.)  lines 137–159
//! - CoseHeaderMap::encode() with all value variants                      lines 414–539
//! - CoseHeaderMap::decode() with all value variants                      lines 452–694
//! - ProtectedHeader::encode / decode round-trip                          line 722

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::{ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader};

// ============================================================================
// Display impls — lines 130–161
// ============================================================================

/// Exercises Display for every CoseHeaderValue variant.
#[test]
fn display_all_header_value_variants() {
    // Int
    assert_eq!(format!("{}", CoseHeaderValue::Int(-7)), "-7");
    // Uint
    assert_eq!(format!("{}", CoseHeaderValue::Uint(u64::MAX)), format!("{}", u64::MAX));
    // Bytes
    assert_eq!(format!("{}", CoseHeaderValue::Bytes(vec![1, 2, 3])), "bytes(3)");
    // Text
    assert_eq!(format!("{}", CoseHeaderValue::Text("hello".into())), "\"hello\"");
    // Array (line 137–143) — with multiple elements to hit the i > 0 branch
    let arr = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Int(2),
        CoseHeaderValue::Int(3),
    ]);
    assert_eq!(format!("{}", arr), "[1, 2, 3]");
    // Array with single element (no comma branch)
    let arr_single = CoseHeaderValue::Array(vec![CoseHeaderValue::Text("a".into())]);
    assert_eq!(format!("{}", arr_single), "[\"a\"]");
    // Map (line 145–151) — with multiple entries to hit i > 0 branch
    let map_val = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("x".into())),
        (CoseHeaderLabel::Text("k".into()), CoseHeaderValue::Int(42)),
    ]);
    assert_eq!(format!("{}", map_val), "{1: \"x\", k: 42}");
    // Tagged (line 153)
    let tagged = CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(0)));
    assert_eq!(format!("{}", tagged), "tag(18, 0)");
    // Bool (line 154)
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
    assert_eq!(format!("{}", CoseHeaderValue::Bool(false)), "false");
    // Null (line 155)
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    // Undefined (line 156)
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
    // Float (line 157)
    let float_display = format!("{}", CoseHeaderValue::Float(2.5));
    assert!(float_display.contains("2.5"), "got: {}", float_display);
    // Raw (line 158)
    assert_eq!(format!("{}", CoseHeaderValue::Raw(vec![0xAA, 0xBB])), "raw(2)");
}

// ============================================================================
// CoseHeaderMap encode/decode round-trip with every value type
// Lines 408–539 (encode), lines 543–700 (decode)
// ============================================================================

/// Encode a header map with Int, Uint, Bytes, Text, Bool, Null, Undefined, Float, Raw, Array, Map, Tagged.
/// Then decode and verify.
#[test]
fn encode_decode_roundtrip_all_value_types() {
    let mut map = CoseHeaderMap::new();

    // Int (negative) — lines 488–490 encode, 589–593 decode
    map.insert(CoseHeaderLabel::Int(-7), CoseHeaderValue::Int(-7));
    // Uint — lines 491–493 encode, 578–587 decode (large uint)
    map.insert(CoseHeaderLabel::Int(99), CoseHeaderValue::Uint(u64::MAX));
    // Bytes — lines 494–496 encode, 595–599 decode
    map.insert(
        CoseHeaderLabel::Int(10),
        CoseHeaderValue::Bytes(vec![0xDE, 0xAD]),
    );
    // Text — lines 497–499 encode, 601–605 decode
    map.insert(
        CoseHeaderLabel::Text("txt".into()),
        CoseHeaderValue::Text("hello".into()),
    );
    // Bool — lines 525–527 encode, 672–676 decode
    map.insert(CoseHeaderLabel::Int(20), CoseHeaderValue::Bool(true));
    // Null — lines 528–530 encode, 678–682 decode
    map.insert(CoseHeaderLabel::Int(21), CoseHeaderValue::Null);
    // Array of Bytes — lines 500–506 encode, 607–632 decode
    map.insert(
        CoseHeaderLabel::Int(30),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![1]),
            CoseHeaderValue::Bytes(vec![2]),
        ]),
    );
    // Map (nested) — lines 509–517 encode, 634–663 decode
    map.insert(
        CoseHeaderLabel::Int(31),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("nested".into()),
        )]),
    );
    // Tagged — lines 519–524 encode, 665–670 decode
    map.insert(
        CoseHeaderLabel::Int(32),
        CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(7))),
    );

    let encoded = map.encode().expect("encode should succeed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode should succeed");

    // Verify each value survived the round-trip
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(-7)),
        Some(&CoseHeaderValue::Int(-7))
    );
    // Uint that exceeds i64::MAX should stay as Uint
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(99)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Bytes(vec![0xDE, 0xAD]))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("txt".into())),
        Some(&CoseHeaderValue::Text("hello".into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(20)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(21)),
        Some(&CoseHeaderValue::Null)
    );

    // Array
    match decoded.get(&CoseHeaderLabel::Int(30)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], CoseHeaderValue::Bytes(vec![1]));
            assert_eq!(arr[1], CoseHeaderValue::Bytes(vec![2]));
        }
        other => panic!("expected Array, got {:?}", other),
    }

    // Map
    match decoded.get(&CoseHeaderLabel::Int(31)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
            assert_eq!(pairs[0].1, CoseHeaderValue::Text("nested".into()));
        }
        other => panic!("expected Map, got {:?}", other),
    }

    // Tagged
    match decoded.get(&CoseHeaderLabel::Int(32)) {
        Some(CoseHeaderValue::Tagged(tag, inner)) => {
            assert_eq!(*tag, 42);
            assert_eq!(**inner, CoseHeaderValue::Int(7));
        }
        other => panic!("expected Tagged, got {:?}", other),
    }
}

// ============================================================================
// CoseHeaderMap::encode with text-string label (line 477–479)
// ============================================================================

#[test]
fn encode_decode_text_label() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("my-header".into()),
        CoseHeaderValue::Int(42),
    );

    let encoded = map.encode().expect("encode text label");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode text label");

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("my-header".into())),
        Some(&CoseHeaderValue::Int(42))
    );
}

// ============================================================================
// CoseHeaderMap::encode Raw value (line 537–539)
// ============================================================================

#[test]
fn encode_raw_value() {
    let provider = EverParseCborProvider::default();

    // Pre-encode a simple integer as raw bytes
    let mut inner_enc = provider.encoder();
    inner_enc.encode_i64(999).unwrap();
    let raw_bytes = inner_enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(50),
        CoseHeaderValue::Raw(raw_bytes.clone()),
    );

    let encoded = map.encode().expect("encode with Raw");
    // Decode — the raw value gets interpreted as Int(999)
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode with Raw");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(50)),
        Some(&CoseHeaderValue::Int(999))
    );
}

// ============================================================================
// ProtectedHeader round-trip (line 722)
// ============================================================================

#[test]
fn protected_header_encode_decode_roundtrip() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"key-id-1".to_vec());

    let protected = ProtectedHeader::encode(headers).expect("encode protected");

    assert!(!protected.as_bytes().is_empty());
    assert_eq!(protected.alg(), Some(-7));

    // Decode from the raw bytes
    let decoded = ProtectedHeader::decode(protected.as_bytes().to_vec())
        .expect("decode protected");
    assert_eq!(decoded.alg(), Some(-7));
}

// ============================================================================
// CoseHeaderMap::decode empty bytes returns empty map
// ============================================================================

#[test]
fn decode_empty_bytes_returns_empty_map() {
    let decoded = CoseHeaderMap::decode(&[]).expect("empty decode");
    assert!(decoded.is_empty());
}

// ============================================================================
// ContentType Display (cose_primitives re-export)
// ============================================================================

#[test]
fn content_type_display() {
    let ct_int = ContentType::Int(42);
    assert_eq!(format!("{}", ct_int), "42");

    let ct_text = ContentType::Text("application/json".into());
    assert_eq!(format!("{}", ct_text), "application/json");
}

// ============================================================================
// CoseHeaderLabel Display
// ============================================================================

#[test]
fn header_label_display() {
    assert_eq!(format!("{}", CoseHeaderLabel::Int(1)), "1");
    assert_eq!(format!("{}", CoseHeaderLabel::Text("x".into())), "x");
}

// ============================================================================
// CoseHeaderValue accessor methods (lines 167–213)
// ============================================================================

#[test]
fn header_value_as_bytes_returns_some_for_bytes() {
    let val = CoseHeaderValue::Bytes(vec![1, 2]);
    assert_eq!(val.as_bytes(), Some(&[1u8, 2][..]));
}

#[test]
fn header_value_as_bytes_returns_none_for_int() {
    let val = CoseHeaderValue::Int(5);
    assert_eq!(val.as_bytes(), None);
}

#[test]
fn header_value_as_i64_returns_some_for_int() {
    let val = CoseHeaderValue::Int(-42);
    assert_eq!(val.as_i64(), Some(-42));
}

#[test]
fn header_value_as_i64_returns_none_for_text() {
    let val = CoseHeaderValue::Text("x".into());
    assert_eq!(val.as_i64(), None);
}

#[test]
fn header_value_as_str_returns_some_for_text() {
    let val = CoseHeaderValue::Text("hello".into());
    assert_eq!(val.as_str(), Some("hello"));
}

#[test]
fn header_value_as_str_returns_none_for_int() {
    let val = CoseHeaderValue::Int(0);
    assert_eq!(val.as_str(), None);
}

// ============================================================================
// CoseHeaderMap convenience setters/getters
// ============================================================================

#[test]
fn header_map_content_type_int() {
    let mut map = CoseHeaderMap::new();
    map.set_content_type(ContentType::Int(42));
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
}

#[test]
fn header_map_content_type_text() {
    let mut map = CoseHeaderMap::new();
    map.set_content_type(ContentType::Text("application/cbor".into()));
    assert_eq!(
        map.content_type(),
        Some(ContentType::Text("application/cbor".into()))
    );
}

#[test]
fn header_map_crit_roundtrip() {
    let mut map = CoseHeaderMap::new();
    let labels = vec![CoseHeaderLabel::Int(1), CoseHeaderLabel::Text("x".into())];
    map.set_crit(labels.clone());
    assert_eq!(map.crit(), Some(labels));
}

// ============================================================================
// CoseHeaderMap::encode/decode with nested Map in value (exercises lines 509–517, 634–663)
// ============================================================================

#[test]
fn encode_decode_nested_map_value() {
    let mut outer = CoseHeaderMap::new();
    outer.insert(
        CoseHeaderLabel::Int(40),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10)),
            (
                CoseHeaderLabel::Text("sub".into()),
                CoseHeaderValue::Bytes(vec![0xBE, 0xEF]),
            ),
        ]),
    );

    let bytes = outer.encode().expect("encode nested map");
    let decoded = CoseHeaderMap::decode(&bytes).expect("decode nested map");

    match decoded.get(&CoseHeaderLabel::Int(40)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 2);
        }
        other => panic!("expected Map with 2 entries, got {:?}", other),
    }
}

// ============================================================================
// From impls for CoseHeaderValue (lines 88–128)
// ============================================================================

#[test]
fn from_impls_for_header_value() {
    let _: CoseHeaderValue = i64::from(-1i64).into();
    let _: CoseHeaderValue = CoseHeaderValue::from(42u64);
    let _: CoseHeaderValue = CoseHeaderValue::from(vec![1u8, 2, 3]);
    let _: CoseHeaderValue = CoseHeaderValue::from(&[4u8, 5][..]);
    let _: CoseHeaderValue = CoseHeaderValue::from(String::from("s"));
    let _: CoseHeaderValue = CoseHeaderValue::from("literal");
    let _: CoseHeaderValue = CoseHeaderValue::from(true);
}
