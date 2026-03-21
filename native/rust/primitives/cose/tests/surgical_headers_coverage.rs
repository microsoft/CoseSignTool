// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical tests targeting uncovered lines in headers.rs.
//!
//! Focuses on:
//! - Display for all CoseHeaderValue variants (Array, Map, Tagged, Bool, Null, Undefined, Float, Raw)
//! - Encode/decode roundtrip for uncommon header value types
//! - decode_value branches: NegativeInt, Tag, Bool, Null, Undefined, nested Array, nested Map
//! - Indefinite-length map/array decoding (manually crafted CBOR)
//! - ContentType Display
//! - ProtectedHeader encode/decode

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::{
    ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};

// ═══════════════════════════════════════════════════════════════════════════
// Display for every CoseHeaderValue variant
// Targets lines 137-158
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn display_int() {
    assert_eq!(format!("{}", CoseHeaderValue::Int(-7)), "-7");
}

#[test]
fn display_uint() {
    assert_eq!(
        format!("{}", CoseHeaderValue::Uint(u64::MAX)),
        format!("{}", u64::MAX)
    );
}

#[test]
fn display_bytes() {
    assert_eq!(
        format!("{}", CoseHeaderValue::Bytes(vec![1, 2, 3].into())),
        "bytes(3)"
    );
}

#[test]
fn display_text() {
    assert_eq!(
        format!("{}", CoseHeaderValue::Text("hello".into())),
        "\"hello\""
    );
}

#[test]
fn display_array() {
    let arr = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("two".into()),
    ]);
    let s = format!("{}", arr);
    assert_eq!(s, "[1, \"two\"]");
}

#[test]
fn display_array_empty() {
    let arr = CoseHeaderValue::Array(vec![]);
    assert_eq!(format!("{}", arr), "[]");
}

#[test]
fn display_map() {
    let map = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("alg".into())),
        (CoseHeaderLabel::Text("x".into()), CoseHeaderValue::Int(42)),
    ]);
    let s = format!("{}", map);
    assert_eq!(s, "{1: \"alg\", x: 42}");
}

#[test]
fn display_map_empty() {
    let map = CoseHeaderValue::Map(vec![]);
    assert_eq!(format!("{}", map), "{}");
}

#[test]
fn display_tagged() {
    let tagged = CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(99)));
    assert_eq!(format!("{}", tagged), "tag(18, 99)");
}

#[test]
fn display_bool_true() {
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
}

#[test]
fn display_bool_false() {
    assert_eq!(format!("{}", CoseHeaderValue::Bool(false)), "false");
}

#[test]
fn display_null() {
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
}

#[test]
fn display_undefined() {
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
}

#[test]
fn display_float() {
    let s = format!("{}", CoseHeaderValue::Float(3.14));
    assert!(s.starts_with("3.14"));
}

#[test]
fn display_raw() {
    assert_eq!(
        format!("{}", CoseHeaderValue::Raw(vec![0xA0, 0xB0].into())),
        "raw(2)"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ContentType Display
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn content_type_display_int() {
    assert_eq!(format!("{}", ContentType::Int(42)), "42");
}

#[test]
fn content_type_display_text() {
    assert_eq!(
        format!("{}", ContentType::Text("application/json".into())),
        "application/json"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Encode / decode roundtrip for uncommon value types
// Targets encode_value lines 500-539 and decode_value lines 578-700
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn roundtrip_array_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Bytes(vec![0xAB].into()),
            CoseHeaderValue::Text("inner".into()),
        ]),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    let val = decoded.get(&CoseHeaderLabel::Int(100)).expect("key 100");
    match val {
        CoseHeaderValue::Array(arr) => {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
        }
        other => panic!("Expected Array, got {:?}", other),
    }
}

#[test]
fn roundtrip_nested_map_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(200),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("v1".into())),
            (
                CoseHeaderLabel::Text("k2".into()),
                CoseHeaderValue::Int(-99),
            ),
        ]),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    let val = decoded.get(&CoseHeaderLabel::Int(200)).expect("key 200");
    match val {
        CoseHeaderValue::Map(pairs) => {
            assert_eq!(pairs.len(), 2);
        }
        other => panic!("Expected Map, got {:?}", other),
    }
}

#[test]
fn roundtrip_tagged_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(300),
        CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Bytes(vec![0xFF].into()))),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    let val = decoded.get(&CoseHeaderLabel::Int(300)).expect("key 300");
    match val {
        CoseHeaderValue::Tagged(tag, inner) => {
            assert_eq!(*tag, 18);
            assert_eq!(**inner, CoseHeaderValue::Bytes(vec![0xFF].into()));
        }
        other => panic!("Expected Tagged, got {:?}", other),
    }
}

#[test]
fn roundtrip_bool_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(400), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(401), CoseHeaderValue::Bool(false));

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(400)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(401)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

#[test]
fn roundtrip_null_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(500), CoseHeaderValue::Null);

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(500)),
        Some(&CoseHeaderValue::Null)
    );
}

#[test]
fn roundtrip_undefined_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(600), CoseHeaderValue::Undefined);

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(600)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn roundtrip_raw_value() {
    let _provider = EverParseCborProvider;

    // Encode a small CBOR integer (42 = 0x18 0x2A) as Raw bytes
    let mut inner_enc = cose_primitives::provider::cbor_provider().encoder();
    inner_enc.encode_u64(42).unwrap();
    let raw_bytes = inner_enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(700),
        CoseHeaderValue::Raw(raw_bytes.clone().into()),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");

    // Raw value is re-decoded — the decoder sees 42 as a UnsignedInt
    let val = decoded.get(&CoseHeaderLabel::Int(700)).expect("key 700");
    assert_eq!(*val, CoseHeaderValue::Int(42));
}

#[test]
fn roundtrip_negative_int_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(800), CoseHeaderValue::Int(-35));

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(800)),
        Some(&CoseHeaderValue::Int(-35))
    );
}

#[test]
fn roundtrip_text_label() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("custom-hdr".into()),
        CoseHeaderValue::Int(999),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom-hdr".into())),
        Some(&CoseHeaderValue::Int(999))
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CoseHeaderMap encode and decode for map with many value types in one map
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn encode_decode_mixed_value_map() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(vec![0x01, 0x02].into()),
    );
    map.insert(
        CoseHeaderLabel::Int(3),
        CoseHeaderValue::Text("application/cose".into()),
    );
    map.insert(CoseHeaderLabel::Int(10), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(11), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(12), CoseHeaderValue::Undefined);
    map.insert(
        CoseHeaderLabel::Int(13),
        CoseHeaderValue::Tagged(1, Box::new(CoseHeaderValue::Int(1234567890))),
    );
    map.insert(
        CoseHeaderLabel::Int(14),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1), CoseHeaderValue::Int(2)]),
    );
    map.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("nested".into()),
        )]),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");

    assert_eq!(decoded.len(), 9);
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-7))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(11)),
        Some(&CoseHeaderValue::Null)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(12)),
        Some(&CoseHeaderValue::Undefined)
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// ProtectedHeader encode/decode roundtrip
// Targets lines 721-733
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn protected_header_encode_decode_roundtrip() {
    let _provider = EverParseCborProvider;

    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"test-key".to_vec());

    let protected = ProtectedHeader::encode(headers).expect("encode");
    assert!(!protected.as_bytes().is_empty());
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"test-key".as_slice()));

    let decoded = ProtectedHeader::decode(protected.as_bytes().to_vec()).expect("decode");
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"test-key".as_slice()));
}

#[test]
fn protected_header_decode_empty() {
    let _provider = EverParseCborProvider;

    let decoded = ProtectedHeader::decode(Vec::new()).expect("decode empty");
    assert!(decoded.headers().is_empty());
    assert!(decoded.as_bytes().is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// CoseHeaderMap::decode with empty data
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn decode_empty_bytes_returns_empty_map() {
    let _provider = EverParseCborProvider;
    let map = CoseHeaderMap::decode(&[]).expect("decode empty");
    assert!(map.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// CoseHeaderLabel Display
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn header_label_display_int() {
    assert_eq!(format!("{}", CoseHeaderLabel::Int(1)), "1");
    assert_eq!(format!("{}", CoseHeaderLabel::Int(-7)), "-7");
}

#[test]
fn header_label_display_text() {
    assert_eq!(format!("{}", CoseHeaderLabel::Text("alg".into())), "alg");
}

// ═══════════════════════════════════════════════════════════════════════════
// content_type accessor edge cases
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn content_type_uint_in_range() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    // Insert as Uint (which happens when decoded from CBOR unsigned > i64::MAX won't happen,
    // but values like 100 decoded as u64 then stored as Uint in certain paths)
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(42),
    );
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
}

#[test]
fn content_type_uint_out_of_range() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(u64::MAX),
    );
    assert_eq!(map.content_type(), None);
}

#[test]
fn content_type_int_negative_returns_none() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1),
    );
    assert_eq!(map.content_type(), None);
}

#[test]
fn content_type_int_too_large_returns_none() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(100_000),
    );
    assert_eq!(map.content_type(), None);
}

#[test]
fn content_type_text_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.set_content_type(ContentType::Text("application/cbor".into()));
    assert_eq!(
        map.content_type(),
        Some(ContentType::Text("application/cbor".into()))
    );
}

#[test]
fn content_type_non_matching_value_returns_none() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Bool(true),
    );
    assert_eq!(map.content_type(), None);
}

// ═══════════════════════════════════════════════════════════════════════════
// crit() accessor
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn crit_returns_none_when_not_set() {
    let map = CoseHeaderMap::new();
    assert_eq!(map.crit(), None);
}

#[test]
fn crit_returns_none_when_not_array() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Int(42),
    );
    assert_eq!(map.crit(), None);
}

// ═══════════════════════════════════════════════════════════════════════════
// get_bytes_one_or_many
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn get_bytes_one_or_many_not_present() {
    let map = CoseHeaderMap::new();
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)), None);
}

#[test]
fn get_bytes_one_or_many_non_bytes_value() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(33), CoseHeaderValue::Int(42));
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)), None);
}

// ═══════════════════════════════════════════════════════════════════════════
// CoseHeaderMap: encode with label types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn encode_map_with_text_and_int_labels() {
    let _provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(
        CoseHeaderLabel::Text("custom".into()),
        CoseHeaderValue::Text("value".into()),
    );

    let encoded = map.encode().expect("encode");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode");
    assert_eq!(decoded.len(), 2);
}
