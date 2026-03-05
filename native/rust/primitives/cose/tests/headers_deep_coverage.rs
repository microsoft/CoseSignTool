// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for CoseHeaderMap and CoseHeaderValue:
//! encode/decode for every variant, Display for all variants,
//! map operations, merge, ProtectedHeader, and error paths.

use cose_primitives::{
    CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ContentType, CoseError, ProtectedHeader,
};

// ---------------------------------------------------------------------------
// CoseHeaderLabel — From impls and Display
// ---------------------------------------------------------------------------

#[test]
fn label_from_i64() {
    let l = CoseHeaderLabel::from(42i64);
    assert_eq!(l, CoseHeaderLabel::Int(42));
}

#[test]
fn label_from_negative_i64() {
    let l = CoseHeaderLabel::from(-1i64);
    assert_eq!(l, CoseHeaderLabel::Int(-1));
}

#[test]
fn label_from_str_ref() {
    let l = CoseHeaderLabel::from("custom");
    assert_eq!(l, CoseHeaderLabel::Text("custom".to_string()));
}

#[test]
fn label_from_string() {
    let l = CoseHeaderLabel::from("owned".to_string());
    assert_eq!(l, CoseHeaderLabel::Text("owned".to_string()));
}

#[test]
fn label_display_int() {
    let l = CoseHeaderLabel::Int(7);
    assert_eq!(format!("{}", l), "7");
}

#[test]
fn label_display_negative_int() {
    let l = CoseHeaderLabel::Int(-3);
    assert_eq!(format!("{}", l), "-3");
}

#[test]
fn label_display_text() {
    let l = CoseHeaderLabel::Text("hello".to_string());
    assert_eq!(format!("{}", l), "hello");
}

// ---------------------------------------------------------------------------
// CoseHeaderValue — From impls
// ---------------------------------------------------------------------------

#[test]
fn value_from_i64() {
    assert_eq!(CoseHeaderValue::from(10i64), CoseHeaderValue::Int(10));
}

#[test]
fn value_from_u64() {
    assert_eq!(CoseHeaderValue::from(20u64), CoseHeaderValue::Uint(20));
}

#[test]
fn value_from_vec_u8() {
    assert_eq!(
        CoseHeaderValue::from(vec![1u8, 2]),
        CoseHeaderValue::Bytes(vec![1, 2])
    );
}

#[test]
fn value_from_slice_u8() {
    assert_eq!(
        CoseHeaderValue::from(&[3u8, 4][..]),
        CoseHeaderValue::Bytes(vec![3, 4])
    );
}

#[test]
fn value_from_string() {
    assert_eq!(
        CoseHeaderValue::from("s".to_string()),
        CoseHeaderValue::Text("s".to_string())
    );
}

#[test]
fn value_from_str_ref() {
    assert_eq!(
        CoseHeaderValue::from("r"),
        CoseHeaderValue::Text("r".to_string())
    );
}

#[test]
fn value_from_bool() {
    assert_eq!(CoseHeaderValue::from(true), CoseHeaderValue::Bool(true));
    assert_eq!(CoseHeaderValue::from(false), CoseHeaderValue::Bool(false));
}

// ---------------------------------------------------------------------------
// CoseHeaderValue — Display for every variant
// ---------------------------------------------------------------------------

#[test]
fn display_int() {
    assert_eq!(format!("{}", CoseHeaderValue::Int(42)), "42");
}

#[test]
fn display_int_negative() {
    assert_eq!(format!("{}", CoseHeaderValue::Int(-5)), "-5");
}

#[test]
fn display_uint() {
    assert_eq!(format!("{}", CoseHeaderValue::Uint(999)), "999");
}

#[test]
fn display_bytes() {
    let v = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    assert_eq!(format!("{}", v), "bytes(3)");
}

#[test]
fn display_bytes_empty() {
    assert_eq!(format!("{}", CoseHeaderValue::Bytes(vec![])), "bytes(0)");
}

#[test]
fn display_text() {
    assert_eq!(
        format!("{}", CoseHeaderValue::Text("abc".to_string())),
        "\"abc\""
    );
}

#[test]
fn display_array_empty() {
    assert_eq!(format!("{}", CoseHeaderValue::Array(vec![])), "[]");
}

#[test]
fn display_array_single() {
    let arr = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]);
    assert_eq!(format!("{}", arr), "[1]");
}

#[test]
fn display_array_multiple() {
    let arr = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("x".to_string()),
        CoseHeaderValue::Bool(true),
    ]);
    assert_eq!(format!("{}", arr), "[1, \"x\", true]");
}

#[test]
fn display_map_empty() {
    assert_eq!(format!("{}", CoseHeaderValue::Map(vec![])), "{}");
}

#[test]
fn display_map_single() {
    let m = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Text("v".to_string()),
    )]);
    assert_eq!(format!("{}", m), "{1: \"v\"}");
}

#[test]
fn display_map_multiple() {
    let m = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10)),
        (
            CoseHeaderLabel::Text("k".to_string()),
            CoseHeaderValue::Bool(false),
        ),
    ]);
    assert_eq!(format!("{}", m), "{1: 10, k: false}");
}

#[test]
fn display_tagged() {
    let t = CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(0)));
    assert_eq!(format!("{}", t), "tag(18, 0)");
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
    let s = format!("{}", CoseHeaderValue::Float(1.5));
    assert_eq!(s, "1.5");
}

#[test]
fn display_raw() {
    let r = CoseHeaderValue::Raw(vec![0xAA, 0xBB]);
    assert_eq!(format!("{}", r), "raw(2)");
}

// ---------------------------------------------------------------------------
// CoseHeaderValue — accessor helpers
// ---------------------------------------------------------------------------

#[test]
fn as_bytes_returns_some_for_bytes() {
    let v = CoseHeaderValue::Bytes(vec![1, 2]);
    assert_eq!(v.as_bytes(), Some([1u8, 2].as_slice()));
}

#[test]
fn as_bytes_returns_none_for_non_bytes() {
    assert!(CoseHeaderValue::Int(1).as_bytes().is_none());
    assert!(CoseHeaderValue::Text("x".to_string()).as_bytes().is_none());
}

#[test]
fn as_i64_returns_some() {
    assert_eq!(CoseHeaderValue::Int(7).as_i64(), Some(7));
}

#[test]
fn as_i64_returns_none_for_non_int() {
    assert!(CoseHeaderValue::Text("x".to_string()).as_i64().is_none());
}

#[test]
fn as_str_returns_some() {
    let v = CoseHeaderValue::Text("abc".to_string());
    assert_eq!(v.as_str(), Some("abc"));
}

#[test]
fn as_str_returns_none_for_non_text() {
    assert!(CoseHeaderValue::Int(1).as_str().is_none());
}

#[test]
fn as_bytes_one_or_many_single_bstr() {
    let v = CoseHeaderValue::Bytes(vec![1, 2]);
    assert_eq!(v.as_bytes_one_or_many(), Some(vec![vec![1u8, 2]]));
}

#[test]
fn as_bytes_one_or_many_array_of_bstr() {
    let v = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![0xAA]),
        CoseHeaderValue::Bytes(vec![0xBB]),
    ]);
    assert_eq!(
        v.as_bytes_one_or_many(),
        Some(vec![vec![0xAA], vec![0xBB]])
    );
}

#[test]
fn as_bytes_one_or_many_empty_array() {
    let v = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]);
    // Array with no Bytes elements -> None (empty result vec)
    assert_eq!(v.as_bytes_one_or_many(), None);
}

#[test]
fn as_bytes_one_or_many_non_bytes_or_array() {
    assert!(CoseHeaderValue::Int(1).as_bytes_one_or_many().is_none());
}

// ---------------------------------------------------------------------------
// ContentType — Display
// ---------------------------------------------------------------------------

#[test]
fn content_type_display_int() {
    assert_eq!(format!("{}", ContentType::Int(42)), "42");
}

#[test]
fn content_type_display_text() {
    assert_eq!(
        format!("{}", ContentType::Text("application/json".to_string())),
        "application/json"
    );
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — basic operations
// ---------------------------------------------------------------------------

#[test]
fn map_new_is_empty() {
    let m = CoseHeaderMap::new();
    assert!(m.is_empty());
    assert_eq!(m.len(), 0);
}

#[test]
fn map_insert_get_remove() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10));
    assert_eq!(m.len(), 1);
    assert!(!m.is_empty());
    assert_eq!(
        m.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(10))
    );
    let removed = m.remove(&CoseHeaderLabel::Int(1));
    assert_eq!(removed, Some(CoseHeaderValue::Int(10)));
    assert!(m.is_empty());
}

#[test]
fn map_get_missing_returns_none() {
    let m = CoseHeaderMap::new();
    assert!(m.get(&CoseHeaderLabel::Int(999)).is_none());
}

#[test]
fn map_remove_missing_returns_none() {
    let mut m = CoseHeaderMap::new();
    assert!(m.remove(&CoseHeaderLabel::Int(999)).is_none());
}

#[test]
fn map_iter() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10));
    m.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Int(20));
    let collected: Vec<_> = m.iter().collect();
    assert_eq!(collected.len(), 2);
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — well-known header getters/setters
// ---------------------------------------------------------------------------

#[test]
fn map_alg_set_get() {
    let mut m = CoseHeaderMap::new();
    assert!(m.alg().is_none());
    m.set_alg(-7);
    assert_eq!(m.alg(), Some(-7));
}

#[test]
fn map_kid_set_get() {
    let mut m = CoseHeaderMap::new();
    assert!(m.kid().is_none());
    m.set_kid(vec![0x01, 0x02]);
    assert_eq!(m.kid(), Some([0x01u8, 0x02].as_slice()));
}

#[test]
fn map_content_type_int() {
    let mut m = CoseHeaderMap::new();
    m.set_content_type(ContentType::Int(42));
    assert_eq!(m.content_type(), Some(ContentType::Int(42)));
}

#[test]
fn map_content_type_text() {
    let mut m = CoseHeaderMap::new();
    m.set_content_type(ContentType::Text("application/cbor".to_string()));
    assert_eq!(
        m.content_type(),
        Some(ContentType::Text("application/cbor".to_string()))
    );
}

#[test]
fn map_content_type_uint_in_range() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(100),
    );
    assert_eq!(m.content_type(), Some(ContentType::Int(100)));
}

#[test]
fn map_content_type_uint_out_of_range() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(u64::MAX),
    );
    assert!(m.content_type().is_none());
}

#[test]
fn map_content_type_int_out_of_range() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(i64::MAX),
    );
    assert!(m.content_type().is_none());
}

#[test]
fn map_content_type_wrong_type() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Bool(true),
    );
    assert!(m.content_type().is_none());
}

#[test]
fn map_crit_roundtrip() {
    let mut m = CoseHeaderMap::new();
    assert!(m.crit().is_none());
    m.set_crit(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("x".to_string()),
    ]);
    let labels = m.crit().unwrap();
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0], CoseHeaderLabel::Int(1));
    assert_eq!(labels[1], CoseHeaderLabel::Text("x".to_string()));
}

#[test]
fn map_crit_not_array_returns_none() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Int(99),
    );
    assert!(m.crit().is_none());
}

#[test]
fn map_get_bytes_one_or_many() {
    let mut m = CoseHeaderMap::new();
    let label = CoseHeaderLabel::Int(33);
    m.insert(label.clone(), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    let result = m.get_bytes_one_or_many(&label);
    assert_eq!(result, Some(vec![vec![1u8, 2, 3]]));
}

#[test]
fn map_get_bytes_one_or_many_missing() {
    let m = CoseHeaderMap::new();
    assert!(m.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)).is_none());
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — encode/decode roundtrip: basic types
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_empty_map() {
    let m = CoseHeaderMap::new();
    let bytes = m.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn decode_empty_slice() {
    let decoded = CoseHeaderMap::decode(&[]).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn encode_decode_int_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
}

#[test]
fn encode_decode_uint_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Uint(u64::MAX));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Uint(u64::MAX)));
}

#[test]
fn encode_decode_positive_uint_fits_i64() {
    let mut m = CoseHeaderMap::new();
    // Uint that fits in i64 should decode as Int
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Uint(100));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    // When decoding, UnsignedInt <= i64::MAX becomes Int
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(100)));
}

#[test]
fn encode_decode_bytes_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(vec![0xDE, 0xAD]),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(4)),
        Some(&CoseHeaderValue::Bytes(vec![0xDE, 0xAD]))
    );
}

#[test]
fn encode_decode_text_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(3),
        CoseHeaderValue::Text("application/json".to_string()),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(3)),
        Some(&CoseHeaderValue::Text("application/json".to_string()))
    );
}

#[test]
fn encode_decode_bool_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(10), CoseHeaderValue::Bool(true));
    m.insert(CoseHeaderLabel::Int(11), CoseHeaderValue::Bool(false));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(10)), Some(&CoseHeaderValue::Bool(true)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(11)), Some(&CoseHeaderValue::Bool(false)));
}

#[test]
fn encode_decode_null_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(20), CoseHeaderValue::Null);
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(20)), Some(&CoseHeaderValue::Null));
}

#[test]
fn encode_decode_undefined_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(21), CoseHeaderValue::Undefined);
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(21)), Some(&CoseHeaderValue::Undefined));
}

#[test]
fn encode_decode_tagged_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(30),
        CoseHeaderValue::Tagged(1, Box::new(CoseHeaderValue::Int(1234))),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(30)),
        Some(&CoseHeaderValue::Tagged(1, Box::new(CoseHeaderValue::Int(1234))))
    );
}

#[test]
fn encode_decode_raw_value() {
    // Raw embeds pre-encoded CBOR. Encode an integer 42 (0x18 0x2a) as raw.
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(40),
        CoseHeaderValue::Raw(vec![0x18, 0x2a]),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    // Raw bytes decode as the underlying CBOR type, which is Int(42)
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(40)), Some(&CoseHeaderValue::Int(42)));
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — encode/decode: nested Array
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_array_of_ints() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(50),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Int(2),
            CoseHeaderValue::Int(3),
        ]),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    let arr = decoded.get(&CoseHeaderLabel::Int(50)).unwrap();
    if let CoseHeaderValue::Array(items) = arr {
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], CoseHeaderValue::Int(1));
    } else {
        panic!("expected array");
    }
}

#[test]
fn encode_decode_array_of_mixed_types() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(51),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(10),
            CoseHeaderValue::Text("hello".to_string()),
            CoseHeaderValue::Bytes(vec![0xFF]),
            CoseHeaderValue::Bool(true),
            CoseHeaderValue::Null,
        ]),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    let arr = decoded.get(&CoseHeaderLabel::Int(51)).unwrap();
    if let CoseHeaderValue::Array(items) = arr {
        assert_eq!(items.len(), 5);
    } else {
        panic!("expected array");
    }
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — encode/decode: nested Map
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_nested_map() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Int(60),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(100)),
            (
                CoseHeaderLabel::Text("key".to_string()),
                CoseHeaderValue::Text("val".to_string()),
            ),
        ]),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    let inner = decoded.get(&CoseHeaderLabel::Int(60)).unwrap();
    if let CoseHeaderValue::Map(pairs) = inner {
        assert_eq!(pairs.len(), 2);
    } else {
        panic!("expected map");
    }
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — text string labels
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_text_label() {
    let mut m = CoseHeaderMap::new();
    m.insert(
        CoseHeaderLabel::Text("custom-header".to_string()),
        CoseHeaderValue::Int(999),
    );
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom-header".to_string())),
        Some(&CoseHeaderValue::Int(999))
    );
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — large integers (> 23, which need 2-byte CBOR encoding)
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_large_int_label() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1000), CoseHeaderValue::Int(0));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1000)), Some(&CoseHeaderValue::Int(0)));
}

#[test]
fn encode_decode_large_positive_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(100_000));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(100_000)));
}

#[test]
fn encode_decode_large_negative_value() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-100_000));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-100_000)));
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — decode invalid CBOR
// ---------------------------------------------------------------------------

#[test]
fn decode_invalid_cbor_returns_error() {
    let bad = vec![0xFF]; // break code without context
    let result = CoseHeaderMap::decode(&bad);
    assert!(result.is_err());
}

#[test]
fn decode_non_map_cbor_returns_error() {
    let non_map = vec![0x01]; // unsigned int 1
    let result = CoseHeaderMap::decode(&non_map);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — negative int label
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_negative_int_label() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(-1), CoseHeaderValue::Text("neg".to_string()));
    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(-1)),
        Some(&CoseHeaderValue::Text("neg".to_string()))
    );
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — multiple entries roundtrip
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_multiple_entries() {
    let mut m = CoseHeaderMap::new();
    m.set_alg(-7);
    m.set_kid(b"my-key-id".to_vec());
    m.set_content_type(ContentType::Text("application/cose".to_string()));
    m.insert(
        CoseHeaderLabel::Text("extra".to_string()),
        CoseHeaderValue::Bool(true),
    );

    let bytes = m.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&bytes).unwrap();

    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"my-key-id".as_slice()));
    assert_eq!(
        decoded.content_type(),
        Some(ContentType::Text("application/cose".to_string()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("extra".to_string())),
        Some(&CoseHeaderValue::Bool(true))
    );
}

// ---------------------------------------------------------------------------
// ProtectedHeader
// ---------------------------------------------------------------------------

#[test]
fn protected_header_encode_decode_roundtrip() {
    let mut m = CoseHeaderMap::new();
    m.set_alg(-7);
    m.set_kid(b"kid1".to_vec());

    let ph = ProtectedHeader::encode(m).unwrap();
    assert!(!ph.is_empty());
    assert!(!ph.as_bytes().is_empty());
    assert_eq!(ph.alg(), Some(-7));
    assert_eq!(ph.kid(), Some(b"kid1".as_slice()));

    let decoded = ProtectedHeader::decode(ph.as_bytes().to_vec()).unwrap();
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"kid1".as_slice()));
}

#[test]
fn protected_header_decode_empty() {
    let ph = ProtectedHeader::decode(vec![]).unwrap();
    assert!(ph.is_empty());
    assert!(ph.alg().is_none());
}

#[test]
fn protected_header_default() {
    let ph = ProtectedHeader::default();
    assert!(ph.is_empty());
    assert_eq!(ph.as_bytes().len(), 0);
}

#[test]
fn protected_header_get() {
    let mut m = CoseHeaderMap::new();
    m.insert(CoseHeaderLabel::Int(99), CoseHeaderValue::Text("val".to_string()));
    let ph = ProtectedHeader::encode(m).unwrap();
    assert_eq!(
        ph.get(&CoseHeaderLabel::Int(99)),
        Some(&CoseHeaderValue::Text("val".to_string()))
    );
    assert!(ph.get(&CoseHeaderLabel::Int(100)).is_none());
}

#[test]
fn protected_header_content_type() {
    let mut m = CoseHeaderMap::new();
    m.set_content_type(ContentType::Int(50));
    let ph = ProtectedHeader::encode(m).unwrap();
    assert_eq!(ph.content_type(), Some(ContentType::Int(50)));
}

#[test]
fn protected_header_headers_and_headers_mut() {
    let mut m = CoseHeaderMap::new();
    m.set_alg(-35);
    let mut ph = ProtectedHeader::encode(m).unwrap();

    assert_eq!(ph.headers().alg(), Some(-35));

    ph.headers_mut().set_alg(-7);
    assert_eq!(ph.headers().alg(), Some(-7));
}

// ---------------------------------------------------------------------------
// CoseError — Display and Error trait
// ---------------------------------------------------------------------------

#[test]
fn cose_error_display_cbor() {
    let e = CoseError::CborError("bad cbor".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("CBOR error"));
    assert!(msg.contains("bad cbor"));
}

#[test]
fn cose_error_display_invalid_message() {
    let e = CoseError::InvalidMessage("bad msg".to_string());
    let msg = format!("{}", e);
    assert!(msg.contains("invalid message"));
    assert!(msg.contains("bad msg"));
}

#[test]
fn cose_error_is_std_error() {
    let e = CoseError::CborError("x".to_string());
    let _: &dyn std::error::Error = &e;
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — complex nested structure roundtrip
// ---------------------------------------------------------------------------

#[test]
fn encode_decode_deeply_nested_structure() {
    let mut m = CoseHeaderMap::new();
    // Array containing a map containing an array
    let inner_array = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1), CoseHeaderValue::Int(2)]);
    let inner_map = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(99),
        inner_array,
    )]);
    let outer_array = CoseHeaderValue::Array(vec![inner_map, CoseHeaderValue::Text("end".to_string())]);
    m.insert(CoseHeaderLabel::Int(70), outer_array);

    let decoded = CoseHeaderMap::decode(&m.encode().unwrap()).unwrap();
    let val = decoded.get(&CoseHeaderLabel::Int(70)).unwrap();
    if let CoseHeaderValue::Array(items) = val {
        assert_eq!(items.len(), 2);
        if let CoseHeaderValue::Map(pairs) = &items[0] {
            assert_eq!(pairs.len(), 1);
        } else {
            panic!("expected nested map");
        }
    } else {
        panic!("expected outer array");
    }
}

// ---------------------------------------------------------------------------
// CoseHeaderMap — Clone and Debug
// ---------------------------------------------------------------------------

#[test]
fn header_map_clone_and_debug() {
    let mut m = CoseHeaderMap::new();
    m.set_alg(-7);
    let cloned = m.clone();
    assert_eq!(cloned.alg(), Some(-7));

    let dbg = format!("{:?}", m);
    assert!(dbg.contains("headers"));
}

// ---------------------------------------------------------------------------
// CoseHeaderLabel — Clone, Debug, PartialEq, Eq, Hash, Ord
// ---------------------------------------------------------------------------

#[test]
fn header_label_clone_debug_eq() {
    let l1 = CoseHeaderLabel::Int(5);
    let l2 = l1.clone();
    assert_eq!(l1, l2);
    let dbg = format!("{:?}", l1);
    assert!(dbg.contains("Int"));
    assert!(dbg.contains("5"));
}

#[test]
fn header_label_ordering() {
    let a = CoseHeaderLabel::Int(-1);
    let b = CoseHeaderLabel::Int(1);
    let c = CoseHeaderLabel::Text("z".to_string());
    assert!(a < b);
    assert!(b < c);
}

// ---------------------------------------------------------------------------
// CoseHeaderValue — Clone, Debug, PartialEq
// ---------------------------------------------------------------------------

#[test]
fn header_value_clone_debug_eq() {
    let v = CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Null));
    let vc = v.clone();
    assert_eq!(v, vc);
    let dbg = format!("{:?}", v);
    assert!(dbg.contains("Tagged"));
}

// ---------------------------------------------------------------------------
// CoseHeaderMap constants
// ---------------------------------------------------------------------------

#[test]
fn header_map_constants() {
    assert_eq!(CoseHeaderMap::ALG, 1);
    assert_eq!(CoseHeaderMap::CRIT, 2);
    assert_eq!(CoseHeaderMap::CONTENT_TYPE, 3);
    assert_eq!(CoseHeaderMap::KID, 4);
    assert_eq!(CoseHeaderMap::IV, 5);
    assert_eq!(CoseHeaderMap::PARTIAL_IV, 6);
}
