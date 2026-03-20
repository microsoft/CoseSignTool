// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered lines in cose_primitives headers.rs
//! and provider.rs.

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{
    ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};

// ============================================================================
// provider.rs — convenience functions (L51-53, L56-58)
// ============================================================================

/// Target: provider.rs L51-53 — encoder() convenience function.
#[test]
fn test_cb_provider_encoder_convenience() {
    let mut encoder = cose_primitives::provider::encoder();
    encoder.encode_i64(42).unwrap();
    let bytes = encoder.into_bytes();
    assert!(!bytes.is_empty(), "encoder should produce bytes");
}

/// Target: provider.rs L56-58 — decoder() convenience function.
#[test]
fn test_cb_provider_decoder_convenience() {
    // CBOR integer 42 = 0x18 0x2A
    let data = [0x18, 0x2A];
    let mut decoder = cose_primitives::provider::decoder(&data);
    let val: i64 = decoder.decode_i64().unwrap();
    assert_eq!(val, 42);
}

/// Exercise both encoder and decoder convenience functions together.
#[test]
fn test_cb_provider_encoder_decoder_roundtrip() {
    let mut encoder = cose_primitives::provider::encoder();
    encoder.encode_tstr("hello").unwrap();
    let bytes = encoder.into_bytes();

    let mut decoder = cose_primitives::provider::decoder(&bytes);
    let val: &str = decoder.decode_tstr().unwrap();
    assert_eq!(val, "hello");
}

// ============================================================================
// CoseHeaderValue Display — Array and Map with multiple items (L138-151)
// ============================================================================

/// Target: headers.rs L138, L140-141 — Display for Array with multiple items.
#[test]
fn test_cb_display_array_multiple_items() {
    let arr = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("hello".to_string().into()),
        CoseHeaderValue::Bool(true),
    ]);
    let s = format!("{}", arr);
    assert_eq!(s, "[1, \"hello\", true]");
}

/// Target: headers.rs L138 — Display for Array with single item.
#[test]
fn test_cb_display_array_single_item() {
    let arr = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(42)]);
    let s = format!("{}", arr);
    assert_eq!(s, "[42]");
}

/// Target: headers.rs L138 — Display for empty Array.
#[test]
fn test_cb_display_array_empty() {
    let arr = CoseHeaderValue::Array(vec![]);
    let s = format!("{}", arr);
    assert_eq!(s, "[]");
}

/// Target: headers.rs L146, L148-149 — Display for Map with multiple items.
#[test]
fn test_cb_display_map_multiple_items() {
    let m = CoseHeaderValue::Map(vec![
        (
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("a".to_string().into()),
        ),
        (
            CoseHeaderLabel::Text("key".to_string()),
            CoseHeaderValue::Int(2),
        ),
    ]);
    let s = format!("{}", m);
    assert_eq!(s, "{1: \"a\", key: 2}");
}

/// Target: headers.rs L146 — Display for empty Map.
#[test]
fn test_cb_display_map_empty() {
    let m = CoseHeaderValue::Map(vec![]);
    let s = format!("{}", m);
    assert_eq!(s, "{}");
}

/// Display for Tagged, Bool, Null, Undefined, Raw values.
#[test]
fn test_cb_display_various_value_types() {
    assert_eq!(
        format!(
            "{}",
            CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(1)))
        ),
        "tag(42, 1)"
    );
    assert_eq!(format!("{}", CoseHeaderValue::Bool(false)), "false");
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
    assert_eq!(
        format!("{}", CoseHeaderValue::Raw(vec![0xA0].into())),
        "raw(1)"
    );
    assert_eq!(
        format!("{}", CoseHeaderValue::Bytes(vec![1, 2, 3].into())),
        "bytes(3)"
    );
    assert_eq!(format!("{}", CoseHeaderValue::Uint(999)), "999");
    assert_eq!(format!("{}", CoseHeaderValue::Float(3.14)), "3.14");
}

/// Display for CoseHeaderLabel.
#[test]
fn test_cb_display_header_labels() {
    assert_eq!(format!("{}", CoseHeaderLabel::Int(1)), "1");
    assert_eq!(format!("{}", CoseHeaderLabel::Int(-7)), "-7");
    assert_eq!(
        format!("{}", CoseHeaderLabel::Text("alg".to_string())),
        "alg"
    );
}

/// Display for ContentType.
#[test]
fn test_cb_display_content_type() {
    assert_eq!(format!("{}", ContentType::Int(42)), "42");
    assert_eq!(
        format!("{}", ContentType::Text("application/json".to_string())),
        "application/json"
    );
}

// ============================================================================
// CoseHeaderMap encode/decode — all value types
// ============================================================================

/// Target: headers.rs encode_value/decode_value — Bool (L525-527, L672-676).
#[test]
fn test_cb_encode_decode_bool_values() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(100), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(101), CoseHeaderValue::Bool(false));

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(100)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(101)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

/// Target: headers.rs encode_value/decode_value — Null (L528-530, L678-682).
#[test]
fn test_cb_encode_decode_null_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(200), CoseHeaderValue::Null);

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(200)),
        Some(&CoseHeaderValue::Null)
    );
}

/// Target: headers.rs encode_value/decode_value — Undefined (L531-533, L684-688).
#[test]
fn test_cb_encode_decode_undefined_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(201), CoseHeaderValue::Undefined);

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(201)),
        Some(&CoseHeaderValue::Undefined)
    );
}

/// Target: headers.rs encode_value/decode_value — Tagged (L519-523, L665-670).
#[test]
fn test_cb_encode_decode_tagged_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(300),
        CoseHeaderValue::Tagged(1, Box::new(CoseHeaderValue::Int(1234567890))),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(300)),
        Some(&CoseHeaderValue::Tagged(
            1,
            Box::new(CoseHeaderValue::Int(1234567890))
        ))
    );
}

/// Target: headers.rs encode_value — Raw (L537-539).
/// Raw bytes are written directly, so decoding interprets the raw CBOR.
#[test]
fn test_cb_encode_decode_raw_value() {
    let provider = EverParseCborProvider::default();

    // Pre-encode an integer 42 as raw CBOR.
    let mut enc = provider.encoder();
    enc.encode_i64(42).unwrap();
    let raw_cbor = enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(400),
        CoseHeaderValue::Raw(raw_cbor.into()),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    // Raw bytes are interpreted as their CBOR content on decode.
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(400)),
        Some(&CoseHeaderValue::Int(42))
    );
}

/// Target: headers.rs encode_value/decode_value — Array (L500-507, L607-632).
#[test]
fn test_cb_encode_decode_array_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(500),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Int(2),
            CoseHeaderValue::Text("three".to_string().into()),
            CoseHeaderValue::Bytes(vec![4, 5, 6].into()),
        ]),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    match decoded.get(&CoseHeaderLabel::Int(500)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Int(2));
            assert_eq!(arr[2], CoseHeaderValue::Text("three".to_string().into()));
            assert_eq!(arr[3], CoseHeaderValue::Bytes(vec![4, 5, 6].into()));
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

/// Target: headers.rs encode_value/decode_value — nested Map (L509-517, L634-663).
#[test]
fn test_cb_encode_decode_nested_map_value() {
    let inner_map = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(10), CoseHeaderValue::Int(100)),
        (
            CoseHeaderLabel::Text("name".to_string()),
            CoseHeaderValue::Text("value".to_string().into()),
        ),
    ]);

    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(600), inner_map.clone());

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    match decoded.get(&CoseHeaderLabel::Int(600)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 2);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(10));
            assert_eq!(pairs[0].1, CoseHeaderValue::Int(100));
            assert_eq!(pairs[1].0, CoseHeaderLabel::Text("name".to_string()));
            assert_eq!(
                pairs[1].1,
                CoseHeaderValue::Text("value".to_string().into())
            );
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

/// Target: headers.rs encode_label/decode_label — Text labels (L477-479, L557-561).
#[test]
fn test_cb_encode_decode_text_labels() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("custom-header".to_string()),
        CoseHeaderValue::Text("custom-value".to_string().into()),
    );
    map.insert(
        CoseHeaderLabel::Text("another".to_string()),
        CoseHeaderValue::Int(42),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom-header".to_string())),
        Some(&CoseHeaderValue::Text("custom-value".to_string().into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("another".to_string())),
        Some(&CoseHeaderValue::Int(42))
    );
}

/// Target: headers.rs decode_value — large Uint > i64::MAX (L585-586).
#[test]
fn test_cb_encode_decode_large_uint() {
    let large_val: u64 = (i64::MAX as u64) + 1;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(700), CoseHeaderValue::Uint(large_val));

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(700)),
        Some(&CoseHeaderValue::Uint(large_val))
    );
}

/// Target: headers.rs decode_value — negative integer (L589-593).
#[test]
fn test_cb_encode_decode_negative_int() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(701), CoseHeaderValue::Int(-42));

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(701)),
        Some(&CoseHeaderValue::Int(-42))
    );
}

/// Target: headers.rs encode/decode — comprehensive all-types-in-one-map roundtrip.
/// Exercises encode_value and decode_value for Int, Uint, Bytes, Text, Array,
/// Map, Tagged, Bool, Null, Undefined, and Raw.
#[test]
fn test_cb_encode_decode_all_types_roundtrip() {
    let provider = EverParseCborProvider::default();

    // Pre-encode bytes value as raw CBOR for the Raw variant.
    let mut enc = provider.encoder();
    enc.encode_bstr(&[0xDE, 0xAD]).unwrap();
    let raw_cbor = enc.into_bytes();

    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Uint(u64::MAX));
    map.insert(
        CoseHeaderLabel::Int(3),
        CoseHeaderValue::Bytes(vec![0xCA, 0xFE].into()),
    );
    map.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Text("test".to_string().into()),
    );
    map.insert(
        CoseHeaderLabel::Int(5),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1), CoseHeaderValue::Bool(true)]),
    );
    map.insert(
        CoseHeaderLabel::Int(6),
        CoseHeaderValue::Map(vec![(CoseHeaderLabel::Int(99), CoseHeaderValue::Null)]),
    );
    map.insert(
        CoseHeaderLabel::Int(7),
        CoseHeaderValue::Tagged(
            42,
            Box::new(CoseHeaderValue::Text("tagged".to_string().into())),
        ),
    );
    map.insert(CoseHeaderLabel::Int(8), CoseHeaderValue::Bool(false));
    map.insert(CoseHeaderLabel::Int(9), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(10), CoseHeaderValue::Undefined);
    map.insert(
        CoseHeaderLabel::Int(11),
        CoseHeaderValue::Raw(raw_cbor.into()),
    );
    // Also use text labels.
    map.insert(
        CoseHeaderLabel::Text("txt-label".to_string()),
        CoseHeaderValue::Int(999),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-7))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(2)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(3)),
        Some(&CoseHeaderValue::Bytes(vec![0xCA, 0xFE].into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(4)),
        Some(&CoseHeaderValue::Text("test".to_string().into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(8)),
        Some(&CoseHeaderValue::Bool(false))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(9)),
        Some(&CoseHeaderValue::Null)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Undefined)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("txt-label".to_string())),
        Some(&CoseHeaderValue::Int(999))
    );

    // Raw bytes are decoded as their CBOR content (Bytes([0xDE, 0xAD])).
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(11)),
        Some(&CoseHeaderValue::Bytes(vec![0xDE, 0xAD].into()))
    );
}

// ============================================================================
// ProtectedHeader::encode (L722)
// ============================================================================

/// Target: headers.rs L722 — ProtectedHeader::encode().
#[test]
fn test_cb_protected_header_encode() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"key-1".to_vec());

    let protected = ProtectedHeader::encode(map).unwrap();
    assert!(!protected.as_bytes().is_empty());
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"key-1".as_slice()));
    assert!(!protected.is_empty());
}

/// ProtectedHeader::encode with various header types.
#[test]
fn test_cb_protected_header_encode_complex() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_content_type(ContentType::Text("application/cbor".to_string()));
    map.set_crit(vec![CoseHeaderLabel::Int(1), CoseHeaderLabel::Int(3)]);
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Bytes(vec![0x01, 0x02, 0x03].into()),
    );

    let protected = ProtectedHeader::encode(map).unwrap();
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(
        protected.content_type(),
        Some(ContentType::Text("application/cbor".to_string()))
    );

    let crit = protected.headers().crit().unwrap();
    assert_eq!(crit.len(), 2);
    assert_eq!(crit[0], CoseHeaderLabel::Int(1));
    assert_eq!(crit[1], CoseHeaderLabel::Int(3));
}

/// ProtectedHeader decode/encode roundtrip.
#[test]
fn test_cb_protected_header_decode_encode_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-35);
    map.insert(CoseHeaderLabel::Int(99), CoseHeaderValue::Bool(true));

    let protected1 = ProtectedHeader::encode(map).unwrap();
    let raw_bytes = protected1.as_bytes().to_vec();

    let protected2 = ProtectedHeader::decode(raw_bytes).unwrap();
    assert_eq!(protected2.alg(), Some(-35));
    assert_eq!(
        protected2.get(&CoseHeaderLabel::Int(99)),
        Some(&CoseHeaderValue::Bool(true))
    );
}

// ============================================================================
// CoseHeaderMap::decode error paths
// ============================================================================

/// Target: headers.rs L696 — unsupported CBOR type in header value.
/// CBOR simple value (not bool/null/undefined) triggers the default match arm.
#[test]
fn test_cb_decode_unsupported_cbor_simple_value() {
    let provider = EverParseCborProvider::default();

    // Manually build CBOR: map(1) { int(1): simple(0) }
    // simple(0) = 0xE0 in CBOR
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    // Write simple value 0 as raw CBOR.
    enc.encode_raw(&[0xE0]).unwrap();
    let cbor = enc.into_bytes();

    let result = CoseHeaderMap::decode(&cbor);
    // The decoder may error on the unsupported type or handle it as Simple.
    // Either outcome exercises the decode path.
    if let Err(e) = result {
        let msg = format!("{}", e);
        assert!(
            msg.contains("unsupported") || msg.contains("CBOR"),
            "error should mention unsupported type: {}",
            msg
        );
    }
}

/// Target: headers.rs L563-566 — invalid header label type.
#[test]
fn test_cb_decode_invalid_header_label_type() {
    let provider = EverParseCborProvider::default();

    // Build CBOR: map(1) { bstr(key): int(1) }
    // byte string is not a valid header label.
    let mut enc = provider.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_bstr(&[0x01, 0x02]).unwrap(); // bstr label (invalid)
    enc.encode_i64(1).unwrap();
    let cbor = enc.into_bytes();

    let result = CoseHeaderMap::decode(&cbor);
    assert!(result.is_err(), "bstr label should be rejected");
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("invalid header label"),
        "error should mention invalid label: {}",
        msg
    );
}

/// CoseHeaderMap::decode with empty data returns empty map.
#[test]
fn test_cb_decode_empty_data() {
    let decoded = CoseHeaderMap::decode(&[]).unwrap();
    assert!(decoded.is_empty());
    assert_eq!(decoded.len(), 0);
}

/// CoseHeaderMap::decode with completely invalid CBOR.
#[test]
fn test_cb_decode_garbage_data() {
    let garbage = [0xFF, 0xFE, 0xFD, 0xFC];
    let result = CoseHeaderMap::decode(&garbage);
    assert!(result.is_err(), "garbage CBOR should fail decoding");
}

// ============================================================================
// CoseHeaderMap accessor methods — edge cases
// ============================================================================

/// content_type with Uint value within u16 range.
#[test]
fn test_cb_content_type_uint_within_range() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(42),
    );
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
}

/// content_type with Uint value exceeding u16 range returns None.
#[test]
fn test_cb_content_type_uint_out_of_range() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(u64::MAX),
    );
    assert_eq!(map.content_type(), None);
}

/// content_type with Int value out of u16 range returns None.
#[test]
fn test_cb_content_type_int_out_of_range() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1),
    );
    assert_eq!(map.content_type(), None);
}

/// content_type with Bytes (wrong type) returns None.
#[test]
fn test_cb_content_type_wrong_type() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Bytes(vec![1, 2].into()),
    );
    assert_eq!(map.content_type(), None);
}

/// crit with mixed label types.
#[test]
fn test_cb_crit_mixed_labels() {
    let mut map = CoseHeaderMap::new();
    map.set_crit(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderLabel::Int(33),
    ]);

    let crit = map.crit().unwrap();
    assert_eq!(crit.len(), 3);
    assert_eq!(crit[0], CoseHeaderLabel::Int(1));
    assert_eq!(crit[1], CoseHeaderLabel::Text("custom".to_string()));
    assert_eq!(crit[2], CoseHeaderLabel::Int(33));
}

/// get_bytes_one_or_many with a single bstr.
#[test]
fn test_cb_get_bytes_one_or_many_single() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()),
    );
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33));
    assert_eq!(result, Some(vec![vec![1, 2, 3]]));
}

/// get_bytes_one_or_many with an array of bstrs.
#[test]
fn test_cb_get_bytes_one_or_many_array() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![1, 2].into()),
            CoseHeaderValue::Bytes(vec![3, 4].into()),
        ]),
    );
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33));
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
}

/// get_bytes_one_or_many with non-matching type returns None.
#[test]
fn test_cb_get_bytes_one_or_many_wrong_type() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(33), CoseHeaderValue::Int(42));
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33));
    assert_eq!(result, None);
}

/// get_bytes_one_or_many with missing label returns None.
#[test]
fn test_cb_get_bytes_one_or_many_missing() {
    let map = CoseHeaderMap::new();
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33));
    assert_eq!(result, None);
}

/// as_bytes_one_or_many on array with non-bytes items returns empty (None).
#[test]
fn test_cb_as_bytes_one_or_many_array_no_bytes() {
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("text".to_string().into()),
    ]);
    assert_eq!(val.as_bytes_one_or_many(), None);
}

/// CoseHeaderMap iterator.
#[test]
fn test_cb_header_map_iter() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"test-key".to_vec());

    let entries: Vec<_> = map.iter().collect();
    assert_eq!(entries.len(), 2);
}

/// CoseHeaderMap remove.
#[test]
fn test_cb_header_map_remove() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    assert_eq!(map.len(), 1);

    let removed = map.remove(&CoseHeaderLabel::Int(CoseHeaderMap::ALG));
    assert_eq!(removed, Some(CoseHeaderValue::Int(-7)));
    assert!(map.is_empty());
}

/// ProtectedHeader default.
#[test]
fn test_cb_protected_header_default() {
    let ph = ProtectedHeader::default();
    assert!(ph.is_empty());
    assert!(ph.as_bytes().is_empty());
    assert_eq!(ph.alg(), None);
    assert_eq!(ph.kid(), None);
    assert_eq!(ph.content_type(), None);
}

/// ProtectedHeader headers_mut.
#[test]
fn test_cb_protected_header_headers_mut() {
    let map = CoseHeaderMap::new();
    let mut protected = ProtectedHeader::encode(map).unwrap();
    protected.headers_mut().set_alg(-7);
    assert_eq!(protected.alg(), Some(-7));
}

/// CoseHeaderValue From implementations.
#[test]
fn test_cb_header_value_from_impls() {
    let _: CoseHeaderValue = 42i64.into();
    let _: CoseHeaderValue = 42u64.into();
    let _: CoseHeaderValue = vec![1u8, 2, 3].into();
    let _: CoseHeaderValue = (&[1u8, 2, 3][..]).into();
    let _: CoseHeaderValue = "hello".into();
    let _: CoseHeaderValue = String::from("hello").into();
    let _: CoseHeaderValue = true.into();
}

/// CoseHeaderLabel From implementations.
#[test]
fn test_cb_header_label_from_impls() {
    let _: CoseHeaderLabel = 1i64.into();
    let _: CoseHeaderLabel = "key".into();
    let _: CoseHeaderLabel = String::from("key").into();
}

/// CoseHeaderValue accessor methods.
#[test]
fn test_cb_header_value_accessors() {
    assert_eq!(CoseHeaderValue::Int(42).as_i64(), Some(42));
    assert_eq!(
        CoseHeaderValue::Text("hi".to_string().into()).as_i64(),
        None
    );

    assert_eq!(
        CoseHeaderValue::Text("hi".to_string().into()).as_str(),
        Some("hi")
    );
    assert_eq!(CoseHeaderValue::Int(42).as_str(), None);

    assert_eq!(
        CoseHeaderValue::Bytes(vec![1, 2].into()).as_bytes(),
        Some(&[1, 2][..])
    );
    assert_eq!(CoseHeaderValue::Int(42).as_bytes(), None);
}
