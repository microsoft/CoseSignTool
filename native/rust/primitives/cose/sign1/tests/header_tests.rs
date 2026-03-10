// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for COSE header types and operations.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::error::CoseError;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ContentType};

#[test]
fn test_header_label_equality() {
    let label1 = CoseHeaderLabel::Int(1);
    let label2 = CoseHeaderLabel::Int(1);
    let label3 = CoseHeaderLabel::Int(2);
    let label4 = CoseHeaderLabel::Text("custom".to_string());
    let label5 = CoseHeaderLabel::Text("custom".to_string());

    assert_eq!(label1, label2);
    assert_ne!(label1, label3);
    assert_eq!(label4, label5);
    assert_ne!(label1, label4);
}

#[test]
fn test_header_label_ordering() {
    let mut labels = vec![
        CoseHeaderLabel::Int(3),
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("z".to_string()),
        CoseHeaderLabel::Text("a".to_string()),
        CoseHeaderLabel::Int(2),
    ];

    labels.sort();

    assert_eq!(labels[0], CoseHeaderLabel::Int(1));
    assert_eq!(labels[1], CoseHeaderLabel::Int(2));
    assert_eq!(labels[2], CoseHeaderLabel::Int(3));
    assert_eq!(labels[3], CoseHeaderLabel::Text("a".to_string()));
    assert_eq!(labels[4], CoseHeaderLabel::Text("z".to_string()));
}

#[test]
fn test_header_label_from_i64() {
    let label: CoseHeaderLabel = 42i64.into();
    assert_eq!(label, CoseHeaderLabel::Int(42));
}

#[test]
fn test_header_label_from_str() {
    let label: CoseHeaderLabel = "test".into();
    assert_eq!(label, CoseHeaderLabel::Text("test".to_string()));
}

#[test]
fn test_header_label_from_string() {
    let label: CoseHeaderLabel = "test".to_string().into();
    assert_eq!(label, CoseHeaderLabel::Text("test".to_string()));
}

#[test]
fn test_header_value_int() {
    let value = CoseHeaderValue::Int(42);
    assert_eq!(value, CoseHeaderValue::Int(42));
    
    let value2: CoseHeaderValue = 42i64.into();
    assert_eq!(value, value2);
}

#[test]
fn test_header_value_uint() {
    let value = CoseHeaderValue::Uint(u64::MAX);
    assert_eq!(value, CoseHeaderValue::Uint(u64::MAX));
    
    let value2: CoseHeaderValue = u64::MAX.into();
    assert_eq!(value, value2);
}

#[test]
fn test_header_value_bytes() {
    let bytes = vec![1, 2, 3, 4];
    let value = CoseHeaderValue::Bytes(bytes.clone());
    assert_eq!(value, CoseHeaderValue::Bytes(bytes.clone()));
    
    let value2: CoseHeaderValue = bytes.clone().into();
    assert_eq!(value, value2);
    
    let value3: CoseHeaderValue = bytes.as_slice().into();
    assert_eq!(value, value3);
}

#[test]
fn test_header_value_text() {
    let text = "hello";
    let value = CoseHeaderValue::Text(text.to_string());
    assert_eq!(value, CoseHeaderValue::Text(text.to_string()));
    
    let value2: CoseHeaderValue = text.into();
    assert_eq!(value, value2);
    
    let value3: CoseHeaderValue = text.to_string().into();
    assert_eq!(value, value3);
}

#[test]
fn test_header_value_bool() {
    let value_true = CoseHeaderValue::Bool(true);
    let value_false = CoseHeaderValue::Bool(false);
    
    assert_eq!(value_true, CoseHeaderValue::Bool(true));
    assert_eq!(value_false, CoseHeaderValue::Bool(false));
    
    let value2: CoseHeaderValue = true.into();
    assert_eq!(value_true, value2);
}

#[test]
fn test_header_value_null() {
    let value = CoseHeaderValue::Null;
    assert_eq!(value, CoseHeaderValue::Null);
}

#[test]
fn test_header_value_undefined() {
    let value = CoseHeaderValue::Undefined;
    assert_eq!(value, CoseHeaderValue::Undefined);
}

#[test]
fn test_header_value_float() {
    let value = CoseHeaderValue::Float(3.14);
    assert_eq!(value, CoseHeaderValue::Float(3.14));
}

#[test]
fn test_header_value_array() {
    let arr = vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("test".to_string()),
        CoseHeaderValue::Bool(true),
    ];
    let value = CoseHeaderValue::Array(arr.clone());
    assert_eq!(value, CoseHeaderValue::Array(arr));
}

#[test]
fn test_header_value_map() {
    let pairs = vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42)),
        (CoseHeaderLabel::Text("key".to_string()), CoseHeaderValue::Text("value".to_string())),
    ];
    let value = CoseHeaderValue::Map(pairs.clone());
    assert_eq!(value, CoseHeaderValue::Map(pairs));
}

#[test]
fn test_header_value_tagged() {
    let inner = CoseHeaderValue::Int(42);
    let value = CoseHeaderValue::Tagged(18, Box::new(inner.clone()));
    assert_eq!(value, CoseHeaderValue::Tagged(18, Box::new(inner)));
}

#[test]
fn test_header_value_raw() {
    let raw_bytes = vec![0xa1, 0x01, 0x18, 0x2a]; // CBOR: {1: 42}
    let value = CoseHeaderValue::Raw(raw_bytes.clone());
    assert_eq!(value, CoseHeaderValue::Raw(raw_bytes));
}

#[test]
fn test_header_map_new() {
    let map = CoseHeaderMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_header_map_insert_get() {
    let mut map = CoseHeaderMap::new();
    
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42));
    assert_eq!(map.len(), 1);
    assert!(!map.is_empty());
    
    let value = map.get(&CoseHeaderLabel::Int(1));
    assert_eq!(value, Some(&CoseHeaderValue::Int(42)));
    
    let missing = map.get(&CoseHeaderLabel::Int(2));
    assert_eq!(missing, None);
}

#[test]
fn test_header_map_remove() {
    let mut map = CoseHeaderMap::new();
    
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42));
    assert_eq!(map.len(), 1);
    
    let removed = map.remove(&CoseHeaderLabel::Int(1));
    assert_eq!(removed, Some(CoseHeaderValue::Int(42)));
    assert_eq!(map.len(), 0);
    assert!(map.is_empty());
    
    let missing = map.remove(&CoseHeaderLabel::Int(99));
    assert_eq!(missing, None);
}

#[test]
fn test_header_map_alg_accessor() {
    let mut map = CoseHeaderMap::new();
    
    assert_eq!(map.alg(), None);
    
    map.set_alg(-7);
    assert_eq!(map.alg(), Some(-7));
    
    map.set_alg(-35);
    assert_eq!(map.alg(), Some(-35));
}

#[test]
fn test_header_map_kid_accessor() {
    let mut map = CoseHeaderMap::new();
    
    assert_eq!(map.kid(), None);
    
    let kid = vec![1, 2, 3, 4];
    map.set_kid(kid.clone());
    assert_eq!(map.kid(), Some(kid.as_slice()));
    
    let kid2 = b"key-id";
    map.set_kid(kid2);
    assert_eq!(map.kid(), Some(kid2.as_slice()));
}

#[test]
fn test_header_map_content_type_accessor() {
    let mut map = CoseHeaderMap::new();
    
    assert_eq!(map.content_type(), None);
    
    map.set_content_type(ContentType::Int(50));
    assert_eq!(map.content_type(), Some(ContentType::Int(50)));
    
    map.set_content_type(ContentType::Text("application/json".to_string()));
    assert_eq!(map.content_type(), Some(ContentType::Text("application/json".to_string())));
}

#[test]
fn test_header_map_crit_accessor() {
    let mut map = CoseHeaderMap::new();
    
    assert_eq!(map.crit(), None);
    
    let labels = vec![
        CoseHeaderLabel::Int(10),
        CoseHeaderLabel::Text("custom".to_string()),
    ];
    map.set_crit(labels.clone());
    
    let result = map.crit();
    assert!(result.is_some());
    let result_labels = result.unwrap();
    assert_eq!(result_labels.len(), 2);
    assert_eq!(result_labels[0], CoseHeaderLabel::Int(10));
    assert_eq!(result_labels[1], CoseHeaderLabel::Text("custom".to_string()));
}

#[test]
fn test_header_map_iter() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    
    let mut count = 0;
    for (label, value) in map.iter() {
        count += 1;
        match label {
            CoseHeaderLabel::Int(1) => assert_eq!(value, &CoseHeaderValue::Int(42)),
            CoseHeaderLabel::Int(4) => assert_eq!(value, &CoseHeaderValue::Bytes(vec![1, 2, 3])),
            _ => panic!("Unexpected label"),
        }
    }
    assert_eq!(count, 2);
}

#[test]
fn test_header_map_encode_empty() {
    let provider = EverParseCborProvider;
    let map = CoseHeaderMap::new();
    
    let encoded = map.encode().expect("encode failed");
    
    // Empty map: 0xa0
    assert_eq!(encoded, vec![0xa0]);
}

#[test]
fn test_header_map_encode_single_entry() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    
    let encoded = map.encode().expect("encode failed");
    
    // Map with one entry {1: -7} => 0xa1 0x01 0x26
    assert_eq!(encoded, vec![0xa1, 0x01, 0x26]);
}

#[test]
fn test_header_map_encode_multiple_entries() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Bytes(vec![0xaa, 0xbb]));
    
    let encoded = map.encode().expect("encode failed");
    
    // Should encode as a CBOR map with 2 entries
    assert!(encoded[0] == 0xa2); // Map with 2 entries
}

#[test]
fn test_header_map_decode_empty() {
    let provider = EverParseCborProvider;
    let data = vec![0xa0]; // Empty map
    
    let map = CoseHeaderMap::decode(&data).expect("decode failed");
    
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_header_map_decode_empty_bytes() {
    let provider = EverParseCborProvider;
    let data: &[u8] = &[];
    
    let map = CoseHeaderMap::decode(data).expect("decode failed");
    
    assert!(map.is_empty());
}

#[test]
fn test_header_map_decode_single_entry() {
    let provider = EverParseCborProvider;
    let data = vec![0xa1, 0x01, 0x26]; // {1: -7}
    
    let map = CoseHeaderMap::decode(&data).expect("decode failed");
    
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
}

#[test]
fn test_header_map_encode_decode_roundtrip() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.set_alg(-7);
    original.set_kid(vec![1, 2, 3, 4]);
    original.set_content_type(ContentType::Int(50));
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(&[1, 2, 3, 4][..]));
    assert_eq!(decoded.content_type(), Some(ContentType::Int(50)));
}

#[test]
fn test_header_map_encode_decode_text_labels() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderValue::Text("value".to_string()),
    );
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom".to_string())),
        Some(&CoseHeaderValue::Text("value".to_string()))
    );
}

#[test]
fn test_header_map_encode_decode_array_value() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(
        CoseHeaderLabel::Int(10),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Int(2),
            CoseHeaderValue::Int(3),
        ]),
    );
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    match decoded.get(&CoseHeaderLabel::Int(10)) {
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
fn test_header_map_encode_decode_nested_map() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(
        CoseHeaderLabel::Int(20),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42)),
            (CoseHeaderLabel::Text("key".to_string()), CoseHeaderValue::Text("val".to_string())),
        ]),
    );
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    match decoded.get(&CoseHeaderLabel::Int(20)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 2);
        }
        _ => panic!("Expected map value"),
    }
}

#[test]
fn test_header_map_encode_decode_tagged_value() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(
        CoseHeaderLabel::Int(30),
        CoseHeaderValue::Tagged(100, Box::new(CoseHeaderValue::Int(42))),
    );
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    match decoded.get(&CoseHeaderLabel::Int(30)) {
        Some(CoseHeaderValue::Tagged(tag, inner)) => {
            assert_eq!(*tag, 100);
            assert_eq!(**inner, CoseHeaderValue::Int(42));
        }
        _ => panic!("Expected tagged value"),
    }
}

#[test]
fn test_header_map_encode_decode_bool_values() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(CoseHeaderLabel::Int(40), CoseHeaderValue::Bool(true));
    original.insert(CoseHeaderLabel::Int(41), CoseHeaderValue::Bool(false));
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(40)), Some(&CoseHeaderValue::Bool(true)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(41)), Some(&CoseHeaderValue::Bool(false)));
}

#[test]
fn test_header_map_encode_decode_null_undefined() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(CoseHeaderLabel::Int(50), CoseHeaderValue::Null);
    original.insert(CoseHeaderLabel::Int(51), CoseHeaderValue::Undefined);
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(50)), Some(&CoseHeaderValue::Null));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(51)), Some(&CoseHeaderValue::Undefined));
}

#[test]
#[ignore = "EverParse does not support floating-point CBOR encoding"]
fn test_header_map_encode_decode_float() {
    let provider = EverParseCborProvider;
    let mut original = CoseHeaderMap::new();
    original.insert(CoseHeaderLabel::Int(60), CoseHeaderValue::Float(3.14159));
    
    let encoded = original.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    match decoded.get(&CoseHeaderLabel::Int(60)) {
        Some(CoseHeaderValue::Float(f)) => {
            assert!((f - 3.14159).abs() < 0.00001);
        }
        _ => panic!("Expected float value"),
    }
}

#[test]
fn test_header_map_well_known_constants() {
    assert_eq!(CoseHeaderMap::ALG, 1);
    assert_eq!(CoseHeaderMap::CRIT, 2);
    assert_eq!(CoseHeaderMap::CONTENT_TYPE, 3);
    assert_eq!(CoseHeaderMap::KID, 4);
    assert_eq!(CoseHeaderMap::IV, 5);
    assert_eq!(CoseHeaderMap::PARTIAL_IV, 6);
}

#[test]
fn test_content_type_int() {
    let ct = ContentType::Int(50);
    assert_eq!(ct, ContentType::Int(50));
}

#[test]
fn test_content_type_text() {
    let ct = ContentType::Text("application/json".to_string());
    assert_eq!(ct, ContentType::Text("application/json".to_string()));
}

#[test]
fn test_header_map_content_type_out_of_range() {
    let mut map = CoseHeaderMap::new();
    
    // Insert an int value that's out of u16 range for content type
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Int(100_000));
    
    // content_type() should return None for out-of-range values
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_content_type_uint() {
    let mut map = CoseHeaderMap::new();
    
    // Insert as Uint
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Uint(100));
    assert_eq!(map.content_type(), Some(ContentType::Int(100)));
    
    // Out of range Uint
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Uint(100_000));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_content_type_negative_int() {
    let mut map = CoseHeaderMap::new();
    
    // Negative int should return None for content type
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Int(-1));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_content_type_invalid_type() {
    let mut map = CoseHeaderMap::new();
    
    // Non-int/text type should return None
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_crit_empty() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Array(vec![]));
    
    let labels = map.crit();
    assert!(labels.is_some());
    assert_eq!(labels.unwrap().len(), 0);
}

#[test]
fn test_header_map_crit_mixed_labels() {
    let mut map = CoseHeaderMap::new();
    map.set_crit(vec![
        CoseHeaderLabel::Int(10),
        CoseHeaderLabel::Text("ext".to_string()),
        CoseHeaderLabel::Int(20),
    ]);
    
    let labels = map.crit().unwrap();
    assert_eq!(labels.len(), 3);
    assert_eq!(labels[0], CoseHeaderLabel::Int(10));
    assert_eq!(labels[1], CoseHeaderLabel::Text("ext".to_string()));
    assert_eq!(labels[2], CoseHeaderLabel::Int(20));
}

#[test]
fn test_header_map_uint_to_int_conversion_on_decode() {
    let provider = EverParseCborProvider;
    
    // Create a map with a Uint that fits in i64
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(100), CoseHeaderValue::Uint(1000));
    
    let encoded = map.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    
    // Should be decoded as Int since it fits
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(100)), Some(&CoseHeaderValue::Int(1000)));
}

#[test]
fn test_header_label_clone() {
    let label = CoseHeaderLabel::Int(42);
    let cloned = label.clone();
    assert_eq!(label, cloned);
}

#[test]
fn test_header_value_clone() {
    let value = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    let cloned = value.clone();
    assert_eq!(value, cloned);
}

#[test]
fn test_header_map_default() {
    let map = CoseHeaderMap::default();
    assert!(map.is_empty());
}

// --- encode_value for Raw variant ---

#[test]
fn test_header_map_encode_decode_raw_value() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    // Raw CBOR bytes representing the integer 42: 0x18 0x2a
    map.insert(
        CoseHeaderLabel::Int(70),
        CoseHeaderValue::Raw(vec![0x18, 0x2a]),
    );

    let encoded = map.encode().expect("encode failed");
    // When decoded, raw bytes should be decoded as whatever CBOR type they represent
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");
    // The raw value 0x18 0x2a is the integer 42
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(70)),
        Some(&CoseHeaderValue::Int(42))
    );
}

// --- crit() filtering non-int/text values ---

#[test]
fn test_header_map_crit_filters_non_label_values() {
    let mut map = CoseHeaderMap::new();
    // Manually set crit to an array containing a Bytes value (should be filtered)
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(10),
            CoseHeaderValue::Bytes(vec![1, 2, 3]),
            CoseHeaderValue::Text("ext".to_string()),
        ]),
    );

    let labels = map.crit().unwrap();
    // Bytes value should be filtered out
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0], CoseHeaderLabel::Int(10));
    assert_eq!(labels[1], CoseHeaderLabel::Text("ext".to_string()));
}

// --- decode indefinite-length map at top level ---

#[test]
fn test_header_map_decode_indefinite_length_map() {
    let provider = EverParseCborProvider;
    // BF 01 26 04 42 AA BB FF → {_ 1: -7, 4: h'AABB' }
    let data = vec![0xbf, 0x01, 0x26, 0x04, 0x42, 0xaa, 0xbb, 0xff];

    let map = CoseHeaderMap::decode(&data).expect("decode failed");

    assert_eq!(map.alg(), Some(-7));
    assert_eq!(map.kid(), Some(&[0xaa, 0xbb][..]));
}

// --- decode_value: Uint > i64::MAX ---

#[test]
fn test_header_map_decode_uint_over_i64_max() {
    let provider = EverParseCborProvider;
    // {10: 0xFFFFFFFFFFFFFFFF}
    // A1 0A 1B FF FF FF FF FF FF FF FF
    let data = vec![
        0xa1, 0x0a, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ];

    let map = CoseHeaderMap::decode(&data).expect("decode failed");

    assert_eq!(
        map.get(&CoseHeaderLabel::Int(10)),
        Some(&CoseHeaderValue::Uint(u64::MAX))
    );
}

// --- decode_value: indefinite-length array ---

#[test]
fn test_header_map_decode_indefinite_array_value() {
    let provider = EverParseCborProvider;
    // {10: [_ 1, 2, 3, break]}
    // A1 0A 9F 01 02 03 FF
    let data = vec![0xa1, 0x0a, 0x9f, 0x01, 0x02, 0x03, 0xff];

    let map = CoseHeaderMap::decode(&data).expect("decode failed");

    match map.get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 3);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Int(2));
            assert_eq!(arr[2], CoseHeaderValue::Int(3));
        }
        other => panic!("expected Array, got {:?}", other),
    }
}

// --- decode_value: indefinite-length map value ---

#[test]
fn test_header_map_decode_indefinite_map_value() {
    let provider = EverParseCborProvider;
    // {10: {_ 1: 42, break}}
    // A1 0A BF 01 18 2A FF
    let data = vec![0xa1, 0x0a, 0xbf, 0x01, 0x18, 0x2a, 0xff];

    let map = CoseHeaderMap::decode(&data).expect("decode failed");

    match map.get(&CoseHeaderLabel::Int(10)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
            assert_eq!(pairs[0].1, CoseHeaderValue::Int(42));
        }
        other => panic!("expected Map, got {:?}", other),
    }
}

// --- decode_label: invalid type (e.g., bstr as label) ---

#[test]
fn test_header_map_decode_invalid_label_type() {
    let provider = EverParseCborProvider;
    // {h'01': 42} → A1 41 01 18 2A — ByteString as key should fail
    let data = vec![0xa1, 0x41, 0x01, 0x18, 0x2a];

    let result = CoseHeaderMap::decode(&data);
    assert!(result.is_err());
    match result {
        Err(CoseError::InvalidMessage(msg)) => {
            assert!(msg.contains("invalid header label type"));
        }
        _ => panic!("expected InvalidMessage error"),
    }
}

// --- decode_value: unsupported CBOR type (break marker where value expected) ---

// The unsupported type branch is hard to reach with well-formed CBOR since all
// standard types are handled. It can only be triggered by a CBOR break or
// simple value that doesn't map to Bool/Null/Undefined/Float. We use a definite
// map where the value position has a break marker – the decoder may expose this
// as an unsupported type.

#[test]
fn test_header_map_encode_decode_with_undefined() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(70), CoseHeaderValue::Undefined);
    map.insert(CoseHeaderLabel::Int(71), CoseHeaderValue::Null);

    let encoded = map.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(70)),
        Some(&CoseHeaderValue::Undefined)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(71)),
        Some(&CoseHeaderValue::Null)
    );
}

#[test]
#[ignore = "EverParse does not support floating-point CBOR encoding"]
fn test_header_map_encode_decode_with_undefined_and_float() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(70), CoseHeaderValue::Undefined);
    map.insert(CoseHeaderLabel::Int(71), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(72), CoseHeaderValue::Float(1.5));

    let encoded = map.encode().expect("encode failed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode failed");

    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(70)),
        Some(&CoseHeaderValue::Undefined)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(71)),
        Some(&CoseHeaderValue::Null)
    );
    match decoded.get(&CoseHeaderLabel::Int(72)) {
        Some(CoseHeaderValue::Float(f)) => assert!((f - 1.5).abs() < 0.001),
        other => panic!("expected Float, got {:?}", other),
    }
}

// --- decode_value: unsupported CBOR type (Simple value) ---

#[test]
fn test_header_map_decode_unsupported_simple_value() {
    let provider = EverParseCborProvider;
    // {10: simple(16)} → A1 0A F0
    // Simple values are not supported in header map values
    let data = vec![0xa1, 0x0a, 0xf0];

    let result = CoseHeaderMap::decode(&data);
    assert!(result.is_err());
    match result {
        Err(CoseError::InvalidMessage(msg)) => {
            assert!(msg.contains("unsupported CBOR type"));
        }
        _ => panic!("expected InvalidMessage error"),
    }
}
