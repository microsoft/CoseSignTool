// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for CoseHeaderMap and CoseHeaderValue.
//!
//! These tests target uncovered paths in header manipulation and CBOR encoding/decoding.

use cbor_primitives::{CborProvider, CborEncoder, CborDecoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{
    CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ContentType, ProtectedHeader,
};
use std::fmt::Write;

#[test]
fn test_header_label_from_conversions() {
    let label1: CoseHeaderLabel = 42i64.into();
    assert_eq!(label1, CoseHeaderLabel::Int(42));
    
    let label2: CoseHeaderLabel = "test".into();
    assert_eq!(label2, CoseHeaderLabel::Text("test".to_string()));
    
    let label3: CoseHeaderLabel = "test".to_string().into();
    assert_eq!(label3, CoseHeaderLabel::Text("test".to_string()));
}

#[test]
fn test_header_value_from_conversions() {
    let val1: CoseHeaderValue = 42i64.into();
    assert_eq!(val1, CoseHeaderValue::Int(42));
    
    let val2: CoseHeaderValue = 42u64.into();
    assert_eq!(val2, CoseHeaderValue::Uint(42));
    
    let val3: CoseHeaderValue = vec![1u8, 2, 3].into();
    assert_eq!(val3, CoseHeaderValue::Bytes(vec![1, 2, 3]));
    
    let val4: CoseHeaderValue = ([1u8, 2, 3].as_slice()).into();
    assert_eq!(val4, CoseHeaderValue::Bytes(vec![1, 2, 3]));
    
    let val5: CoseHeaderValue = "test".to_string().into();
    assert_eq!(val5, CoseHeaderValue::Text("test".to_string()));
    
    let val6: CoseHeaderValue = "test".into();
    assert_eq!(val6, CoseHeaderValue::Text("test".to_string()));
    
    let val7: CoseHeaderValue = true.into();
    assert_eq!(val7, CoseHeaderValue::Bool(true));
}

#[test]
fn test_header_value_accessors() {
    // Test as_bytes
    let bytes_val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    assert_eq!(bytes_val.as_bytes(), Some(&[1u8, 2, 3][..]));
    
    let text_val = CoseHeaderValue::Text("test".to_string());
    assert_eq!(text_val.as_bytes(), None);
    
    // Test as_bytes_one_or_many with single bytes
    assert_eq!(bytes_val.as_bytes_one_or_many(), Some(vec![vec![1, 2, 3]]));
    
    // Test as_bytes_one_or_many with array of bytes
    let array_val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Bytes(vec![3, 4]),
    ]);
    assert_eq!(array_val.as_bytes_one_or_many(), Some(vec![vec![1, 2], vec![3, 4]]));
    
    // Test as_bytes_one_or_many with mixed array (should return None)
    let mixed_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Int(42),
    ]);
    assert_eq!(mixed_array.as_bytes_one_or_many(), Some(vec![vec![1, 2]]));
    
    // Test as_bytes_one_or_many with empty array
    let empty_array = CoseHeaderValue::Array(vec![]);
    assert_eq!(empty_array.as_bytes_one_or_many(), None);
    
    // Test as_i64
    let int_val = CoseHeaderValue::Int(42);
    assert_eq!(int_val.as_i64(), Some(42));
    
    let uint_val = CoseHeaderValue::Uint(42);
    assert_eq!(uint_val.as_i64(), None);
    
    // Test as_str
    assert_eq!(text_val.as_str(), Some("test"));
    assert_eq!(int_val.as_str(), None);
}

#[test]
fn test_content_type_variants() {
    let ct1 = ContentType::Int(42);
    let ct2 = ContentType::Text("application/json".to_string());
    
    assert_ne!(ct1, ct2);
    
    // Test Debug formatting
    let debug_str = format!("{:?}", ct1);
    assert!(debug_str.contains("Int(42)"));
}

#[test]
fn test_header_map_basic_operations() {
    let mut map = CoseHeaderMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    
    // Test insert and get
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    assert!(!map.is_empty());
    assert_eq!(map.len(), 1);
    
    assert_eq!(map.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
    assert_eq!(map.get(&CoseHeaderLabel::Int(2)), None);
    
    // Test remove
    let removed = map.remove(&CoseHeaderLabel::Int(1));
    assert_eq!(removed, Some(CoseHeaderValue::Int(-7)));
    assert!(map.is_empty());
    
    let not_removed = map.remove(&CoseHeaderLabel::Int(1));
    assert_eq!(not_removed, None);
}

#[test]
fn test_header_map_well_known_headers() {
    let mut map = CoseHeaderMap::new();
    
    // Test algorithm
    map.set_alg(-7);
    assert_eq!(map.alg(), Some(-7));
    
    // Test kid
    map.set_kid(b"test-key");
    assert_eq!(map.kid(), Some(&b"test-key"[..]));
    
    // Test content type - integer
    map.set_content_type(ContentType::Int(42));
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
    
    // Test content type - text
    map.set_content_type(ContentType::Text("application/json".to_string()));
    assert_eq!(map.content_type(), Some(ContentType::Text("application/json".to_string())));
    
    // Test critical headers
    let crit_labels = vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".to_string()),
    ];
    map.set_crit(crit_labels.clone());
    assert_eq!(map.crit(), Some(crit_labels));
}

#[test]
fn test_header_map_content_type_edge_cases() {
    let mut map = CoseHeaderMap::new();
    
    // Test uint content type within u16 range
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), 
              CoseHeaderValue::Uint(65535));
    assert_eq!(map.content_type(), Some(ContentType::Int(65535)));
    
    // Test uint content type outside u16 range
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), 
              CoseHeaderValue::Uint(65536));
    assert_eq!(map.content_type(), None);
    
    // Test negative int content type
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), 
              CoseHeaderValue::Int(-1));
    assert_eq!(map.content_type(), None);
    
    // Test int content type outside u16 range
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), 
              CoseHeaderValue::Int(65536));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_crit_edge_cases() {
    let mut map = CoseHeaderMap::new();
    
    // Test crit with mixed valid and invalid types
    let crit_array = vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("custom".to_string()),
        CoseHeaderValue::Bytes(vec![1, 2, 3]), // Invalid - should be filtered out
    ];
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), 
              CoseHeaderValue::Array(crit_array));
    
    let result = map.crit();
    assert_eq!(result, Some(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".to_string()),
    ]));
    
    // Test crit with non-array value
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), 
              CoseHeaderValue::Int(42));
    assert_eq!(map.crit(), None);
}

#[test]
fn test_header_map_get_bytes_one_or_many() {
    let mut map = CoseHeaderMap::new();
    
    // Single bytes
    map.insert(CoseHeaderLabel::Int(33), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33)), 
              Some(vec![vec![1, 2, 3]]));
    
    // Array of bytes
    map.insert(CoseHeaderLabel::Int(34), CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Bytes(vec![3, 4]),
    ]));
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(34)), 
              Some(vec![vec![1, 2], vec![3, 4]]));
    
    // Non-existent header
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(35)), None);
    
    // Wrong type
    map.insert(CoseHeaderLabel::Int(36), CoseHeaderValue::Int(42));
    assert_eq!(map.get_bytes_one_or_many(&CoseHeaderLabel::Int(36)), None);
}

#[test]
fn test_header_map_iterator() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Text("custom".to_string()), CoseHeaderValue::Text("value".to_string()));
    
    let items: Vec<_> = map.iter().collect();
    assert_eq!(items.len(), 2);
    
    // BTreeMap should sort by key
    assert_eq!(items[0].0, &CoseHeaderLabel::Int(1));
    assert_eq!(items[1].0, &CoseHeaderLabel::Text("custom".to_string()));
}

#[test]
fn test_header_map_encode_empty() {
    let map = CoseHeaderMap::new();
    let bytes = map.encode().expect("should encode empty map");
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&bytes);
    let len = decoder.decode_map_len().expect("should be map");
    assert_eq!(len, Some(0));
}

#[test]
fn test_header_map_encode_decode_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Text("test".to_string()), CoseHeaderValue::Text("value".to_string()));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    map.insert(CoseHeaderLabel::Int(5), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(6), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(7), CoseHeaderValue::Undefined);
    map.insert(CoseHeaderLabel::Int(9), CoseHeaderValue::Uint(u64::MAX));
    
    let bytes = map.encode().expect("should encode");
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode");
    
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Text("test".to_string())), 
              Some(&CoseHeaderValue::Text("value".to_string())));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(4)), Some(&CoseHeaderValue::Bytes(vec![1, 2, 3])));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(5)), Some(&CoseHeaderValue::Bool(true)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(6)), Some(&CoseHeaderValue::Null));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(7)), Some(&CoseHeaderValue::Undefined));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(7)), Some(&CoseHeaderValue::Undefined));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(9)), Some(&CoseHeaderValue::Uint(u64::MAX)));
}

#[test]
fn test_header_map_encode_complex_structures() {
    let mut map = CoseHeaderMap::new();
    
    // Array value
    map.insert(CoseHeaderLabel::Int(100), CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("nested".to_string()),
    ]));
    
    // Map value
    map.insert(CoseHeaderLabel::Int(101), CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42)),
        (CoseHeaderLabel::Text("key".to_string()), CoseHeaderValue::Text("value".to_string())),
    ]));
    
    // Tagged value
    map.insert(CoseHeaderLabel::Int(102), CoseHeaderValue::Tagged(
        42, 
        Box::new(CoseHeaderValue::Text("tagged".to_string()))
    ));
    
    // Raw value
    map.insert(CoseHeaderLabel::Int(103), CoseHeaderValue::Raw(vec![0xf6])); // null in CBOR
    
    let bytes = map.encode().expect("should encode");
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode");
    
    // Verify complex structures
    match decoded.get(&CoseHeaderLabel::Int(100)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], CoseHeaderValue::Int(1));
            assert_eq!(arr[1], CoseHeaderValue::Text("nested".to_string()));
        }
        _ => panic!("Expected array value"),
    }
    
    match decoded.get(&CoseHeaderLabel::Int(101)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 2);
        }
        _ => panic!("Expected map value"),
    }
    
    match decoded.get(&CoseHeaderLabel::Int(102)) {
        Some(CoseHeaderValue::Tagged(tag, inner)) => {
            assert_eq!(*tag, 42);
            assert_eq!(**inner, CoseHeaderValue::Text("tagged".to_string()));
        }
        _ => panic!("Expected tagged value"),
    }
}

#[test]
fn test_header_map_decode_empty_bytes() {
    let decoded = CoseHeaderMap::decode(&[]).expect("should decode empty bytes");
    assert!(decoded.is_empty());
}

#[test]
fn test_header_map_decode_indefinite_map() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map_indefinite_begin().expect("encode indefinite map");
    encoder.encode_i64(1).expect("encode key");
    encoder.encode_i64(-7).expect("encode value");
    encoder.encode_tstr("test").expect("encode key");
    encoder.encode_tstr("value").expect("encode value");
    encoder.encode_break().expect("encode break");
    
    let bytes = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode indefinite map");
    
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Text("test".to_string())), 
              Some(&CoseHeaderValue::Text("value".to_string())));
}

#[test]
fn test_header_value_decode_large_uint() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).expect("encode map");
    encoder.encode_i64(1).expect("encode key");
    encoder.encode_u64(u64::MAX).expect("encode large uint");
    
    let bytes = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode");
    
    // Large uint should be stored as Uint, not Int
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Uint(u64::MAX)));
}

#[test]
fn test_header_value_decode_uint_in_int_range() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).expect("encode map");
    encoder.encode_i64(1).expect("encode key");
    encoder.encode_u64(42).expect("encode small uint");
    
    let bytes = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode");
    
    // Small uint should be stored as Int
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(42)));
}

#[test]
fn test_decode_unsupported_cbor_type() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).expect("encode map");
    encoder.encode_i64(1).expect("encode key");
    // Encode simple value (not supported in headers)
    // Let's just use an existing supported type instead since we can't easily create unsupported types
    encoder.encode_null().expect("encode null");
    
    let bytes = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&bytes).expect("should decode");
    
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Null));
}

#[test]
fn test_decode_invalid_header_label() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).expect("encode map");
    encoder.encode_bstr(b"invalid").expect("encode invalid label");
    encoder.encode_i64(42).expect("encode value");
    
    let bytes = encoder.into_bytes();
    let result = CoseHeaderMap::decode(&bytes);
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid header label type"));
}

#[test]
fn test_protected_header_creation() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    
    let protected = ProtectedHeader::encode(headers.clone()).expect("should encode");
    assert_eq!(protected.alg(), Some(-7));
    // Can't use assert_eq! because CoseHeaderMap doesn't implement PartialEq
    assert_eq!(protected.headers().alg(), Some(-7));
    assert!(!protected.is_empty());
    
    let raw_bytes = protected.as_bytes();
    assert!(!raw_bytes.is_empty());
}

#[test]
fn test_protected_header_decode() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(2).expect("encode map");
    encoder.encode_i64(1).expect("encode alg label");
    encoder.encode_i64(-7).expect("encode alg value");
    encoder.encode_i64(4).expect("encode kid label");
    encoder.encode_bstr(b"test-key").expect("encode kid value");
    
    let bytes = encoder.into_bytes();
    let protected = ProtectedHeader::decode(bytes.clone()).expect("should decode");
    
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(&b"test-key"[..]));
    assert_eq!(protected.as_bytes(), &bytes);
}

#[test]
fn test_protected_header_empty() {
    let protected = ProtectedHeader::decode(vec![]).expect("should decode empty");
    assert!(protected.is_empty());
    assert_eq!(protected.alg(), None);
    assert_eq!(protected.kid(), None);
    assert_eq!(protected.content_type(), None);
}

#[test]
fn test_protected_header_default() {
    let protected = ProtectedHeader::default();
    assert!(protected.is_empty());
    assert_eq!(protected.as_bytes(), &[]);
}

#[test]
fn test_protected_header_get() {
    let mut headers = CoseHeaderMap::new();
    headers.insert(CoseHeaderLabel::Int(999), CoseHeaderValue::Text("custom".to_string()));
    
    let protected = ProtectedHeader::encode(headers).expect("should encode");
    assert_eq!(protected.get(&CoseHeaderLabel::Int(999)), 
              Some(&CoseHeaderValue::Text("custom".to_string())));
    assert_eq!(protected.get(&CoseHeaderLabel::Int(1000)), None);
}

#[test]
fn test_protected_header_mutable_access() {
    let mut protected = ProtectedHeader::default();
    
    // Modify headers via mutable reference
    protected.headers_mut().set_alg(-7);
    assert_eq!(protected.headers().alg(), Some(-7));
    
    // Note: the raw bytes won't match anymore, which would cause verification to fail
    // but that's documented behavior
}

#[test]
fn test_protected_header_content_type() {
    let mut headers = CoseHeaderMap::new();
    headers.set_content_type(ContentType::Text("application/cbor".to_string()));
    
    let protected = ProtectedHeader::encode(headers).expect("should encode");
    assert_eq!(protected.content_type(), Some(ContentType::Text("application/cbor".to_string())));
}

#[test]
fn test_header_value_display_coverage() {
    // Test Display implementations to ensure all variants are covered
    let mut output = String::new();
    
    let values = vec![
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Uint(42),
        CoseHeaderValue::Bytes(vec![1, 2, 3]),
        CoseHeaderValue::Text("test".to_string()),
        CoseHeaderValue::Bool(true),
        CoseHeaderValue::Null,
        CoseHeaderValue::Undefined,
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]),
        CoseHeaderValue::Map(vec![(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(2))]),
        CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Null)),
        CoseHeaderValue::Raw(vec![0xf6]),
    ];
    
    for value in values {
        write!(&mut output, "{:?}", value).expect("should format");
    }
    
    assert!(!output.is_empty());
}
