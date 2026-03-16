// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for CoseHeaderValue and CoseHeaderMap.
//!
//! Tests uncovered paths in headers.rs including:
//! - CoseHeaderValue type checking methods (as_bytes, as_i64, as_str)  
//! - Header value extraction with wrong types
//! - Display formatting
//! - CBOR roundtrip edge cases

use cose_primitives::headers::{
    CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ContentType, ProtectedHeader,
};

#[test]
fn test_header_value_as_bytes_wrong_type() {
    let val = CoseHeaderValue::Int(42);
    assert_eq!(val.as_bytes(), None);
    
    let val = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(val.as_bytes(), None);
    
    let val = CoseHeaderValue::Bool(true);
    assert_eq!(val.as_bytes(), None);
}

#[test]
fn test_header_value_as_bytes_correct_type() {
    let val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    assert_eq!(val.as_bytes(), Some([1, 2, 3].as_slice()));
}

#[test]
fn test_header_value_as_i64_wrong_type() {
    let val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    assert_eq!(val.as_i64(), None);
    
    let val = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(val.as_i64(), None);
    
    let val = CoseHeaderValue::Bool(false);
    assert_eq!(val.as_i64(), None);
}

#[test]
fn test_header_value_as_i64_correct_type() {
    let val = CoseHeaderValue::Int(-123);
    assert_eq!(val.as_i64(), Some(-123));
}

#[test]
fn test_header_value_as_str_wrong_type() {
    let val = CoseHeaderValue::Int(42);
    assert_eq!(val.as_str(), None);
    
    let val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    assert_eq!(val.as_str(), None);
    
    let val = CoseHeaderValue::Bool(true);
    assert_eq!(val.as_str(), None);
}

#[test]
fn test_header_value_as_str_correct_type() {
    let val = CoseHeaderValue::Text("hello world".to_string());
    assert_eq!(val.as_str(), Some("hello world"));
}

#[test]
fn test_header_value_as_bytes_one_or_many_single_bytes() {
    let val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    let result = val.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2, 3]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_of_bytes() {
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Bytes(vec![3, 4]),
        CoseHeaderValue::Bytes(vec![5, 6]),
    ]);
    let result = val.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4], vec![5, 6]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_mixed() {
    // Array with some non-bytes values should return only the bytes
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Int(42), // This should be ignored
        CoseHeaderValue::Bytes(vec![3, 4]),
        CoseHeaderValue::Text("ignore".to_string()), // This should be ignored
    ]);
    let result = val.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_no_bytes() {
    // Array with no bytes values should return None
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Text("hello".to_string()),
        CoseHeaderValue::Bool(true),
    ]);
    let result = val.as_bytes_one_or_many();
    assert_eq!(result, None);
}

#[test]
fn test_header_value_as_bytes_one_or_many_wrong_type() {
    let val = CoseHeaderValue::Int(42);
    assert_eq!(val.as_bytes_one_or_many(), None);
    
    let val = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(val.as_bytes_one_or_many(), None);
    
    let val = CoseHeaderValue::Bool(false);
    assert_eq!(val.as_bytes_one_or_many(), None);
}

#[test]
fn test_header_map_get_bytes_one_or_many() {
    let mut map = CoseHeaderMap::new();
    
    // Single bytes value
    map.insert(CoseHeaderLabel::Int(33), CoseHeaderValue::Bytes(vec![1, 2, 3]));
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(33));
    assert_eq!(result, Some(vec![vec![1, 2, 3]]));
    
    // Array of bytes
    map.insert(
        CoseHeaderLabel::Int(34), 
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![4, 5]),
            CoseHeaderValue::Bytes(vec![6, 7]),
        ])
    );
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(34));
    assert_eq!(result, Some(vec![vec![4, 5], vec![6, 7]]));
    
    // Non-existent header
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(99));
    assert_eq!(result, None);
    
    // Wrong type header
    map.insert(CoseHeaderLabel::Int(35), CoseHeaderValue::Int(42));
    let result = map.get_bytes_one_or_many(&CoseHeaderLabel::Int(35));
    assert_eq!(result, None);
}

#[test]
fn test_content_type_int_boundary() {
    let mut map = CoseHeaderMap::new();
    
    // Valid u16 range
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Int(u16::MAX as i64));
    assert_eq!(map.content_type(), Some(ContentType::Int(u16::MAX)));
    
    // Too large for u16
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Int(u16::MAX as i64 + 1));
    assert_eq!(map.content_type(), None);
    
    // Negative value
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Int(-1));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_content_type_uint_boundary() {
    let mut map = CoseHeaderMap::new();
    
    // Valid u16 range for Uint
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Uint(u16::MAX as u64));
    assert_eq!(map.content_type(), Some(ContentType::Int(u16::MAX)));
    
    // Too large for u16
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Uint(u16::MAX as u64 + 1));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_crit_with_mixed_labels() {
    let mut map = CoseHeaderMap::new();
    
    let crit_array = vec![
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Text("custom".to_string()),
        CoseHeaderValue::Int(43),
        CoseHeaderValue::Bool(true), // This should be filtered out
        CoseHeaderValue::Text("another".to_string()),
        CoseHeaderValue::Bytes(vec![1, 2]), // This should be filtered out
    ];
    
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), CoseHeaderValue::Array(crit_array));
    
    let crit_labels = map.crit().unwrap();
    assert_eq!(crit_labels.len(), 4);
    assert_eq!(crit_labels[0], CoseHeaderLabel::Int(42));
    assert_eq!(crit_labels[1], CoseHeaderLabel::Text("custom".to_string()));
    assert_eq!(crit_labels[2], CoseHeaderLabel::Int(43));
    assert_eq!(crit_labels[3], CoseHeaderLabel::Text("another".to_string()));
}

#[test]
fn test_crit_wrong_type() {
    let mut map = CoseHeaderMap::new();
    
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), CoseHeaderValue::Int(42));
    assert_eq!(map.crit(), None);
    
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), CoseHeaderValue::Text("not an array".to_string()));
    assert_eq!(map.crit(), None);
}

#[test]
fn test_set_content_type_variations() {
    let mut map = CoseHeaderMap::new();
    
    // Set int content type
    map.set_content_type(ContentType::Int(1234));
    assert_eq!(map.content_type(), Some(ContentType::Int(1234)));
    
    // Set text content type 
    map.set_content_type(ContentType::Text("application/json".to_string()));
    assert_eq!(map.content_type(), Some(ContentType::Text("application/json".to_string())));
}

#[test]
fn test_header_map_remove() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(42);
    map.set_kid(b"test_kid");
    
    assert_eq!(map.len(), 2);
    
    let removed = map.remove(&CoseHeaderLabel::Int(CoseHeaderMap::ALG));
    assert!(removed.is_some());
    assert_eq!(map.len(), 1);
    assert_eq!(map.alg(), None);
    
    // Remove non-existent key
    let removed = map.remove(&CoseHeaderLabel::Int(99));
    assert!(removed.is_none());
}

#[test]
fn test_header_map_iter() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(42);
    map.set_kid(b"test_kid");
    
    let items: Vec<_> = map.iter().collect();
    assert_eq!(items.len(), 2);
    
    // Check that both headers are present (order may vary)
    let has_alg = items.iter().any(|(k, _)| *k == &CoseHeaderLabel::Int(CoseHeaderMap::ALG));
    let has_kid = items.iter().any(|(k, _)| *k == &CoseHeaderLabel::Int(CoseHeaderMap::KID));
    assert!(has_alg);
    assert!(has_kid);
}

#[test]
fn test_protected_header_empty_bytes() {
    let empty_protected = ProtectedHeader::decode(Vec::new()).unwrap();
    assert!(empty_protected.is_empty());
    assert_eq!(empty_protected.as_bytes(), &[]);
    assert_eq!(empty_protected.alg(), None);
    assert_eq!(empty_protected.kid(), None);
    assert_eq!(empty_protected.content_type(), None);
}

#[test]
fn test_protected_header_get() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(42);
    map.insert(CoseHeaderLabel::Text("custom".to_string()), CoseHeaderValue::Text("value".to_string()));
    
    let protected = ProtectedHeader::encode(map).unwrap();
    
    assert_eq!(protected.get(&CoseHeaderLabel::Int(CoseHeaderMap::ALG)), Some(&CoseHeaderValue::Int(42)));
    assert_eq!(protected.get(&CoseHeaderLabel::Text("custom".to_string())), Some(&CoseHeaderValue::Text("value".to_string())));
    assert_eq!(protected.get(&CoseHeaderLabel::Int(99)), None);
}

#[test]
fn test_protected_header_headers_mut() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(42);
    
    let mut protected = ProtectedHeader::encode(map).unwrap();
    
    // Modify headers
    protected.headers_mut().set_kid(b"new_kid");
    assert_eq!(protected.headers().kid(), Some(b"new_kid".as_slice()));
    
    // Note: raw bytes won't match modified headers (as documented)
    // This is expected behavior for verification safety
}

#[test]
fn test_protected_header_default() {
    let protected = ProtectedHeader::default();
    assert!(protected.is_empty());
    assert_eq!(protected.as_bytes(), &[]);
}

#[test]
fn test_content_type_debug_formatting() {
    let ct1 = ContentType::Int(42);
    let debug_str = format!("{:?}", ct1);
    assert!(debug_str.contains("Int"));
    assert!(debug_str.contains("42"));
    
    let ct2 = ContentType::Text("application/json".to_string());
    let debug_str = format!("{:?}", ct2);
    assert!(debug_str.contains("Text"));
    assert!(debug_str.contains("application/json"));
}

#[test]
fn test_content_type_equality() {
    let ct1 = ContentType::Int(42);
    let ct2 = ContentType::Int(42);
    let ct3 = ContentType::Int(43);
    let ct4 = ContentType::Text("test".to_string());
    
    assert_eq!(ct1, ct2);
    assert_ne!(ct1, ct3);
    assert_ne!(ct1, ct4);
}

#[test]
fn test_content_type_clone() {
    let ct1 = ContentType::Text("application/json".to_string());
    let ct2 = ct1.clone();
    assert_eq!(ct1, ct2);
}
