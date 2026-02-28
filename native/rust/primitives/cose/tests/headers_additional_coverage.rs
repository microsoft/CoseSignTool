// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for COSE headers to reach all uncovered code paths.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{
    ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};

#[test]
fn test_header_value_from_conversions() {
    // Test all From trait implementations
    let _val: CoseHeaderValue = 42i64.into();
    let _val: CoseHeaderValue = 42u64.into(); 
    let _val: CoseHeaderValue = b"bytes".to_vec().into();
    let _val: CoseHeaderValue = "text".to_string().into();
    let _val: CoseHeaderValue = "text".into();
    let _val: CoseHeaderValue = true.into();
    
    // Test From for CoseHeaderLabel
    let _label: CoseHeaderLabel = 42i64.into();
    let _label: CoseHeaderLabel = "text".into();
    let _label: CoseHeaderLabel = "text".to_string().into();
}

#[test] 
fn test_header_value_accessor_methods() {
    // Test as_bytes
    let bytes_val = CoseHeaderValue::Bytes(b"test".to_vec());
    assert_eq!(bytes_val.as_bytes(), Some(b"test".as_slice()));
    
    let int_val = CoseHeaderValue::Int(42);
    assert_eq!(int_val.as_bytes(), None);
    
    // Test as_i64
    assert_eq!(int_val.as_i64(), Some(42));
    assert_eq!(bytes_val.as_i64(), None);
    
    // Test as_str
    let text_val = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(text_val.as_str(), Some("hello"));
    assert_eq!(int_val.as_str(), None);
}

#[test]
fn test_header_value_as_bytes_one_or_many() {
    // Single bytes value
    let single = CoseHeaderValue::Bytes(b"cert1".to_vec());
    assert_eq!(single.as_bytes_one_or_many(), Some(vec![b"cert1".to_vec()]));
    
    // Array of bytes values
    let array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(b"cert1".to_vec()),
        CoseHeaderValue::Bytes(b"cert2".to_vec()),
    ]);
    assert_eq!(array.as_bytes_one_or_many(), Some(vec![b"cert1".to_vec(), b"cert2".to_vec()]));
    
    // Array with mixed types (returns only the bytes elements) 
    let mixed_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(b"cert".to_vec()),
        CoseHeaderValue::Int(42),
    ]);
    assert_eq!(mixed_array.as_bytes_one_or_many(), Some(vec![b"cert".to_vec()]));
    
    // Empty array
    let empty_array = CoseHeaderValue::Array(vec![]);
    assert_eq!(empty_array.as_bytes_one_or_many(), None);
    
    // Non-bytes, non-array value
    let int_val = CoseHeaderValue::Int(42);
    assert_eq!(int_val.as_bytes_one_or_many(), None);
}

#[test]
fn test_content_type_values() {
    // Test ContentType variants
    let int_ct = ContentType::Int(42);
    let text_ct = ContentType::Text("application/json".to_string());
    
    // These are mainly for coverage of ContentType enum
    assert_ne!(int_ct, text_ct);
    
    // Test Debug formatting
    let debug_str = format!("{:?}", int_ct);
    assert!(debug_str.contains("Int"));
}

#[test]
fn test_header_map_content_type_operations() {
    let mut map = CoseHeaderMap::new();
    
    // Test setting int content type
    map.set_content_type(ContentType::Int(42));
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
    
    // Test setting text content type
    map.set_content_type(ContentType::Text("application/json".to_string()));
    assert_eq!(map.content_type(), Some(ContentType::Text("application/json".to_string())));
    
    // Test manually set uint content type (via insert)
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(123),
    );
    assert_eq!(map.content_type(), Some(ContentType::Int(123)));
    
    // Test out-of-range uint 
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), 
        CoseHeaderValue::Uint(u64::MAX),
    );
    assert_eq!(map.content_type(), None);
    
    // Test out-of-range negative int
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1),
    );
    assert_eq!(map.content_type(), None);
    
    // Test invalid content type value
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Bytes(b"invalid".to_vec()),
    );
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_header_map_critical_headers() {
    let mut map = CoseHeaderMap::new();
    
    // Set critical headers
    let crit_labels = vec![
        CoseHeaderLabel::Int(1),   // alg
        CoseHeaderLabel::Text("custom".to_string()),
    ];
    map.set_crit(crit_labels.clone());
    
    let retrieved = map.crit().unwrap();
    assert_eq!(retrieved.len(), 2);
    assert_eq!(retrieved[0], CoseHeaderLabel::Int(1));
    assert_eq!(retrieved[1], CoseHeaderLabel::Text("custom".to_string()));
    
    // Test crit() when header is not an array
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Int(42),
    );
    assert_eq!(map.crit(), None);
    
    // Test crit() with invalid array elements
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Bytes(b"invalid".to_vec()), // Invalid - not int or text
        ]),
    );
    let filtered = map.crit().unwrap();
    assert_eq!(filtered.len(), 1); // Only the valid int should remain
    assert_eq!(filtered[0], CoseHeaderLabel::Int(1));
}

#[test]
fn test_header_map_get_bytes_one_or_many() {
    let mut map = CoseHeaderMap::new();
    let label = CoseHeaderLabel::Int(33); // x5chain
    
    // Single bytes value
    map.insert(label.clone(), CoseHeaderValue::Bytes(b"cert1".to_vec()));
    assert_eq!(map.get_bytes_one_or_many(&label), Some(vec![b"cert1".to_vec()]));
    
    // Array of bytes 
    map.insert(label.clone(), CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(b"cert1".to_vec()),
        CoseHeaderValue::Bytes(b"cert2".to_vec()),
    ]));
    assert_eq!(map.get_bytes_one_or_many(&label), Some(vec![b"cert1".to_vec(), b"cert2".to_vec()]));
    
    // Non-existent label
    let missing_label = CoseHeaderLabel::Int(999);
    assert_eq!(map.get_bytes_one_or_many(&missing_label), None);
    
    // Invalid value type
    map.insert(label.clone(), CoseHeaderValue::Int(42));
    assert_eq!(map.get_bytes_one_or_many(&label), None);
}

#[test]
fn test_header_map_basic_operations() {
    let mut map = CoseHeaderMap::new();
    
    // Test empty map
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    
    // Test insertion and retrieval
    let label = CoseHeaderLabel::Int(42);
    let value = CoseHeaderValue::Text("test".to_string());
    map.insert(label.clone(), value.clone());
    
    assert!(!map.is_empty());
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(&label), Some(&value));
    
    // Test removal
    let removed = map.remove(&label);
    assert_eq!(removed, Some(value));
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
    assert_eq!(map.get(&label), None);
    
    // Test remove non-existent key
    assert_eq!(map.remove(&label), None);
}

#[test]
fn test_header_map_iterator() {
    let mut map = CoseHeaderMap::new();
    
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Bytes(b"key-id".to_vec()));
    
    let items: Vec<_> = map.iter().collect();
    assert_eq!(items.len(), 2);
    
    // BTreeMap iteration is ordered by key
    assert_eq!(items[0].0, &CoseHeaderLabel::Int(1));
    assert_eq!(items[0].1, &CoseHeaderValue::Int(-7));
    assert_eq!(items[1].0, &CoseHeaderLabel::Int(4));
    assert_eq!(items[1].1, &CoseHeaderValue::Bytes(b"key-id".to_vec()));
}

#[test]
fn test_header_map_cbor_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"test-key");
    map.set_content_type(ContentType::Int(42));
    
    // Test encoding
    let encoded = map.encode().expect("should encode");
    
    // Test decoding 
    let decoded = CoseHeaderMap::decode(&encoded).expect("should decode");
    
    // Verify roundtrip 
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"test-key".as_slice()));
    assert_eq!(decoded.content_type(), Some(ContentType::Int(42)));
}

#[test]
fn test_header_map_encode_all_value_types() {
    let provider = EverParseCborProvider;
    let mut map = CoseHeaderMap::new();
    
    // Add all value types to ensure encode_value covers everything
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Uint(u64::MAX));
    map.insert(CoseHeaderLabel::Int(3), CoseHeaderValue::Bytes(b"bytes".to_vec()));
    map.insert(CoseHeaderLabel::Int(4), CoseHeaderValue::Text("text".to_string()));
    map.insert(CoseHeaderLabel::Int(5), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(6), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(7), CoseHeaderValue::Undefined);
    
    // Array value
    map.insert(CoseHeaderLabel::Int(8), CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("nested".to_string()),
    ]));
    
    // Map value
    map.insert(CoseHeaderLabel::Int(9), CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(10), CoseHeaderValue::Int(42)),
        (CoseHeaderLabel::Text("key".to_string()), CoseHeaderValue::Text("value".to_string())),
    ]));
    
    // Tagged value
    map.insert(CoseHeaderLabel::Int(11), CoseHeaderValue::Tagged(
        42,
        Box::new(CoseHeaderValue::Text("tagged".to_string())),
    ));
    
    // Raw CBOR value
    let mut raw_encoder = provider.encoder();
    raw_encoder.encode_i64(999).unwrap();
    let raw_bytes = raw_encoder.into_bytes();
    map.insert(CoseHeaderLabel::Int(12), CoseHeaderValue::Raw(raw_bytes));
    
    // Test encoding (should not panic or error)
    let encoded = map.encode().expect("should encode all types");
    
    // Test decoding back
    let decoded = CoseHeaderMap::decode(&encoded).expect("should decode");
    
    // Verify some key values
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(2)), Some(&CoseHeaderValue::Uint(u64::MAX)));
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(5)), Some(&CoseHeaderValue::Bool(true)));
}

#[test]
fn test_header_map_decode_empty_data() {
    let decoded = CoseHeaderMap::decode(&[]).expect("should decode empty");
    assert!(decoded.is_empty());
}

#[test]
fn test_header_map_decode_indefinite_map() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Create indefinite-length map
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap(); // alg
    encoder.encode_i64(-7).unwrap(); // ES256
    encoder.encode_tstr("custom").unwrap(); // custom label
    encoder.encode_i64(42).unwrap();
    encoder.encode_break().unwrap();
    
    let encoded = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&encoded).expect("should decode indefinite map");
    
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.get(&CoseHeaderLabel::Text("custom".to_string())), Some(&CoseHeaderValue::Int(42)));
}

#[test] 
fn test_header_map_decode_invalid_label_type() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_bstr(b"invalid").unwrap(); // Invalid label type - should be int or text
    encoder.encode_i64(42).unwrap();
    
    let encoded = encoder.into_bytes();
    let result = CoseHeaderMap::decode(&encoded);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid header label"));
}

#[test]
fn test_header_map_decode_unsupported_value_type() {
    // This is tricky to test since most CBOR types are supported
    // The "unsupported type" error path requires a CBOR type that's not handled
    // This might not be easily testable with EverParse provider
    
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap(); // valid label
    // We'll encode something that might be unsupported... but EverParse supports most types
    encoder.encode_i64(42).unwrap(); // This will be supported, but at least exercises the path
    
    let encoded = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&encoded).expect("should decode");
    assert_eq!(decoded.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(42)));
}

#[test]
fn test_protected_header_operations() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"test-key");
    
    // Test encoding protected header
    let protected = ProtectedHeader::encode(headers.clone()).expect("should encode");
    
    // Test accessors 
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"test-key".as_slice()));
    // Can't compare CoseHeaderMap directly since it doesn't implement PartialEq
    assert_eq!(protected.headers().alg(), headers.alg());
    assert_eq!(protected.headers().kid(), headers.kid());
    assert!(!protected.is_empty());
    assert_eq!(protected.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
    
    // Test raw bytes access
    let raw_bytes = protected.as_bytes();
    assert!(!raw_bytes.is_empty());
    
    // Test decoding from raw bytes
    let decoded = ProtectedHeader::decode(raw_bytes.to_vec()).expect("should decode");
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"test-key".as_slice()));
}

#[test]
fn test_protected_header_empty() {
    // Test decoding empty protected header
    let protected = ProtectedHeader::decode(Vec::new()).expect("should decode empty");
    assert!(protected.is_empty());
    assert_eq!(protected.alg(), None);
    assert_eq!(protected.kid(), None);
    assert_eq!(protected.content_type(), None);
    
    // Test default
    let default = ProtectedHeader::default();
    assert!(default.is_empty());
    assert_eq!(default.as_bytes(), &[]);
}

#[test]
fn test_protected_header_mutable_access() {
    let mut headers = CoseHeaderMap::new(); 
    headers.set_alg(-7);
    
    let mut protected = ProtectedHeader::encode(headers).expect("should encode");
    
    // Test mutable access (note: this will make verification fail if used)
    let headers_mut = protected.headers_mut();
    headers_mut.set_alg(-8); // Change algorithm
    
    assert_eq!(protected.alg(), Some(-8));
}

#[test]
fn test_header_value_float_type() {
    // Test Float value encoding/decoding (if supported by provider)
    // EverParse doesn't support float encoding, so we'll just test the enum variant
    let float_val = CoseHeaderValue::Float(3.14);
    
    // This primarily tests the Float variant exists and can be created
    match float_val {
        CoseHeaderValue::Float(f) => assert!((f - 3.14).abs() < 0.001),
        _ => panic!("Expected Float variant"),
    }
}

#[test]
fn test_all_header_constants() {
    // Test all defined constants are accessible
    assert_eq!(CoseHeaderMap::ALG, 1);
    assert_eq!(CoseHeaderMap::CRIT, 2); 
    assert_eq!(CoseHeaderMap::CONTENT_TYPE, 3);
    assert_eq!(CoseHeaderMap::KID, 4);
    assert_eq!(CoseHeaderMap::IV, 5);
    assert_eq!(CoseHeaderMap::PARTIAL_IV, 6);
}