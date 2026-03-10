// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Advanced coverage tests for COSE headers module.

use cbor_primitives::{CborProvider, CborEncoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::headers::{CoseHeaderMap, CoseHeaderLabel, CoseHeaderValue, ContentType};
use cose_primitives::error::CoseError;

#[test]
fn test_header_value_variants() {
    // Test all CoseHeaderValue variants can be created and compared
    let int_val = CoseHeaderValue::Int(-42);
    let uint_val = CoseHeaderValue::Uint(42u64);
    let bytes_val = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    let text_val = CoseHeaderValue::Text("hello".to_string());
    let bool_val = CoseHeaderValue::Bool(true);
    let null_val = CoseHeaderValue::Null;
    let undefined_val = CoseHeaderValue::Undefined;
    let float_val = CoseHeaderValue::Float(3.14);
    let raw_val = CoseHeaderValue::Raw(vec![0xa1, 0x00, 0x01]);
    
    // Test array value
    let array_val = CoseHeaderValue::Array(vec![int_val.clone(), text_val.clone()]);
    
    // Test map value 
    let map_val = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), int_val.clone()),
        (CoseHeaderLabel::Text("test".to_string()), text_val.clone())
    ]);
    
    // Test tagged value
    let tagged_val = CoseHeaderValue::Tagged(42, Box::new(int_val.clone()));
    
    // Test that they're not equal to each other
    assert_ne!(int_val, uint_val);
    assert_ne!(bytes_val, text_val);
    assert_ne!(bool_val, null_val);
    assert_ne!(undefined_val, float_val);
    assert_ne!(array_val, map_val);
    assert_ne!(tagged_val, raw_val);
}

#[test]
fn test_header_value_conversions() {
    // Test From implementations
    let from_i64: CoseHeaderValue = 42i64.into();
    assert_eq!(from_i64, CoseHeaderValue::Int(42));
    
    let from_u64: CoseHeaderValue = 42u64.into();
    assert_eq!(from_u64, CoseHeaderValue::Uint(42));
    
    let from_vec_u8: CoseHeaderValue = vec![1, 2, 3].into();
    assert_eq!(from_vec_u8, CoseHeaderValue::Bytes(vec![1, 2, 3]));
    
    let from_slice: CoseHeaderValue = [1, 2, 3].as_slice().into();
    assert_eq!(from_slice, CoseHeaderValue::Bytes(vec![1, 2, 3]));
    
    let from_string: CoseHeaderValue = "test".to_string().into();
    assert_eq!(from_string, CoseHeaderValue::Text("test".to_string()));
    
    let from_str: CoseHeaderValue = "test".into();
    assert_eq!(from_str, CoseHeaderValue::Text("test".to_string()));
    
    let from_bool: CoseHeaderValue = true.into();
    assert_eq!(from_bool, CoseHeaderValue::Bool(true));
}

#[test] 
fn test_header_label_variants() {
    // Test different label types
    let int_label = CoseHeaderLabel::Int(42);
    let text_label = CoseHeaderLabel::Text("custom".to_string());
    
    assert_ne!(int_label, text_label);
    
    // Test From implementations
    let from_i64: CoseHeaderLabel = 42i64.into();
    assert_eq!(from_i64, CoseHeaderLabel::Int(42));
    
    let from_str: CoseHeaderLabel = "test".into();
    assert_eq!(from_str, CoseHeaderLabel::Text("test".to_string()));
    
    let from_string: CoseHeaderLabel = "test".to_string().into();
    assert_eq!(from_string, CoseHeaderLabel::Text("test".to_string()));
}

#[test]
fn test_content_type_variants() {
    // Test ContentType variants
    let int_type = ContentType::Int(50);
    let text_type = ContentType::Text("application/json".to_string());
    
    assert_ne!(int_type, text_type);
    
    // Test cloning
    let cloned_int = int_type.clone();
    assert_eq!(int_type, cloned_int);
    
    let cloned_text = text_type.clone();  
    assert_eq!(text_type, cloned_text);
}

#[test]
fn test_header_map_basic_operations() {
    let mut map = CoseHeaderMap::new();
    
    // Test alg header
    map.set_alg(-7); // ES256
    assert_eq!(map.alg(), Some(-7));
    
    // Test kid header
    let kid = b"test-key-id";
    map.set_kid(kid.to_vec());
    assert_eq!(map.kid(), Some(kid.as_slice()));
    
    // Test content type header
    map.set_content_type(ContentType::Int(50));
    assert_eq!(map.content_type(), Some(ContentType::Int(50)));
    
    // Test that map is not empty
    assert!(!map.is_empty());
}

#[test]
fn test_header_value_as_bytes_one_or_many() {
    // Single bytes value
    let single = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    let result = single.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2, 3]]));
    
    // Array of bytes values
    let array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Bytes(vec![3, 4])
    ]);
    let result = array.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
    
    // Array with mixed types (should filter to just bytes)
    let mixed = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Bytes(vec![3, 4])
    ]);
    let result = mixed.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
    
    // Array with no bytes values
    let no_bytes = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Text("hello".to_string())
    ]);
    let result = no_bytes.as_bytes_one_or_many();
    assert_eq!(result, None);
    
    // Non-array, non-bytes value
    let int_val = CoseHeaderValue::Int(42);
    let result = int_val.as_bytes_one_or_many();
    assert_eq!(result, None);
}

#[test]
fn test_header_value_accessors() {
    // Test as_i64
    let int_val = CoseHeaderValue::Int(42);
    assert_eq!(int_val.as_i64(), Some(42));
    
    let non_int = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(non_int.as_i64(), None);
    
    // Test as_str
    let text_val = CoseHeaderValue::Text("hello".to_string());
    assert_eq!(text_val.as_str(), Some("hello"));
    
    let non_text = CoseHeaderValue::Int(42);
    assert_eq!(non_text.as_str(), None);
}

#[test]
fn test_encode_decode_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"test-key".to_vec());
    map.set_content_type(ContentType::Text("application/json".to_string()));
    
    // Insert custom header
    map.insert(
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Text("test".to_string())
        ])
    );
    
    // Encode
    let encoded = map.encode().expect("encode should succeed");
    assert!(!encoded.is_empty());
    
    // Decode
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode should succeed");
    
    // Verify values match
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"test-key".as_slice()));
    assert_eq!(decoded.content_type(), Some(ContentType::Text("application/json".to_string())));
    
    // Verify custom header
    let custom = decoded.get(&CoseHeaderLabel::Text("custom".to_string()));
    assert!(custom.is_some());
}

#[test]
fn test_empty_header_map_decode() {
    // Empty bytes should decode to empty map
    let decoded = CoseHeaderMap::decode(&[]).expect("empty decode should succeed");
    assert!(decoded.is_empty());
}

#[test] 
fn test_header_map_indefinite_length() {
    // Create indefinite length map manually with CBOR
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Encode indefinite map with break
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap(); // alg label
    encoder.encode_i64(-7).unwrap(); // ES256 
    encoder.encode_break().unwrap();
    
    let data = encoder.into_bytes();
    let decoded = CoseHeaderMap::decode(&data).expect("decode should succeed");
    
    assert_eq!(decoded.alg(), Some(-7));
}

#[test]
fn test_header_value_complex_structures() {
    // Test complex nested structures
    let complex = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Text("test".to_string()),
            CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Bytes(vec![1, 2, 3])))
        ])),
        (CoseHeaderLabel::Text("nested".to_string()), CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Bool(true)),
            (CoseHeaderLabel::Int(2), CoseHeaderValue::Null)
        ]))
    ]);
    
    // Test that it can be encoded in a header map
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(100), complex.clone());
    
    let encoded = map.encode().expect("encode should succeed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decode should succeed");
    
    let retrieved = decoded.get(&CoseHeaderLabel::Int(100));
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap(), &complex);
}

#[test]
fn test_decode_invalid_cbor() {
    // Test decode with invalid CBOR
    let invalid_cbor = vec![0xff, 0xff, 0xff];
    let result = CoseHeaderMap::decode(&invalid_cbor);
    assert!(result.is_err());
    
    if let Err(CoseError::CborError(_)) = result {
        // Expected CBOR error
    } else {
        panic!("Expected CborError");
    }
}

#[test]
fn test_header_map_multiple_operations() {
    let mut map = CoseHeaderMap::new();
    
    // Add multiple headers
    map.set_alg(-7);
    map.set_kid(b"key1");
    map.set_content_type(ContentType::Int(50));
    
    // Test len
    assert_eq!(map.len(), 3);
    
    // Test contains headers by getting them
    assert!(map.get(&CoseHeaderLabel::Int(CoseHeaderMap::ALG)).is_some());
    assert!(map.get(&CoseHeaderLabel::Int(CoseHeaderMap::KID)).is_some());
    assert!(map.get(&CoseHeaderLabel::Int(999)).is_none());
    
    // Test iteration
    let mut count = 0;
    for (_label, value) in map.iter() {
        count += 1;
        assert!(value != &CoseHeaderValue::Null); // All our values are non-null
    }
    assert_eq!(count, 3);
    
    // Test remove
    let removed = map.remove(&CoseHeaderLabel::Int(CoseHeaderMap::ALG));
    assert!(removed.is_some());
    assert_eq!(map.len(), 2);
    assert_eq!(map.alg(), None);
    
    // Cannot test clear since it doesn't exist - remove items one by one instead
    map.remove(&CoseHeaderLabel::Int(CoseHeaderMap::KID));
    map.remove(&CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE));
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_header_constants() {
    // Test that header constants are correct values per RFC 9052
    assert_eq!(CoseHeaderMap::ALG, 1);
    assert_eq!(CoseHeaderMap::CRIT, 2);  
    assert_eq!(CoseHeaderMap::CONTENT_TYPE, 3);
    assert_eq!(CoseHeaderMap::KID, 4);
    assert_eq!(CoseHeaderMap::IV, 5);
    assert_eq!(CoseHeaderMap::PARTIAL_IV, 6);
}