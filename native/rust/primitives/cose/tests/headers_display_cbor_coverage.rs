// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive headers Display and CBOR roundtrip tests.

use cose_primitives::{
    CoseHeaderLabel, CoseHeaderValue, CoseHeaderMap, ContentType, ProtectedHeader,
};

#[test]
fn test_header_label_display() {
    let int_label = CoseHeaderLabel::Int(42);
    assert_eq!(format!("{}", int_label), "42");
    
    let text_label = CoseHeaderLabel::Text("custom-header".to_string());
    assert_eq!(format!("{}", text_label), "custom-header");
    
    let negative_int = CoseHeaderLabel::Int(-1);
    assert_eq!(format!("{}", negative_int), "-1");
}

#[test]
fn test_header_value_display() {
    // Test Int display
    let int_val = CoseHeaderValue::Int(42);
    assert_eq!(format!("{}", int_val), "42");
    
    // Test Uint display 
    let uint_val = CoseHeaderValue::Uint(u64::MAX);
    assert_eq!(format!("{}", uint_val), format!("{}", u64::MAX));
    
    // Test Bytes display
    let bytes_val = CoseHeaderValue::Bytes(vec![1, 2, 3, 4, 5]);
    assert_eq!(format!("{}", bytes_val), "bytes(5)");
    
    // Test Text display
    let text_val = CoseHeaderValue::Text("hello world".to_string());
    assert_eq!(format!("{}", text_val), "\"hello world\"");
    
    // Test Bool display
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
    assert_eq!(format!("{}", CoseHeaderValue::Bool(false)), "false");
    
    // Test Null and Undefined
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
    
    // Test Float display
    let float_val = CoseHeaderValue::Float(3.14159);
    assert_eq!(format!("{}", float_val), "3.14159");
    
    // Test Raw display
    let raw_val = CoseHeaderValue::Raw(vec![0x01, 0x02, 0x03]);
    assert_eq!(format!("{}", raw_val), "raw(3)");
}

#[test]
fn test_header_value_array_display() {
    let array_val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Text("test".to_string()),
        CoseHeaderValue::Bool(true),
    ]);
    assert_eq!(format!("{}", array_val), "[1, \"test\", true]");
    
    // Test empty array
    let empty_array = CoseHeaderValue::Array(vec![]);
    assert_eq!(format!("{}", empty_array), "[]");
}

#[test]
fn test_header_value_map_display() {
    let map_val = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("alg".to_string())),
        (CoseHeaderLabel::Text("custom".to_string()), CoseHeaderValue::Int(42)),
    ]);
    assert_eq!(format!("{}", map_val), "{1: \"alg\", custom: 42}");
    
    // Test empty map
    let empty_map = CoseHeaderValue::Map(vec![]);
    assert_eq!(format!("{}", empty_map), "{}");
}

#[test]
fn test_header_value_tagged_display() {
    let tagged_val = CoseHeaderValue::Tagged(
        18, 
        Box::new(CoseHeaderValue::Text("tagged content".to_string()))
    );
    assert_eq!(format!("{}", tagged_val), "tag(18, \"tagged content\")");
    
    // Test nested tagged values
    let nested_tagged = CoseHeaderValue::Tagged(
        100,
        Box::new(CoseHeaderValue::Tagged(
            200,
            Box::new(CoseHeaderValue::Int(42))
        ))
    );
    assert_eq!(format!("{}", nested_tagged), "tag(100, tag(200, 42))");
}

#[test]
fn test_content_type_display() {
    let int_ct = ContentType::Int(1234);
    assert_eq!(format!("{}", int_ct), "1234");
    
    let text_ct = ContentType::Text("application/json".to_string());
    assert_eq!(format!("{}", text_ct), "application/json");
}

#[test]
fn test_cbor_roundtrip_all_header_value_types() {
    let test_values = vec![
        CoseHeaderValue::Int(i64::MIN),
        CoseHeaderValue::Int(i64::MAX),
        CoseHeaderValue::Int(0),
        CoseHeaderValue::Int(-1),
        CoseHeaderValue::Uint(u64::MAX),
        CoseHeaderValue::Bytes(vec![]),
        CoseHeaderValue::Bytes(vec![1, 2, 3, 255]),
        CoseHeaderValue::Text(String::new()),
        CoseHeaderValue::Text("test string".to_string()),
        CoseHeaderValue::Text("UTF-8: 测试".to_string()),
        CoseHeaderValue::Bool(true),
        CoseHeaderValue::Bool(false),
        CoseHeaderValue::Null,
        CoseHeaderValue::Undefined,
        // Skip Float as EverParse doesn't support encode_f64
        CoseHeaderValue::Array(vec![]),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Text("nested".to_string()),
        ]),
        CoseHeaderValue::Map(vec![]),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("value1".to_string())),
            (CoseHeaderLabel::Text("key2".to_string()), CoseHeaderValue::Int(42)),
        ]),
        CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Int(42))),
    ];
    
    for (i, original) in test_values.iter().enumerate() {
        let mut map = CoseHeaderMap::new();
        map.insert(CoseHeaderLabel::Int(i as i64), original.clone());
        
        // Encode to CBOR
        let encoded = map.encode().expect("should encode successfully");
        
        // Decode back
        let decoded_map = CoseHeaderMap::decode(&encoded).expect("should decode successfully");
        let decoded_value = decoded_map.get(&CoseHeaderLabel::Int(i as i64))
            .expect("should find the value");
        
        assert_eq!(original, decoded_value, "Roundtrip failed for value #{}: {:?}", i, original);
    }
}

#[test] 
fn test_cbor_roundtrip_complex_nested_structures() {
    // Test complex nested array
    let complex_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Text("nested".to_string())),
            (CoseHeaderLabel::Text("array".to_string()), CoseHeaderValue::Array(vec![
                CoseHeaderValue::Int(1),
                CoseHeaderValue::Int(2),
                CoseHeaderValue::Int(3),
            ])),
        ]),
        CoseHeaderValue::Tagged(999, Box::new(CoseHeaderValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]))),
    ]);
    
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Text("complex".to_string()), complex_array.clone());
    
    let encoded = map.encode().expect("should encode");
    let decoded_map = CoseHeaderMap::decode(&encoded).expect("should decode");
    let decoded_value = decoded_map.get(&CoseHeaderLabel::Text("complex".to_string()))
        .expect("should find complex value");
    
    assert_eq!(&complex_array, decoded_value);
}

#[test]
fn test_header_value_as_bytes_one_or_many_edge_cases() {
    // Test single bytes
    let single_bytes = CoseHeaderValue::Bytes(vec![1, 2, 3]);
    let result = single_bytes.as_bytes_one_or_many().expect("should extract bytes");
    assert_eq!(result, vec![vec![1, 2, 3]]);
    
    // Test array of bytes
    let array_bytes = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Bytes(vec![3, 4, 5]),
        CoseHeaderValue::Bytes(vec![]),
    ]);
    let result = array_bytes.as_bytes_one_or_many().expect("should extract bytes array");
    assert_eq!(result, vec![vec![1, 2], vec![3, 4, 5], vec![]]);
    
    // Test mixed array (non-bytes elements are skipped)
    let mixed_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2]),
        CoseHeaderValue::Int(42), // Not bytes, will be skipped
        CoseHeaderValue::Bytes(vec![3, 4]),
    ]);
    let result = mixed_array.as_bytes_one_or_many().expect("should extract bytes from mixed array");
    assert_eq!(result, vec![vec![1, 2], vec![3, 4]]);
    
    // Test empty array
    let empty_array = CoseHeaderValue::Array(vec![]);
    assert_eq!(empty_array.as_bytes_one_or_many(), None);
    
    // Test non-bytes, non-array
    let text_value = CoseHeaderValue::Text("not bytes".to_string());
    assert_eq!(text_value.as_bytes_one_or_many(), None);
}

#[test]
fn test_content_type_edge_cases() {
    let mut map = CoseHeaderMap::new();
    
    // Test integer content type at boundaries
    map.set_content_type(ContentType::Int(0));
    assert_eq!(map.content_type(), Some(ContentType::Int(0)));
    
    map.set_content_type(ContentType::Int(u16::MAX));
    assert_eq!(map.content_type(), Some(ContentType::Int(u16::MAX)));
    
    // Test text content type
    map.set_content_type(ContentType::Text("application/cbor".to_string()));
    assert_eq!(map.content_type(), Some(ContentType::Text("application/cbor".to_string())));
    
    // Test invalid integer ranges (manual insertion)
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Int(-1));
    assert_eq!(map.content_type(), None);
    
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Int(u16::MAX as i64 + 1));
    assert_eq!(map.content_type(), None);
    
    // Test uint content type at boundary
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Uint(u16::MAX as u64));
    assert_eq!(map.content_type(), Some(ContentType::Int(u16::MAX)));
    
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE), CoseHeaderValue::Uint(u16::MAX as u64 + 1));
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_protected_header_encoding_decoding() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7); // ES256
    headers.set_kid(b"test-key-id");
    headers.set_content_type(ContentType::Text("application/json".to_string()));
    
    // Test encoding
    let protected = ProtectedHeader::encode(headers.clone()).expect("should encode");
    
    // Verify raw bytes and parsed headers match
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"test-key-id".as_slice()));
    assert_eq!(protected.content_type(), Some(ContentType::Text("application/json".to_string())));
    assert!(!protected.is_empty());
    
    // Test decoding from raw bytes
    let raw_bytes = protected.as_bytes().to_vec();
    let decoded = ProtectedHeader::decode(raw_bytes).expect("should decode");
    
    assert_eq!(decoded.alg(), protected.alg());
    assert_eq!(decoded.kid(), protected.kid());
    assert_eq!(decoded.content_type(), protected.content_type());
    
    // Test empty protected header
    let empty_protected = ProtectedHeader::decode(vec![]).expect("should handle empty");
    assert!(empty_protected.is_empty());
    assert_eq!(empty_protected.alg(), None);
    assert_eq!(empty_protected.kid(), None);
}