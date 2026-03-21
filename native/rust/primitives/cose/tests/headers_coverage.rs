// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for COSE headers.

use cose_primitives::{
    ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};

#[test]
fn test_header_label_from_int() {
    let label = CoseHeaderLabel::from(42i64);
    assert_eq!(label, CoseHeaderLabel::Int(42));
}

#[test]
fn test_header_label_from_str() {
    let label = CoseHeaderLabel::from("custom");
    assert_eq!(label, CoseHeaderLabel::Text("custom".to_string()));
}

#[test]
fn test_header_label_from_string() {
    let label = CoseHeaderLabel::from("custom".to_string());
    assert_eq!(label, CoseHeaderLabel::Text("custom".to_string()));
}

#[test]
fn test_header_label_ordering() {
    let mut labels = vec![
        CoseHeaderLabel::Text("z".to_string()),
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("a".to_string()),
        CoseHeaderLabel::Int(-1),
    ];
    labels.sort();

    // Should sort integers before text, then by value
    assert_eq!(labels[0], CoseHeaderLabel::Int(-1));
    assert_eq!(labels[1], CoseHeaderLabel::Int(1));
    assert_eq!(labels[2], CoseHeaderLabel::Text("a".to_string()));
    assert_eq!(labels[3], CoseHeaderLabel::Text("z".to_string()));
}

#[test]
fn test_header_value_from_conversions() {
    assert_eq!(CoseHeaderValue::from(42i64), CoseHeaderValue::Int(42));
    assert_eq!(CoseHeaderValue::from(42u64), CoseHeaderValue::Uint(42));
    assert_eq!(
        CoseHeaderValue::from(vec![1u8, 2, 3]),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into())
    );
    assert_eq!(
        CoseHeaderValue::from(&[1u8, 2, 3][..]),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into())
    );
    assert_eq!(
        CoseHeaderValue::from("test".to_string()),
        CoseHeaderValue::Text("test".to_string().into())
    );
    assert_eq!(
        CoseHeaderValue::from("test"),
        CoseHeaderValue::Text("test".to_string().into())
    );
    assert_eq!(CoseHeaderValue::from(true), CoseHeaderValue::Bool(true));
}

#[test]
fn test_header_value_as_bytes() {
    let bytes_value = CoseHeaderValue::Bytes(vec![1, 2, 3].into());
    assert_eq!(bytes_value.as_bytes(), Some([1u8, 2, 3].as_slice()));

    let int_value = CoseHeaderValue::Int(42);
    assert_eq!(int_value.as_bytes(), None);
}

#[test]
fn test_header_value_as_bytes_one_or_many() {
    // Single bytes
    let bytes_value = CoseHeaderValue::Bytes(vec![1, 2, 3].into());
    assert_eq!(
        bytes_value.as_bytes_one_or_many(),
        Some(vec![vec![1, 2, 3]])
    );

    // Array of bytes
    let array_value = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2].into()),
        CoseHeaderValue::Bytes(vec![3, 4].into()),
    ]);
    assert_eq!(
        array_value.as_bytes_one_or_many(),
        Some(vec![vec![1, 2], vec![3, 4]])
    );

    // Mixed array (should return only bytes elements, filtering out non-bytes)
    let mixed_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2].into()),
        CoseHeaderValue::Int(42),
    ]);
    assert_eq!(mixed_array.as_bytes_one_or_many(), Some(vec![vec![1, 2]]));

    // Empty array
    let empty_array = CoseHeaderValue::Array(vec![]);
    assert_eq!(empty_array.as_bytes_one_or_many(), None);

    // Non-compatible type
    let int_value = CoseHeaderValue::Int(42);
    assert_eq!(int_value.as_bytes_one_or_many(), None);
}

#[test]
fn test_header_value_as_int() {
    let int_value = CoseHeaderValue::Int(42);
    assert_eq!(int_value.as_i64(), Some(42));

    let text_value = CoseHeaderValue::Text("test".to_string().into());
    assert_eq!(text_value.as_i64(), None);
}

#[test]
fn test_header_value_as_str() {
    let text_value = CoseHeaderValue::Text("hello".to_string().into());
    assert_eq!(text_value.as_str(), Some("hello"));

    let int_value = CoseHeaderValue::Int(42);
    assert_eq!(int_value.as_str(), None);
}

#[test]
fn test_content_type() {
    let int_ct = ContentType::Int(123);
    let text_ct = ContentType::Text("application/json".to_string());

    assert_eq!(int_ct, ContentType::Int(123));
    assert_eq!(text_ct, ContentType::Text("application/json".to_string()));

    // Test debug formatting
    let debug_str = format!("{:?}", int_ct);
    assert!(debug_str.contains("Int(123)"));
}

#[test]
fn test_header_map_new() {
    let map = CoseHeaderMap::new();
    assert!(map.is_empty());
    assert_eq!(map.len(), 0);
}

#[test]
fn test_header_map_default() {
    let map: CoseHeaderMap = Default::default();
    assert!(map.is_empty());
}

#[test]
fn test_header_map_alg() {
    let mut map = CoseHeaderMap::new();

    // Initially no algorithm
    assert_eq!(map.alg(), None);

    // Set algorithm
    map.set_alg(-7); // ES256
    assert_eq!(map.alg(), Some(-7));

    // Chaining
    let result = map.set_alg(-35);
    assert!(std::ptr::eq(result, &map)); // Should return self for chaining
    assert_eq!(map.alg(), Some(-35));
}

#[test]
fn test_header_map_kid() {
    let mut map = CoseHeaderMap::new();

    // Initially no key ID
    assert_eq!(map.kid(), None);

    // Set key ID with Vec<u8>
    map.set_kid(vec![1, 2, 3, 4]);
    assert_eq!(map.kid(), Some([1u8, 2, 3, 4].as_slice()));

    // Set key ID with &[u8]
    map.set_kid(&[5, 6, 7, 8]);
    assert_eq!(map.kid(), Some([5u8, 6, 7, 8].as_slice()));
}

#[test]
fn test_header_map_content_type() {
    let mut map = CoseHeaderMap::new();

    // Initially no content type
    assert_eq!(map.content_type(), None);

    // Set integer content type
    map.set_content_type(ContentType::Int(123));
    assert_eq!(map.content_type(), Some(ContentType::Int(123)));

    // Set text content type
    map.set_content_type(ContentType::Text("application/json".to_string()));
    assert_eq!(
        map.content_type(),
        Some(ContentType::Text("application/json".to_string()))
    );
}

#[test]
fn test_header_map_critical_headers() {
    let mut map = CoseHeaderMap::new();

    // Initially no critical headers
    assert_eq!(map.crit(), None);

    // Set critical headers
    let labels = vec![
        CoseHeaderLabel::Int(4), // kid
        CoseHeaderLabel::Text("custom".to_string()),
    ];
    map.set_crit(labels.clone());

    let retrieved = map.crit().expect("should have critical headers");
    assert_eq!(retrieved.len(), 2);
    assert!(retrieved.contains(&CoseHeaderLabel::Int(4)));
    assert!(retrieved.contains(&CoseHeaderLabel::Text("custom".to_string())));
}

#[test]
fn test_header_map_generic_operations() {
    let mut map = CoseHeaderMap::new();

    // Insert and get
    map.insert(
        CoseHeaderLabel::Int(42),
        CoseHeaderValue::Text("test".to_string().into()),
    );

    let value = map.get(&CoseHeaderLabel::Int(42));
    assert_eq!(
        value,
        Some(&CoseHeaderValue::Text("test".to_string().into()))
    );

    // Check if contains key
    assert!(map.get(&CoseHeaderLabel::Int(42)).is_some());
    assert!(map.get(&CoseHeaderLabel::Int(43)).is_none());

    // Check length
    assert_eq!(map.len(), 1);
    assert!(!map.is_empty());

    // Remove
    let removed = map.remove(&CoseHeaderLabel::Int(42));
    assert_eq!(
        removed,
        Some(CoseHeaderValue::Text("test".to_string().into()))
    );
    assert!(map.is_empty());
}

#[test]
fn test_header_map_iteration() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-7));
    map.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()),
    );

    let mut count = 0;
    for (label, value) in map.iter() {
        count += 1;
        match label {
            CoseHeaderLabel::Int(1) => assert_eq!(value, &CoseHeaderValue::Int(-7)),
            CoseHeaderLabel::Int(4) => {
                assert_eq!(value, &CoseHeaderValue::Bytes(vec![1, 2, 3].into()))
            }
            _ => panic!("unexpected label"),
        }
    }
    assert_eq!(count, 2);
}

#[test]
fn test_header_map_encode_decode_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(vec![1, 2, 3, 4]);
    map.set_content_type(ContentType::Text("application/json".to_string()));
    map.insert(
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderValue::Bool(true),
    );

    // Encode
    let encoded = map.encode().expect("encoding should succeed");
    assert!(!encoded.is_empty());

    // Decode
    let decoded = CoseHeaderMap::decode(&encoded).expect("decoding should succeed");

    // Check that values match
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some([1u8, 2, 3, 4].as_slice()));
    assert_eq!(
        decoded.content_type(),
        Some(ContentType::Text("application/json".to_string()))
    );

    let custom_value = decoded.get(&CoseHeaderLabel::Text("custom".to_string()));
    assert_eq!(custom_value, Some(&CoseHeaderValue::Bool(true)));
}

#[test]
fn test_header_map_all_value_types() {
    let mut map = CoseHeaderMap::new();

    // Test supported header value types
    // (excluding Float and Raw, as they have encoding/decoding limitations)
    map.insert(CoseHeaderLabel::Int(1), CoseHeaderValue::Int(-42));
    map.insert(CoseHeaderLabel::Int(2), CoseHeaderValue::Uint(42));
    map.insert(
        CoseHeaderLabel::Int(3),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()),
    );
    map.insert(
        CoseHeaderLabel::Int(4),
        CoseHeaderValue::Text("hello".to_string().into()),
    );
    map.insert(CoseHeaderLabel::Int(5), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(6), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(7), CoseHeaderValue::Undefined);
    map.insert(
        CoseHeaderLabel::Int(9),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Text("nested".to_string().into()),
        ]),
    );
    map.insert(
        CoseHeaderLabel::Int(10),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Text("key".to_string()),
            CoseHeaderValue::Text("value".to_string().into()),
        )]),
    );
    map.insert(
        CoseHeaderLabel::Int(11),
        CoseHeaderValue::Tagged(
            42,
            Box::new(CoseHeaderValue::Text("tagged".to_string().into())),
        ),
    );

    // Encode and decode
    let encoded = map.encode().expect("encoding should succeed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decoding should succeed");

    // Verify all types
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Int(-42))
    );
    // Note: Small Uint values may be normalized to Int during decode
    assert!(matches!(
        decoded.get(&CoseHeaderLabel::Int(2)),
        Some(CoseHeaderValue::Int(42)) | Some(CoseHeaderValue::Uint(42))
    ));
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(3)),
        Some(&CoseHeaderValue::Bytes(vec![1, 2, 3].into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(4)),
        Some(&CoseHeaderValue::Text("hello".to_string().into()))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(5)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(6)),
        Some(&CoseHeaderValue::Null)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(7)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn test_header_map_empty_encode_decode() {
    let empty_map = CoseHeaderMap::new();

    let encoded = empty_map
        .encode()
        .expect("encoding empty map should succeed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decoding should succeed");

    assert!(decoded.is_empty());
    assert_eq!(decoded.len(), 0);
}

#[test]
fn test_protected_headers() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(vec![1, 2, 3]);

    // Create protected headers
    let protected = ProtectedHeader::encode(map.clone()).expect("encoding should succeed");

    // Should have raw bytes
    assert!(!protected.as_bytes().is_empty());

    // Decode back
    let decoded_map = protected.headers();
    assert_eq!(decoded_map.alg(), Some(-7));
    assert_eq!(decoded_map.kid(), Some([1u8, 2, 3].as_slice()));

    // Test decode from raw bytes
    let raw_bytes = protected.as_bytes().to_vec();
    let from_raw = ProtectedHeader::decode(raw_bytes).expect("decoding from raw should succeed");
    let decoded_map2 = from_raw.headers();
    assert_eq!(decoded_map2.alg(), Some(-7));
}

#[test]
fn test_header_map_decode_invalid_cbor() {
    let invalid_cbor = vec![0xFF, 0xFF]; // Invalid CBOR
    let result = CoseHeaderMap::decode(&invalid_cbor);
    assert!(result.is_err());
}

#[test]
fn test_protected_headers_decode_invalid() {
    let invalid_cbor = vec![0xFF, 0xFF];
    let result = ProtectedHeader::decode(invalid_cbor);
    assert!(result.is_err());
}

#[test]
fn test_header_value_complex_structures() {
    // Test deeply nested structures
    let nested_array = CoseHeaderValue::Array(vec![CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Tagged(
            123,
            Box::new(CoseHeaderValue::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF].into())),
        )]),
    )])]);

    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Text("complex".to_string()), nested_array);

    // Should be able to encode and decode complex structures
    let encoded = map
        .encode()
        .expect("encoding complex structure should succeed");
    let decoded = CoseHeaderMap::decode(&encoded).expect("decoding should succeed");

    let retrieved = decoded.get(&CoseHeaderLabel::Text("complex".to_string()));
    assert!(retrieved.is_some());
}

#[test]
fn test_content_type_edge_cases() {
    let mut map = CoseHeaderMap::new();

    // Test uint content type within u16 range
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(65535),
    );
    assert_eq!(map.content_type(), Some(ContentType::Int(65535)));

    // Test uint content type out of u16 range
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(65536),
    );
    assert_eq!(map.content_type(), None);

    // Test negative int content type
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1),
    );
    assert_eq!(map.content_type(), None);

    // Test int content type out of u16 range
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(65536),
    );
    assert_eq!(map.content_type(), None);
}

#[test]
fn test_critical_headers_mixed_array() {
    let mut map = CoseHeaderMap::new();

    // Set critical array with mixed types (some invalid)
    let mixed_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(4),
        CoseHeaderValue::Text("custom".to_string().into()),
        CoseHeaderValue::Bool(true),  // Invalid - should be filtered out
        CoseHeaderValue::Float(3.14), // Invalid - should be filtered out
    ]);
    map.insert(CoseHeaderLabel::Int(CoseHeaderMap::CRIT), mixed_array);

    let crit = map.crit().expect("should have critical headers");
    assert_eq!(crit.len(), 2); // Only valid labels should be included
    assert!(crit.contains(&CoseHeaderLabel::Int(4)));
    assert!(crit.contains(&CoseHeaderLabel::Text("custom".to_string())));
}

#[test]
fn test_header_map_constants() {
    // Test well-known header label constants
    assert_eq!(CoseHeaderMap::ALG, 1);
    assert_eq!(CoseHeaderMap::CRIT, 2);
    assert_eq!(CoseHeaderMap::CONTENT_TYPE, 3);
    assert_eq!(CoseHeaderMap::KID, 4);
    assert_eq!(CoseHeaderMap::IV, 5);
    assert_eq!(CoseHeaderMap::PARTIAL_IV, 6);
}
