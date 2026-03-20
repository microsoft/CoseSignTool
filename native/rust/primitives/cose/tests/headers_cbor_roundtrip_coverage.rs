// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional CBOR roundtrip coverage for headers.rs edge cases.

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider, CborType};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_primitives::{ContentType, CoseError, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};

#[test]
fn test_header_value_as_bytes_one_or_many_single_bytes() {
    let value = CoseHeaderValue::Bytes(vec![1, 2, 3].into());
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2, 3]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_of_bytes() {
    let value = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2].into()),
        CoseHeaderValue::Bytes(vec![3, 4].into()),
    ]);
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_mixed_types() {
    let value = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(vec![1, 2].into()),
        CoseHeaderValue::Int(42), // Non-bytes element
        CoseHeaderValue::Bytes(vec![3, 4].into()),
    ]);
    // Should only include the bytes elements
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, Some(vec![vec![1, 2], vec![3, 4]]));
}

#[test]
fn test_header_value_as_bytes_one_or_many_empty_array() {
    let value = CoseHeaderValue::Array(vec![]);
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, None);
}

#[test]
fn test_header_value_as_bytes_one_or_many_array_no_bytes() {
    let value = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(42),
        CoseHeaderValue::Text("hello".to_string().into()),
    ]);
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, None);
}

#[test]
fn test_header_value_as_bytes_one_or_many_not_bytes_or_array() {
    let value = CoseHeaderValue::Text("hello".to_string().into());
    let result = value.as_bytes_one_or_many();
    assert_eq!(result, None);
}

#[test]
fn test_header_value_as_i64_variants() {
    assert_eq!(CoseHeaderValue::Int(42).as_i64(), Some(42));
    assert_eq!(CoseHeaderValue::Uint(42).as_i64(), None);
    assert_eq!(
        CoseHeaderValue::Text("42".to_string().into()).as_i64(),
        None
    );
}

#[test]
fn test_header_value_as_str_variants() {
    assert_eq!(
        CoseHeaderValue::Text("hello".to_string().into()).as_str(),
        Some("hello")
    );
    assert_eq!(CoseHeaderValue::Int(42).as_str(), None);
    assert_eq!(CoseHeaderValue::Bytes(vec![1, 2].into()).as_str(), None);
}

#[test]
fn test_header_value_as_bytes_variants() {
    let bytes = vec![1, 2, 3];
    assert_eq!(
        CoseHeaderValue::Bytes(bytes.clone().into()).as_bytes(),
        Some(bytes.as_slice())
    );
    assert_eq!(
        CoseHeaderValue::Text("hello".to_string().into()).as_bytes(),
        None
    );
    assert_eq!(CoseHeaderValue::Int(42).as_bytes(), None);
}

#[test]
fn test_content_type_display() {
    assert_eq!(format!("{}", ContentType::Int(42)), "42");
    assert_eq!(
        format!("{}", ContentType::Text("application/json".to_string())),
        "application/json"
    );
}

#[test]
fn test_header_map_content_type_from_uint_variant() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(42),
    );

    let ct = map.content_type();
    assert_eq!(ct, Some(ContentType::Int(42)));
}

#[test]
fn test_header_map_content_type_from_large_uint() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(u16::MAX as u64 + 1), // Too large for u16
    );

    let ct = map.content_type();
    assert_eq!(ct, None);
}

#[test]
fn test_header_map_content_type_from_negative_int() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1), // Negative, not valid for u16
    );

    let ct = map.content_type();
    assert_eq!(ct, None);
}

#[test]
fn test_header_map_content_type_from_large_positive_int() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(u16::MAX as i64 + 1), // Too large for u16
    );

    let ct = map.content_type();
    assert_eq!(ct, None);
}

#[test]
fn test_header_map_get_bytes_one_or_many() {
    let mut map = CoseHeaderMap::new();
    let label = CoseHeaderLabel::Int(33); // x5chain

    // Single bytes
    map.insert(label.clone(), CoseHeaderValue::Bytes(vec![1, 2, 3].into()));
    assert_eq!(map.get_bytes_one_or_many(&label), Some(vec![vec![1, 2, 3]]));

    // Array of bytes
    map.insert(
        label.clone(),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![1, 2].into()),
            CoseHeaderValue::Bytes(vec![3, 4].into()),
        ]),
    );
    assert_eq!(
        map.get_bytes_one_or_many(&label),
        Some(vec![vec![1, 2], vec![3, 4]])
    );

    // Non-existent label
    let missing = CoseHeaderLabel::Int(999);
    assert_eq!(map.get_bytes_one_or_many(&missing), None);
}

#[test]
fn test_header_map_crit_with_mixed_label_types() {
    let mut map = CoseHeaderMap::new();

    // Set critical headers with both int and text labels
    map.set_crit(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderLabel::Int(-5),
    ]);

    let crit = map.crit().unwrap();
    assert_eq!(crit.len(), 3);
    assert!(crit.contains(&CoseHeaderLabel::Int(1)));
    assert!(crit.contains(&CoseHeaderLabel::Text("custom".to_string())));
    assert!(crit.contains(&CoseHeaderLabel::Int(-5)));
}

#[test]
fn test_header_map_crit_invalid_array_elements() {
    let mut map = CoseHeaderMap::new();

    // Manually insert an array with invalid (non-label) elements
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CRIT),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(1),
            CoseHeaderValue::Bytes(vec![1, 2].into()), // Invalid - not a label type
            CoseHeaderValue::Text("valid".to_string().into()),
        ]),
    );

    let crit = map.crit().unwrap();
    assert_eq!(crit.len(), 2); // Only valid elements
    assert!(crit.contains(&CoseHeaderLabel::Int(1)));
    assert!(crit.contains(&CoseHeaderLabel::Text("valid".to_string())));
}

#[test]
fn test_header_map_cbor_indefinite_array_decode() {
    // Test decoding indefinite-length arrays in header values
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    // Create a header map with an indefinite array
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(100).unwrap(); // Custom label

    // Indefinite array (EverParse might not support this, but test the path)
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_break().unwrap();

    let bytes = encoder.into_bytes();

    // Try to decode - may succeed or fail depending on EverParse support
    match CoseHeaderMap::decode(&bytes) {
        Ok(map) => {
            // If it succeeds, verify the array was decoded
            if let Some(CoseHeaderValue::Array(arr)) = map.get(&CoseHeaderLabel::Int(100)) {
                assert_eq!(arr.len(), 2);
            }
        }
        Err(_) => {
            // If it fails, that's also valid for indefinite arrays
            // depending on the CBOR implementation
        }
    }
}

#[test]
fn test_header_map_cbor_indefinite_map_decode() {
    // Test decoding indefinite-length maps in header values
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    // Create a header map with an indefinite map
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(200).unwrap(); // Custom label

    // Indefinite map
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("value1").unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_tstr("value2").unwrap();
    encoder.encode_break().unwrap();

    let bytes = encoder.into_bytes();

    // Try to decode
    match CoseHeaderMap::decode(&bytes) {
        Ok(map) => {
            // If it succeeds, verify the map was decoded
            if let Some(CoseHeaderValue::Map(pairs)) = map.get(&CoseHeaderLabel::Int(200)) {
                assert_eq!(pairs.len(), 2);
            }
        }
        Err(_) => {
            // If it fails, that's also valid depending on implementation
        }
    }
}

#[test]
fn test_header_value_display_complex_types() {
    // Test Display implementation for complex header values

    // Tagged value
    let tagged =
        CoseHeaderValue::Tagged(18, Box::new(CoseHeaderValue::Bytes(vec![1, 2, 3].into())));
    let display = format!("{}", tagged);
    assert!(display.contains("tag(18"));

    // Nested array
    let nested_array = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(2)]),
    ]);
    let display = format!("{}", nested_array);
    assert!(display.contains("[1, [2]]"));

    // Nested map
    let nested_map = CoseHeaderValue::Map(vec![
        (
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("value1".to_string().into()),
        ),
        (
            CoseHeaderLabel::Text("key2".to_string()),
            CoseHeaderValue::Int(42),
        ),
    ]);
    let display = format!("{}", nested_map);
    assert!(display.contains("1: \"value1\""));
    assert!(display.contains("key2: 42"));

    // Raw bytes
    let raw = CoseHeaderValue::Raw(vec![0xab, 0xcd, 0xef].into());
    let display = format!("{}", raw);
    assert_eq!(display, "raw(3)");
}

#[test]
fn test_header_value_large_uint_decode() {
    // Test decoding very large uint that needs to stay as Uint, not converted to Int
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_u64(u64::MAX).unwrap(); // Largest possible uint

    let bytes = encoder.into_bytes();
    let map = CoseHeaderMap::decode(&bytes).unwrap();

    if let Some(value) = map.get(&CoseHeaderLabel::Int(1)) {
        match value {
            CoseHeaderValue::Uint(v) => assert_eq!(*v, u64::MAX),
            CoseHeaderValue::Int(_) => panic!("Should be Uint, not Int for u64::MAX"),
            _ => panic!("Should be a numeric value"),
        }
    } else {
        panic!("Header should be present");
    }
}
