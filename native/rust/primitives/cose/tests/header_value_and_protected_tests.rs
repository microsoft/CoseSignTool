// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoseHeaderValue with ArcSlice/ArcStr, CoseHeaderMap::decode_shared,
//! and ProtectedHeader encode/decode roundtrip.

use std::sync::Arc;

use cose_primitives::{
    ArcSlice, ArcStr, ContentType, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader,
};

// ============================================================================
// CoseHeaderValue with ArcSlice / ArcStr
// ============================================================================

#[test]
fn header_value_bytes_arc_slice() {
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let arc_slice = ArcSlice::from(data.clone());
    let val = CoseHeaderValue::Bytes(arc_slice);
    assert_eq!(val.as_bytes(), Some(data.as_slice()));
}

#[test]
fn header_value_text_arc_str() {
    let text = "hello world".to_string();
    let arc_str = ArcStr::from(text.clone());
    let val = CoseHeaderValue::Text(arc_str);
    assert_eq!(val.as_str(), Some("hello world"));
}

#[test]
fn header_value_bytes_from_vec() {
    let val = CoseHeaderValue::from(vec![1, 2, 3]);
    assert_eq!(val.as_bytes(), Some([1, 2, 3].as_slice()));
}

#[test]
fn header_value_bytes_from_slice_ref() {
    let val = CoseHeaderValue::from(&[4, 5, 6][..]);
    assert_eq!(val.as_bytes(), Some([4, 5, 6].as_slice()));
}

#[test]
fn header_value_text_from_string() {
    let val = CoseHeaderValue::from("test".to_string());
    assert_eq!(val.as_str(), Some("test"));
}

#[test]
fn header_value_text_from_str_ref() {
    let val = CoseHeaderValue::from("text");
    assert_eq!(val.as_str(), Some("text"));
}

#[test]
fn header_value_int() {
    let val = CoseHeaderValue::Int(-7);
    assert_eq!(val.as_i64(), Some(-7));
    assert!(val.as_bytes().is_none());
    assert!(val.as_str().is_none());
}

#[test]
fn header_value_uint() {
    let val = CoseHeaderValue::Uint(42);
    // Uint variant does NOT map via as_i64 (only Int does)
    assert!(val.as_i64().is_none());
    match val {
        CoseHeaderValue::Uint(v) => assert_eq!(v, 42),
        _ => panic!("expected Uint variant"),
    }
}

#[test]
fn header_value_bool_true() {
    let val = CoseHeaderValue::Bool(true);
    assert!(val.as_bytes().is_none());
    assert!(val.as_str().is_none());
    assert!(val.as_i64().is_none());
}

#[test]
fn header_value_bool_false() {
    let val = CoseHeaderValue::Bool(false);
    assert!(val.as_i64().is_none());
}

#[test]
fn header_value_null() {
    let val = CoseHeaderValue::Null;
    assert!(val.as_bytes().is_none());
    assert!(val.as_str().is_none());
    assert!(val.as_i64().is_none());
}

#[test]
fn header_value_from_i64() {
    let val = CoseHeaderValue::from(-35i64);
    assert_eq!(val.as_i64(), Some(-35));
}

#[test]
fn header_value_from_u64() {
    let val = CoseHeaderValue::from(100u64);
    match val {
        CoseHeaderValue::Uint(v) => assert_eq!(v, 100),
        _ => panic!("expected Uint variant"),
    }
}

#[test]
fn header_value_from_bool() {
    let val = CoseHeaderValue::from(true);
    match val {
        CoseHeaderValue::Bool(b) => assert!(b),
        _ => panic!("expected Bool variant"),
    }
}

#[test]
fn header_value_as_bytes_one_or_many_single() {
    let val = CoseHeaderValue::Bytes(ArcSlice::from(vec![1, 2, 3]));
    let result = val.as_bytes_one_or_many();
    assert!(result.is_some());
    let vecs = result.unwrap();
    assert_eq!(vecs.len(), 1);
    assert_eq!(vecs[0], vec![1, 2, 3]);
}

#[test]
fn header_value_as_bytes_one_or_many_array() {
    let val = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Bytes(ArcSlice::from(vec![1, 2])),
        CoseHeaderValue::Bytes(ArcSlice::from(vec![3, 4])),
    ]);
    let result = val.as_bytes_one_or_many();
    assert!(result.is_some());
    let vecs = result.unwrap();
    assert_eq!(vecs.len(), 2);
    assert_eq!(vecs[0], vec![1, 2]);
    assert_eq!(vecs[1], vec![3, 4]);
}

// ============================================================================
// CoseHeaderMap::decode_shared — zero-copy path
// ============================================================================

#[test]
fn decode_shared_creates_arc_values() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"kid-data".to_vec());

    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let arc: Arc<[u8]> = Arc::from(encoded);

    let decoded = CoseHeaderMap::decode_shared(&arc, 0..len).unwrap();
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"kid-data".as_slice()));
}

#[test]
fn decode_shared_text_header_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Text(ArcStr::from("shared-text")),
    );
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let arc: Arc<[u8]> = Arc::from(encoded);

    let decoded = CoseHeaderMap::decode_shared(&arc, 0..len).unwrap();
    let val = decoded.get(&CoseHeaderLabel::Int(100)).unwrap();
    assert_eq!(val.as_str(), Some("shared-text"));
}

#[test]
fn decode_shared_empty_map() {
    let map = CoseHeaderMap::new();
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let arc: Arc<[u8]> = Arc::from(encoded);

    let decoded = CoseHeaderMap::decode_shared(&arc, 0..len).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn decode_shared_with_offset_range() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-35);
    let encoded = map.encode().unwrap();

    // Embed encoded map at an offset inside a larger buffer
    let mut padded = vec![0xFF; 10];
    let start = padded.len();
    padded.extend_from_slice(&encoded);
    let end = padded.len();
    padded.extend_from_slice(&[0xFF; 10]);

    let arc: Arc<[u8]> = Arc::from(padded);
    let decoded = CoseHeaderMap::decode_shared(&arc, start..end).unwrap();
    assert_eq!(decoded.alg(), Some(-35));
}

// ============================================================================
// ProtectedHeader encode/decode roundtrip
// ============================================================================

#[test]
fn protected_header_encode_decode_roundtrip() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"test-key".to_vec());

    let protected = ProtectedHeader::encode(headers).unwrap();
    assert!(!protected.as_bytes().is_empty());
    assert_eq!(protected.alg(), Some(-7));
    assert_eq!(protected.kid(), Some(b"test-key".as_slice()));

    // Decode from raw bytes
    let decoded = ProtectedHeader::decode(protected.as_bytes().to_vec()).unwrap();
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"test-key".as_slice()));
    assert_eq!(decoded.as_bytes(), protected.as_bytes());
}

#[test]
fn protected_header_as_bytes_roundtrip() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-36);

    let protected = ProtectedHeader::encode(headers).unwrap();
    let raw = protected.as_bytes().to_vec();
    let decoded = ProtectedHeader::decode(raw).unwrap();
    assert_eq!(decoded.alg(), Some(-36));
}

#[test]
fn protected_header_empty() {
    let headers = CoseHeaderMap::new();
    let protected = ProtectedHeader::encode(headers).unwrap();
    assert!(protected.is_empty());
    assert!(protected.alg().is_none());
    assert!(protected.kid().is_none());
}

#[test]
fn protected_header_headers_accessor() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let protected = ProtectedHeader::encode(headers).unwrap();
    let h = protected.headers();
    assert_eq!(h.alg(), Some(-7));
}

#[test]
fn protected_header_headers_mut() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let mut protected = ProtectedHeader::encode(headers).unwrap();
    protected.headers_mut().set_alg(-35);
    assert_eq!(protected.headers().alg(), Some(-35));
}

#[test]
fn protected_header_get() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let protected = ProtectedHeader::encode(headers).unwrap();
    let val = protected.get(&CoseHeaderLabel::Int(1)); // ALG label
    assert!(val.is_some());
}

#[test]
fn protected_header_content_type_int() {
    let mut headers = CoseHeaderMap::new();
    headers.set_content_type(ContentType::Int(42));
    let protected = ProtectedHeader::encode(headers).unwrap();
    let ct = protected.content_type();
    assert!(ct.is_some());
}

#[test]
fn protected_header_content_type_text() {
    let mut headers = CoseHeaderMap::new();
    headers.set_content_type(ContentType::Text("application/json".to_string()));
    let protected = ProtectedHeader::encode(headers).unwrap();
    let ct = protected.content_type();
    assert!(ct.is_some());
}

#[test]
fn protected_header_default() {
    let protected = ProtectedHeader::default();
    assert!(protected.is_empty());
    assert!(protected.as_bytes().is_empty());
}

#[test]
fn protected_header_clone() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let protected = ProtectedHeader::encode(headers).unwrap();
    let cloned = protected.clone();
    assert_eq!(cloned.alg(), protected.alg());
    assert_eq!(cloned.as_bytes(), protected.as_bytes());
}

#[test]
fn protected_header_debug() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let protected = ProtectedHeader::encode(headers).unwrap();
    let dbg = format!("{:?}", protected);
    assert!(dbg.contains("ProtectedHeader"));
}
