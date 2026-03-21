// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_primitives to reach 90%.
//!
//! Focuses on:
//! - CoseData::Streamed accessors and Debug
//! - LazyHeaderMap edge cases
//! - ArcSlice / ArcStr trait impls
//! - CoseHeaderValue conversions and Display
//! - CoseError Display and Error trait
//! - ProtectedHeader edge cases
//! - ContentType Display
//! - CoseHeaderMap encode/decode for complex types

use std::sync::Arc;

use cose_primitives::headers::{ContentType, ProtectedHeader};
use cose_primitives::lazy_headers::LazyHeaderMap;
use cose_primitives::{
    ArcSlice, ArcStr, CoseData, CoseError, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue,
};

// ============================================================================
// CoseError Display and Error trait
// ============================================================================

#[test]
fn cose_error_display_io_error() {
    let err = CoseError::IoError("disk full".into());
    let msg = format!("{}", err);
    assert!(msg.contains("I/O error"));
    assert!(msg.contains("disk full"));
}

#[test]
fn cose_error_display_cbor_error() {
    let err = CoseError::CborError("bad cbor".into());
    assert!(format!("{}", err).contains("CBOR error"));
}

#[test]
fn cose_error_display_invalid_message() {
    let err = CoseError::InvalidMessage("truncated".into());
    assert!(format!("{}", err).contains("invalid message"));
}

#[test]
fn cose_error_implements_std_error() {
    let err = CoseError::IoError("test".into());
    let std_err: &dyn std::error::Error = &err;
    assert!(std_err.to_string().contains("I/O error"));
}

#[test]
fn cose_error_debug() {
    let err = CoseError::IoError("test".into());
    let dbg = format!("{:?}", err);
    assert!(dbg.contains("IoError"));
}

// ============================================================================
// CoseData::Streamed — Debug, accessors
// ============================================================================

#[test]
fn cose_data_streamed_debug() {
    // Build a minimal Streamed CoseData
    let header_buf: Arc<[u8]> = Arc::from(vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    let source: std::sync::Arc<std::sync::Mutex<Box<dyn cose_primitives::data::ReadSeek>>> =
        Arc::new(std::sync::Mutex::new(Box::new(std::io::Cursor::new(
            vec![0u8; 100],
        ))));

    let data = CoseData::Streamed {
        header_buf: header_buf.clone(),
        protected_range: 0..3,
        unprotected_range: 3..6,
        signature_range: 6..10,
        source,
        payload_offset: 42,
        payload_len: 58,
    };

    let dbg = format!("{:?}", data);
    assert!(dbg.contains("Streamed"));
    assert!(dbg.contains("header_buf_len"));
    assert!(dbg.contains("payload_offset"));
}

#[test]
fn cose_data_streamed_accessors() {
    let buf = vec![10u8, 20, 30, 40, 50];
    let header_buf: Arc<[u8]> = Arc::from(buf.clone());
    let payload_data = vec![0xAAu8; 50];

    let source: Arc<std::sync::Mutex<Box<dyn cose_primitives::data::ReadSeek>>> = Arc::new(
        std::sync::Mutex::new(Box::new(std::io::Cursor::new(payload_data.clone()))),
    );

    let data = CoseData::Streamed {
        header_buf: header_buf.clone(),
        protected_range: 0..2,
        unprotected_range: 2..3,
        signature_range: 3..5,
        source,
        payload_offset: 0,
        payload_len: 50,
    };

    assert!(data.is_streamed());
    assert_eq!(data.len(), 5);
    assert!(!data.is_empty());
    assert_eq!(data.as_bytes(), &buf[..]);
    assert_eq!(data.slice(&(0..2)), &[10, 20]);
    assert_eq!(data.arc().len(), 5);

    // stream_payload_location
    let loc = data.stream_payload_location();
    assert_eq!(loc, Some((0, 50)));

    // read_stream_payload
    let payload = data.read_stream_payload().unwrap().unwrap();
    assert_eq!(payload.len(), 50);
    assert!(payload.iter().all(|&b| b == 0xAA));
}

#[test]
fn cose_data_streamed_null_payload() {
    let header_buf: Arc<[u8]> = Arc::from(vec![1u8, 2, 3]);
    let source: Arc<std::sync::Mutex<Box<dyn cose_primitives::data::ReadSeek>>> = Arc::new(
        std::sync::Mutex::new(Box::new(std::io::Cursor::new(vec![]))),
    );

    let data = CoseData::Streamed {
        header_buf,
        protected_range: 0..1,
        unprotected_range: 1..2,
        signature_range: 2..3,
        source,
        payload_offset: 0,
        payload_len: 0, // null/detached payload
    };

    assert_eq!(data.stream_payload_location(), None);
    assert!(data.read_stream_payload().is_none());
}

#[test]
fn cose_data_buffered_stream_accessors() {
    let data = CoseData::new(vec![1, 2, 3]);
    assert!(!data.is_streamed());
    assert_eq!(data.stream_payload_location(), None);
    assert!(data.read_stream_payload().is_none());
}

#[test]
fn cose_data_clone_streamed() {
    let header_buf: Arc<[u8]> = Arc::from(vec![1u8, 2, 3]);
    let source: Arc<std::sync::Mutex<Box<dyn cose_primitives::data::ReadSeek>>> = Arc::new(
        std::sync::Mutex::new(Box::new(std::io::Cursor::new(vec![0u8; 10]))),
    );

    let data = CoseData::Streamed {
        header_buf,
        protected_range: 0..1,
        unprotected_range: 1..2,
        signature_range: 2..3,
        source,
        payload_offset: 5,
        payload_len: 10,
    };

    let cloned = data.clone();
    assert!(cloned.is_streamed());
    assert_eq!(cloned.len(), data.len());
}

// ============================================================================
// ArcSlice trait impls
// ============================================================================

#[test]
fn arc_slice_hash_and_eq() {
    use std::collections::HashSet;

    let a = ArcSlice::from(vec![1u8, 2, 3]);
    let b = ArcSlice::from(vec![1u8, 2, 3]);
    let c = ArcSlice::from(vec![4u8, 5, 6]);

    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = HashSet::new();
    set.insert(a.clone());
    assert!(set.contains(&b));
    assert!(!set.contains(&c));
}

#[test]
fn arc_slice_display() {
    let s = ArcSlice::from(vec![1u8, 2, 3]);
    let display = format!("{}", s);
    assert_eq!(display, "bytes(3)");
}

#[test]
fn arc_slice_deref_and_as_ref() {
    let s = ArcSlice::from(vec![10u8, 20]);
    let deref: &[u8] = &s;
    assert_eq!(deref, &[10, 20]);
    let as_ref: &[u8] = s.as_ref();
    assert_eq!(as_ref, &[10, 20]);
}

#[test]
fn arc_slice_from_slice() {
    let data: &[u8] = &[7, 8, 9];
    let s = ArcSlice::from(data);
    assert_eq!(s.as_bytes(), &[7, 8, 9]);
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
}

#[test]
fn arc_slice_empty() {
    let s = ArcSlice::from(vec![]);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn arc_slice_new_with_range() {
    let arc: Arc<[u8]> = Arc::from(vec![10u8, 20, 30, 40, 50]);
    let s = ArcSlice::new(arc, 1..4);
    assert_eq!(s.as_bytes(), &[20, 30, 40]);
    assert_eq!(s.len(), 3);
}

// ============================================================================
// ArcStr trait impls
// ============================================================================

#[test]
fn arc_str_hash_and_eq() {
    use std::collections::HashSet;

    let a = ArcStr::from("hello");
    let b = ArcStr::from("hello".to_string());
    let c = ArcStr::from("world");

    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = HashSet::new();
    set.insert(a.clone());
    assert!(set.contains(&b));
    assert!(!set.contains(&c));
}

#[test]
fn arc_str_display() {
    let s = ArcStr::from("test display");
    assert_eq!(format!("{}", s), "test display");
}

#[test]
fn arc_str_deref_and_as_ref() {
    let s = ArcStr::from("hello");
    let deref: &str = &s;
    assert_eq!(deref, "hello");
    let as_ref: &str = s.as_ref();
    assert_eq!(as_ref, "hello");
}

#[test]
fn arc_str_empty() {
    let s = ArcStr::from("");
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.as_str(), "");
}

#[test]
fn arc_str_new_with_range() {
    let text = "hello world";
    let arc: Arc<[u8]> = Arc::from(text.as_bytes().to_vec());
    let s = ArcStr::new(arc, 6..11);
    assert_eq!(s.as_str(), "world");
    assert_eq!(s.len(), 5);
}

// ============================================================================
// CoseHeaderValue Display and conversions
// ============================================================================

#[test]
fn header_value_display_all_variants() {
    assert_eq!(format!("{}", CoseHeaderValue::Int(42)), "42");
    assert_eq!(
        format!("{}", CoseHeaderValue::Uint(u64::MAX)),
        format!("{}", u64::MAX)
    );
    assert_eq!(format!("{}", CoseHeaderValue::Bool(true)), "true");
    assert_eq!(format!("{}", CoseHeaderValue::Null), "null");
    assert_eq!(format!("{}", CoseHeaderValue::Undefined), "undefined");
    assert_eq!(format!("{}", CoseHeaderValue::Float(3.14)), "3.14");

    let bytes_val = CoseHeaderValue::Bytes(ArcSlice::from(vec![1, 2, 3]));
    assert_eq!(format!("{}", bytes_val), "bytes(3)");

    let text_val = CoseHeaderValue::Text(ArcStr::from("hello"));
    assert_eq!(format!("{}", text_val), "\"hello\"");

    let raw_val = CoseHeaderValue::Raw(ArcSlice::from(vec![0xDE, 0xAD]));
    assert_eq!(format!("{}", raw_val), "raw(2)");

    let array_val = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1), CoseHeaderValue::Int(2)]);
    assert_eq!(format!("{}", array_val), "[1, 2]");

    let map_val = CoseHeaderValue::Map(vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10)),
        (
            CoseHeaderLabel::Text("key".into()),
            CoseHeaderValue::Bool(false),
        ),
    ]);
    let map_str = format!("{}", map_val);
    assert!(map_str.contains("1: 10"));
    assert!(map_str.contains("key: false"));

    let tagged = CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(99)));
    assert_eq!(format!("{}", tagged), "tag(42, 99)");
}

#[test]
fn header_value_as_bytes_on_non_bytes() {
    let v = CoseHeaderValue::Int(5);
    assert!(v.as_bytes().is_none());
}

#[test]
fn header_value_as_i64_on_non_int() {
    let v = CoseHeaderValue::Text(ArcStr::from("text"));
    assert!(v.as_i64().is_none());
}

#[test]
fn header_value_as_str_on_non_text() {
    let v = CoseHeaderValue::Int(42);
    assert!(v.as_str().is_none());
}

#[test]
fn header_value_as_bytes_one_or_many_array_mixed() {
    // Array with non-Bytes items → those are skipped
    let arr = CoseHeaderValue::Array(vec![
        CoseHeaderValue::Int(1),
        CoseHeaderValue::Bytes(ArcSlice::from(vec![0xAA])),
    ]);
    let result = arr.as_bytes_one_or_many().unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], vec![0xAA]);
}

#[test]
fn header_value_as_bytes_one_or_many_empty_array() {
    // Array with no Bytes items → None
    let arr = CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]);
    assert!(arr.as_bytes_one_or_many().is_none());
}

#[test]
fn header_value_as_bytes_one_or_many_non_array_non_bytes() {
    let v = CoseHeaderValue::Bool(true);
    assert!(v.as_bytes_one_or_many().is_none());
}

#[test]
fn header_value_from_impls() {
    let _: CoseHeaderValue = 42i64.into();
    let _: CoseHeaderValue = 42u64.into();
    let _: CoseHeaderValue = vec![1u8, 2].into();
    let _: CoseHeaderValue = (&[1u8, 2][..]).into();
    let _: CoseHeaderValue = "hello".into();
    let _: CoseHeaderValue = "hello".to_string().into();
    let _: CoseHeaderValue = true.into();
}

// ============================================================================
// CoseHeaderLabel Display and conversions
// ============================================================================

#[test]
fn header_label_display() {
    assert_eq!(format!("{}", CoseHeaderLabel::Int(1)), "1");
    assert_eq!(format!("{}", CoseHeaderLabel::Text("kid".into())), "kid");
}

#[test]
fn header_label_from_impls() {
    let _: CoseHeaderLabel = 1i64.into();
    let _: CoseHeaderLabel = "text".into();
    let _: CoseHeaderLabel = "text".to_string().into();
}

// ============================================================================
// ContentType Display
// ============================================================================

#[test]
fn content_type_display() {
    assert_eq!(format!("{}", ContentType::Int(42)), "42");
    assert_eq!(
        format!("{}", ContentType::Text("application/cbor".into())),
        "application/cbor"
    );
}

// ============================================================================
// CoseHeaderMap content_type edge cases
// ============================================================================

#[test]
fn header_map_content_type_uint() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(42),
    );
    assert_eq!(map.content_type(), Some(ContentType::Int(42)));
}

#[test]
fn header_map_content_type_uint_too_large() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Uint(u64::MAX),
    );
    assert!(map.content_type().is_none());
}

#[test]
fn header_map_content_type_int_negative() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Int(-1),
    );
    assert!(map.content_type().is_none());
}

#[test]
fn header_map_content_type_text() {
    let mut map = CoseHeaderMap::new();
    map.set_content_type(ContentType::Text("application/json".into()));
    assert_eq!(
        map.content_type(),
        Some(ContentType::Text("application/json".into()))
    );
}

#[test]
fn header_map_content_type_non_matching_type() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(CoseHeaderMap::CONTENT_TYPE),
        CoseHeaderValue::Bool(true),
    );
    assert!(map.content_type().is_none());
}

// ============================================================================
// CoseHeaderMap encode/decode roundtrip for complex types
// ============================================================================

#[test]
fn header_map_roundtrip_tagged_value() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Tagged(42, Box::new(CoseHeaderValue::Int(99))),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(100)),
        Some(&CoseHeaderValue::Tagged(
            42,
            Box::new(CoseHeaderValue::Int(99))
        ))
    );
}

#[test]
fn header_map_roundtrip_null_and_undefined() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(200), CoseHeaderValue::Null);
    map.insert(CoseHeaderLabel::Int(201), CoseHeaderValue::Undefined);

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(200)),
        Some(&CoseHeaderValue::Null)
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(201)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn header_map_encode_float() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(300), CoseHeaderValue::Float(2.718));

    // EverParse CBOR encoder doesn't support floats — expect an error
    let result = map.encode();
    assert!(result.is_err());
}

#[test]
fn header_map_roundtrip_bool() {
    let mut map = CoseHeaderMap::new();
    map.insert(CoseHeaderLabel::Int(400), CoseHeaderValue::Bool(true));
    map.insert(CoseHeaderLabel::Int(401), CoseHeaderValue::Bool(false));

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(400)),
        Some(&CoseHeaderValue::Bool(true))
    );
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Int(401)),
        Some(&CoseHeaderValue::Bool(false))
    );
}

#[test]
fn header_map_roundtrip_raw() {
    let mut map = CoseHeaderMap::new();
    // Raw bytes are just passthrough CBOR
    // Encode a simple integer (CBOR 0x18 0x2A = unsigned int 42) as Raw
    map.insert(
        CoseHeaderLabel::Int(500),
        CoseHeaderValue::Raw(ArcSlice::from(vec![0x18, 0x2A])),
    );

    let encoded = map.encode().unwrap();
    // We can't perfectly roundtrip Raw since decode will interpret it as the underlying type.
    // But the encode path is what we want to exercise.
    assert!(!encoded.is_empty());
}

#[test]
fn header_map_roundtrip_nested_map() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(600),
        CoseHeaderValue::Map(vec![
            (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(10)),
            (
                CoseHeaderLabel::Text("nested".into()),
                CoseHeaderValue::Text(ArcStr::from("value")),
            ),
        ]),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();

    if let Some(CoseHeaderValue::Map(pairs)) = decoded.get(&CoseHeaderLabel::Int(600)) {
        assert_eq!(pairs.len(), 2);
    } else {
        panic!("expected Map value");
    }
}

#[test]
fn header_map_roundtrip_text_label() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Text("custom".into()),
        CoseHeaderValue::Int(777),
    );

    let encoded = map.encode().unwrap();
    let decoded = CoseHeaderMap::decode(&encoded).unwrap();
    assert_eq!(
        decoded.get(&CoseHeaderLabel::Text("custom".into())),
        Some(&CoseHeaderValue::Int(777))
    );
}

#[test]
fn header_map_decode_shared_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"my-kid".to_vec());

    let encoded = map.encode().unwrap();
    let arc: Arc<[u8]> = Arc::from(encoded.clone());
    let range = 0..arc.len();

    let decoded = CoseHeaderMap::decode_shared(&arc, range).unwrap();
    assert_eq!(decoded.alg(), Some(-7));
    assert_eq!(decoded.kid(), Some(b"my-kid".as_slice()));
}

#[test]
fn header_map_decode_shared_empty() {
    let arc: Arc<[u8]> = Arc::from(vec![]);
    let decoded = CoseHeaderMap::decode_shared(&arc, 0..0).unwrap();
    assert!(decoded.is_empty());
}

// ============================================================================
// CoseHeaderMap crit
// ============================================================================

#[test]
fn header_map_crit_roundtrip() {
    let mut map = CoseHeaderMap::new();
    map.set_crit(vec![
        CoseHeaderLabel::Int(1),
        CoseHeaderLabel::Text("custom".into()),
    ]);

    let labels = map.crit().unwrap();
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0], CoseHeaderLabel::Int(1));
    assert_eq!(labels[1], CoseHeaderLabel::Text("custom".into()));
}

#[test]
fn header_map_crit_none_when_missing() {
    let map = CoseHeaderMap::new();
    assert!(map.crit().is_none());
}

// ============================================================================
// ProtectedHeader
// ============================================================================

#[test]
fn protected_header_encode_decode_roundtrip() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    headers.set_kid(b"test-kid".to_vec());
    headers.set_content_type(ContentType::Int(42));

    let ph = ProtectedHeader::encode(headers).unwrap();
    assert!(!ph.as_bytes().is_empty());
    assert_eq!(ph.alg(), Some(-7));
    assert_eq!(ph.kid(), Some(b"test-kid".as_slice()));
    assert_eq!(ph.content_type(), Some(ContentType::Int(42)));
    assert!(!ph.is_empty());

    let decoded = ProtectedHeader::decode(ph.as_bytes().to_vec()).unwrap();
    assert_eq!(decoded.alg(), Some(-7));
}

#[test]
fn protected_header_empty() {
    let ph = ProtectedHeader::decode(vec![]).unwrap();
    assert!(ph.is_empty());
    assert!(ph.alg().is_none());
    assert!(ph.kid().is_none());
    assert!(ph.content_type().is_none());
}

#[test]
fn protected_header_default() {
    let ph = ProtectedHeader::default();
    assert!(ph.is_empty());
    assert!(ph.as_bytes().is_empty());
}

#[test]
fn protected_header_get() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let ph = ProtectedHeader::encode(headers).unwrap();
    assert!(ph.get(&CoseHeaderLabel::Int(1)).is_some());
    assert!(ph.get(&CoseHeaderLabel::Int(999)).is_none());
}

#[test]
fn protected_header_headers_mut() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7);
    let mut ph = ProtectedHeader::encode(headers).unwrap();
    ph.headers_mut().set_alg(-35);
    assert_eq!(ph.alg(), Some(-35));
}

// ============================================================================
// LazyHeaderMap edge cases
// ============================================================================

#[test]
fn lazy_header_map_empty_bytes() {
    let arc: Arc<[u8]> = Arc::from(vec![]);
    let lazy = LazyHeaderMap::new(arc, 0..0);
    let headers = lazy.headers();
    assert!(headers.is_empty());
    assert!(lazy.is_parsed());
}

#[test]
fn lazy_header_map_try_headers_empty() {
    let arc: Arc<[u8]> = Arc::from(vec![]);
    let lazy = LazyHeaderMap::new(arc, 0..0);
    let result = lazy.try_headers();
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn lazy_header_map_try_headers_already_parsed() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    let encoded = map.encode().unwrap();

    let arc: Arc<[u8]> = Arc::from(encoded.clone());
    let range = 0..arc.len();
    let lazy = LazyHeaderMap::new(arc.clone(), range.clone());

    // First call parses
    let _ = lazy.headers();
    assert!(lazy.is_parsed());

    // Second call via try_headers returns cached
    let h = lazy.try_headers().unwrap();
    assert_eq!(h.alg(), Some(-7));
}

#[test]
fn lazy_header_map_from_parsed() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-35);
    let encoded = map.encode().unwrap();

    let arc: Arc<[u8]> = Arc::from(encoded.clone());
    let lazy = LazyHeaderMap::from_parsed(arc.clone(), 0..arc.len(), map);
    assert!(lazy.is_parsed());
    assert_eq!(lazy.headers().alg(), Some(-35));
}

#[test]
fn lazy_header_map_as_bytes_and_range() {
    let data = vec![0xA1, 0x01, 0x26]; // {1: -7} encoded
    let arc: Arc<[u8]> = Arc::from(data.clone());
    let lazy = LazyHeaderMap::new(arc.clone(), 0..3);

    assert_eq!(lazy.as_bytes(), &data[..]);
    assert_eq!(lazy.range(), &(0..3));
    assert_eq!(lazy.arc().len(), 3);
}

#[test]
fn lazy_header_map_clone() {
    let data = vec![0xA1, 0x01, 0x26]; // {1: -7}
    let arc: Arc<[u8]> = Arc::from(data);
    let lazy = LazyHeaderMap::new(arc, 0..3);
    let _ = lazy.headers(); // parse

    let cloned = lazy.clone();
    assert_eq!(cloned.headers().alg(), Some(-7));
}

// ============================================================================
// CoseHeaderMap misc
// ============================================================================

#[test]
fn header_map_remove() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    let removed = map.remove(&CoseHeaderLabel::Int(1));
    assert!(removed.is_some());
    assert!(map.alg().is_none());
}

#[test]
fn header_map_iter() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"kid".to_vec());

    let count = map.iter().count();
    assert_eq!(count, 2);
}

#[test]
fn header_map_get_bytes_one_or_many() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(ArcSlice::from(vec![1, 2])),
            CoseHeaderValue::Bytes(ArcSlice::from(vec![3, 4])),
        ]),
    );

    let certs = map
        .get_bytes_one_or_many(&CoseHeaderLabel::Int(33))
        .unwrap();
    assert_eq!(certs.len(), 2);
}

#[test]
fn header_map_get_bytes_one_or_many_single() {
    let mut map = CoseHeaderMap::new();
    map.insert(
        CoseHeaderLabel::Int(33),
        CoseHeaderValue::Bytes(ArcSlice::from(vec![1, 2, 3])),
    );

    let certs = map
        .get_bytes_one_or_many(&CoseHeaderLabel::Int(33))
        .unwrap();
    assert_eq!(certs.len(), 1);
}

#[test]
fn header_map_decode_empty() {
    let decoded = CoseHeaderMap::decode(&[]).unwrap();
    assert!(decoded.is_empty());
}
