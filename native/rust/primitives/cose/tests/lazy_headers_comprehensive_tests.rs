// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for `LazyHeaderMap` covering lazy parsing, from_parsed,
//! try_headers, raw_bytes access, and OnceLock behavior.

use std::sync::Arc;

use cose_primitives::{CoseHeaderMap, CoseHeaderValue, LazyHeaderMap};

#[test]
fn lazy_as_bytes_returns_raw_cbor() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded.clone());
    let lazy = LazyHeaderMap::new(buf, 0..len);
    assert_eq!(lazy.as_bytes(), &encoded[..]);
}

#[test]
fn lazy_range_returns_correct_range() {
    let buf: Arc<[u8]> = Arc::from(vec![0u8; 20]);
    let lazy = LazyHeaderMap::new(buf, 5..15);
    assert_eq!(lazy.range(), &(5..15));
}

#[test]
fn lazy_arc_returns_backing_arc() {
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]);
    let lazy = LazyHeaderMap::new(buf.clone(), 0..1);
    assert!(Arc::ptr_eq(lazy.arc(), &buf));
}

#[test]
fn lazy_is_parsed_initially_false() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-35);
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);
    assert!(!lazy.is_parsed());
}

#[test]
fn lazy_headers_triggers_parse() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-35);
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);
    assert!(!lazy.is_parsed());
    let headers = lazy.headers();
    assert!(lazy.is_parsed());
    assert_eq!(headers.alg(), Some(-35));
}

#[test]
fn lazy_headers_called_twice_returns_same() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"kid1".to_vec());
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);

    let h1 = lazy.headers();
    let h2 = lazy.headers();
    assert_eq!(h1.alg(), h2.alg());
    assert_eq!(h1.kid(), h2.kid());
}

#[test]
fn lazy_try_headers_valid_cbor() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-36);
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);

    let result = lazy.try_headers();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().alg(), Some(-36));
    assert!(lazy.is_parsed());
}

#[test]
fn lazy_try_headers_already_parsed() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]); // will be overridden by from_parsed
    let lazy = LazyHeaderMap::from_parsed(buf, 0..1, map);
    assert!(lazy.is_parsed());

    let result = lazy.try_headers();
    assert!(result.is_ok());
    assert_eq!(result.unwrap().alg(), Some(-7));
}

#[test]
fn lazy_try_headers_empty_range() {
    let buf: Arc<[u8]> = Arc::from(vec![0u8; 10]);
    let lazy = LazyHeaderMap::new(buf, 5..5);
    let result = lazy.try_headers();
    assert!(result.is_ok());
    let headers = result.unwrap();
    assert!(headers.is_empty());
}

#[test]
fn lazy_try_headers_invalid_cbor() {
    let buf: Arc<[u8]> = Arc::from(vec![0xFF, 0xFF]);
    let lazy = LazyHeaderMap::new(buf, 0..2);
    let result = lazy.try_headers();
    assert!(result.is_err());
}

#[test]
fn lazy_headers_invalid_cbor_returns_empty_map() {
    let buf: Arc<[u8]> = Arc::from(vec![0xFF, 0xFF]);
    let lazy = LazyHeaderMap::new(buf, 0..2);
    let headers = lazy.headers();
    assert!(headers.is_empty());
}

#[test]
fn lazy_from_parsed_is_parsed() {
    let map = CoseHeaderMap::new();
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]);
    let lazy = LazyHeaderMap::from_parsed(buf, 0..1, map);
    assert!(lazy.is_parsed());
    assert!(lazy.headers().is_empty());
}

#[test]
fn lazy_from_parsed_preserves_headers() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"test-kid".to_vec());
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]);
    let lazy = LazyHeaderMap::from_parsed(buf, 0..1, map);
    assert_eq!(lazy.headers().alg(), Some(-7));
    assert_eq!(lazy.headers().kid(), Some(b"test-kid".as_slice()));
}

#[test]
fn lazy_clone_preserves_parsed_state() {
    let mut map = CoseHeaderMap::new();
    map.set_alg(-37);
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);

    // Parse first
    let _ = lazy.headers();
    assert!(lazy.is_parsed());

    // Clone should have parsed as well (OnceLock Clone)
    let cloned = lazy.clone();
    // Note: OnceLock clone copies the inner value
    assert_eq!(cloned.headers().alg(), Some(-37));
}

#[test]
fn lazy_debug_format() {
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]);
    let lazy = LazyHeaderMap::new(buf, 0..1);
    let dbg = format!("{:?}", lazy);
    assert!(dbg.contains("LazyHeaderMap"));
}

#[test]
fn lazy_with_multiple_headers() {
    use cose_primitives::CoseHeaderLabel;
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7);
    map.set_kid(b"my-key".to_vec());
    map.insert(
        CoseHeaderLabel::Int(100),
        CoseHeaderValue::Text(cose_primitives::ArcStr::from("custom-value")),
    );
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);

    let headers = lazy.headers();
    assert_eq!(headers.alg(), Some(-7));
    assert_eq!(headers.kid(), Some(b"my-key".as_slice()));
    assert_eq!(headers.len(), 3);
}
