// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `LazyHeaderMap` deferred-parse header maps.

use std::sync::Arc;

use cose_primitives::{CoseHeaderMap, LazyHeaderMap};

#[test]
fn lazy_empty_range() {
    let buf: Arc<[u8]> = Arc::from(vec![0u8; 10]);
    // Empty range → empty header map.
    let lazy = LazyHeaderMap::new(buf, 5..5);
    assert!(lazy.headers().is_empty());
}

#[test]
fn lazy_from_parsed() {
    let buf: Arc<[u8]> = Arc::from(vec![0xA0]); // empty CBOR map
    let mut map = CoseHeaderMap::new();
    map.set_alg(7);
    let lazy = LazyHeaderMap::from_parsed(buf, 0..1, map);
    assert!(lazy.is_parsed());
    assert_eq!(lazy.headers().alg(), Some(7));
}

#[test]
fn lazy_parse_valid_cbor_map() {
    // Encode a simple header map and wrap it.
    let mut map = CoseHeaderMap::new();
    map.set_alg(-7); // ES256
    let encoded = map.encode().unwrap();
    let len = encoded.len();
    let buf: Arc<[u8]> = Arc::from(encoded);
    let lazy = LazyHeaderMap::new(buf, 0..len);
    assert!(!lazy.is_parsed());
    let headers = lazy.headers();
    assert!(lazy.is_parsed());
    assert_eq!(headers.alg(), Some(-7));
}

#[test]
fn lazy_try_headers_error() {
    let buf: Arc<[u8]> = Arc::from(vec![0xFF]); // invalid CBOR
    let lazy = LazyHeaderMap::new(buf, 0..1);
    assert!(lazy.try_headers().is_err());
}
