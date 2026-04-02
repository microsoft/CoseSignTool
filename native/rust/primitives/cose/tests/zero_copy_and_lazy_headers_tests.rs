// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoseData::from_arc_range, ArcSlice accessors, and
//! LazyHeaderMap mutation methods.

use std::sync::Arc;

use cose_primitives::arc_types::ArcSlice;
use cose_primitives::data::CoseData;
use cose_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_primitives::lazy_headers::LazyHeaderMap;

// ---------------------------------------------------------------------------
// CoseData::from_arc_range
// ---------------------------------------------------------------------------

#[test]
fn from_arc_range_as_bytes_returns_sub_range() {
    let full: Arc<[u8]> = Arc::from(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let data = CoseData::from_arc_range(full.clone(), 1..4);

    let bytes = data.as_bytes();
    assert_eq!(bytes, &[0xBB, 0xCC, 0xDD]);
}

#[test]
fn from_arc_range_slice_uses_absolute_indexing() {
    let full: Arc<[u8]> = Arc::from(vec![0x10, 0x20, 0x30, 0x40, 0x50]);
    let data = CoseData::from_arc_range(full.clone(), 1..4);

    // slice() uses absolute offsets into the backing Arc
    let abs_slice = data.slice(&(0..2));
    assert_eq!(abs_slice, &[0x10, 0x20]);

    let abs_slice2 = data.slice(&(3..5));
    assert_eq!(abs_slice2, &[0x40, 0x50]);
}

#[test]
fn from_arc_range_full_range_matches_from_arc() {
    let raw = vec![0x01, 0x02, 0x03];
    let arc: Arc<[u8]> = Arc::from(raw.clone());
    let len = arc.len();
    let data_range = CoseData::from_arc_range(arc.clone(), 0..len);
    let data_full = CoseData::from_arc(arc);

    assert_eq!(data_range.as_bytes(), data_full.as_bytes());
}

// ---------------------------------------------------------------------------
// ArcSlice::arc() and ArcSlice::range()
// ---------------------------------------------------------------------------

#[test]
fn arc_slice_arc_returns_backing_buffer() {
    let buf: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5]);
    let slice = ArcSlice::new(buf.clone(), 2..4);

    // arc() returns the same Arc
    assert!(Arc::ptr_eq(slice.arc(), &buf));
}

#[test]
fn arc_slice_range_returns_correct_range() {
    let buf: Arc<[u8]> = Arc::from(vec![10, 20, 30, 40]);
    let slice = ArcSlice::new(buf, 1..3);

    assert_eq!(slice.range(), &(1..3));
    assert_eq!(slice.as_bytes(), &[20, 30]);
}

#[test]
fn arc_slice_from_vec_owns_independent_arc() {
    let slice = ArcSlice::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);

    assert_eq!(slice.as_bytes(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(slice.range(), &(0..4));
    assert_eq!(slice.len(), 4);
    assert!(!slice.is_empty());
}

#[test]
fn arc_slice_empty() {
    let buf: Arc<[u8]> = Arc::from(vec![1, 2, 3]);
    let slice = ArcSlice::new(buf, 2..2);

    assert!(slice.is_empty());
    assert_eq!(slice.len(), 0);
    assert_eq!(slice.as_bytes(), &[] as &[u8]);
}

// ---------------------------------------------------------------------------
// LazyHeaderMap::insert / remove / get
// ---------------------------------------------------------------------------

#[test]
fn lazy_header_map_insert_and_get() {
    // Build a minimal CBOR empty map: 0xA0
    let raw: Arc<[u8]> = Arc::from(vec![0xA0]);
    let mut map = LazyHeaderMap::new(raw, 0..1);

    let label = CoseHeaderLabel::Int(42);
    let value = CoseHeaderValue::Int(99);

    assert!(
        map.get(&label).is_none(),
        "label should not exist before insert"
    );

    map.insert(label.clone(), value.clone());

    let got = map.get(&label).expect("label should exist after insert");
    assert_eq!(*got, value);
}

#[test]
fn lazy_header_map_remove_returns_value() {
    let raw: Arc<[u8]> = Arc::from(vec![0xA0]);
    let mut map = LazyHeaderMap::new(raw, 0..1);

    let label = CoseHeaderLabel::Int(7);
    let value = CoseHeaderValue::Text("hello".into());

    map.insert(label.clone(), value.clone());
    assert!(map.get(&label).is_some());

    let removed = map.remove(&label);
    assert_eq!(removed, Some(value));
    assert!(
        map.get(&label).is_none(),
        "label should be gone after remove"
    );
}

#[test]
fn lazy_header_map_remove_missing_returns_none() {
    let raw: Arc<[u8]> = Arc::from(vec![0xA0]);
    let mut map = LazyHeaderMap::new(raw, 0..1);

    let label = CoseHeaderLabel::Int(999);
    let removed = map.remove(&label);
    assert!(removed.is_none());
}

#[test]
fn lazy_header_map_insert_overwrites() {
    let raw: Arc<[u8]> = Arc::from(vec![0xA0]);
    let mut map = LazyHeaderMap::new(raw, 0..1);

    let label = CoseHeaderLabel::Int(1);
    map.insert(label.clone(), CoseHeaderValue::Int(10));
    map.insert(label.clone(), CoseHeaderValue::Int(20));

    let got = map.get(&label).unwrap();
    assert_eq!(*got, CoseHeaderValue::Int(20));
}

#[test]
fn lazy_header_map_from_parsed_get_works() {
    let mut headers = CoseHeaderMap::new();
    headers.set_alg(-7); // ES256

    let raw: Arc<[u8]> = Arc::from(vec![0xA0]); // placeholder bytes
    let map = LazyHeaderMap::from_parsed(raw, 0..1, headers);

    assert!(map.is_parsed());
    let alg = map.get(&CoseHeaderLabel::Int(1));
    assert!(alg.is_some(), "algorithm header should be present");
}
