// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `ArcSlice` and `ArcStr` zero-copy types.

use std::sync::Arc;

use cose_primitives::{ArcSlice, ArcStr};

#[test]
fn arc_slice_from_vec() {
    let s = ArcSlice::from(vec![1, 2, 3]);
    assert_eq!(s.as_bytes(), &[1, 2, 3]);
    assert_eq!(s.len(), 3);
    assert!(!s.is_empty());
}

#[test]
fn arc_slice_shared() {
    let buf: Arc<[u8]> = Arc::from(vec![0, 1, 2, 3, 4]);
    let s = ArcSlice::new(buf.clone(), 1..4);
    assert_eq!(s.as_bytes(), &[1, 2, 3]);
    assert_eq!(s.len(), 3);
}

#[test]
fn arc_slice_deref() {
    let s = ArcSlice::from(vec![10, 20]);
    let slice: &[u8] = &s;
    assert_eq!(slice, &[10, 20]);
}

#[test]
fn arc_slice_eq() {
    let a = ArcSlice::from(vec![1, 2]);
    let b = ArcSlice::from(vec![1, 2]);
    assert_eq!(a, b);
}

#[test]
fn arc_str_from_string() {
    let s = ArcStr::from("hello".to_string());
    assert_eq!(s.as_str(), "hello");
    assert_eq!(s.len(), 5);
}

#[test]
fn arc_str_shared() {
    let buf: Arc<[u8]> = Arc::from(b"xxhelloxx".to_vec());
    let s = ArcStr::new(buf, 2..7);
    assert_eq!(s.as_str(), "hello");
}

#[test]
fn arc_str_deref() {
    let s = ArcStr::from("test".to_string());
    let r: &str = &s;
    assert_eq!(r, "test");
}

#[test]
fn arc_str_display() {
    let s = ArcStr::from("world".to_string());
    assert_eq!(format!("{}", s), "world");
}

#[test]
fn arc_slice_display() {
    let s = ArcSlice::from(vec![1, 2, 3]);
    assert_eq!(format!("{}", s), "bytes(3)");
}

#[test]
fn arc_slice_empty() {
    let s = ArcSlice::from(vec![]);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}

#[test]
fn arc_str_empty() {
    let s = ArcStr::from(String::new());
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
}
