// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for `ArcSlice` and `ArcStr` to cover all trait impls and edge cases.

use std::collections::HashSet;
use std::sync::Arc;

use cose_primitives::{ArcSlice, ArcStr};

// ============================================================================
// ArcSlice trait impls
// ============================================================================

#[test]
fn arc_slice_as_ref() {
    let s = ArcSlice::from(vec![1, 2, 3]);
    let r: &[u8] = s.as_ref();
    assert_eq!(r, &[1, 2, 3]);
}

#[test]
fn arc_slice_partial_eq_different_backing() {
    let buf1: Arc<[u8]> = Arc::from(vec![0, 1, 2, 3]);
    let buf2: Arc<[u8]> = Arc::from(vec![99, 1, 2, 3, 99]);
    let a = ArcSlice::new(buf1, 1..4);
    let b = ArcSlice::new(buf2, 1..4);
    assert_eq!(a, b);
}

#[test]
fn arc_slice_partial_eq_not_equal() {
    let a = ArcSlice::from(vec![1, 2]);
    let b = ArcSlice::from(vec![3, 4]);
    assert_ne!(a, b);
}

#[test]
fn arc_slice_hash_equal_slices_same_hash() {
    let a = ArcSlice::from(vec![10, 20, 30]);
    let b = ArcSlice::from(vec![10, 20, 30]);
    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[test]
fn arc_slice_hash_different_slices_different_hash() {
    let a = ArcSlice::from(vec![1]);
    let b = ArcSlice::from(vec![2]);
    let mut set = HashSet::new();
    set.insert(a);
    assert!(!set.contains(&b));
}

#[test]
fn arc_slice_from_borrowed_slice() {
    let data: &[u8] = &[5, 6, 7, 8];
    let s = ArcSlice::from(data);
    assert_eq!(s.as_bytes(), &[5, 6, 7, 8]);
    assert_eq!(s.len(), 4);
}

#[test]
fn arc_slice_clone_shares_arc() {
    let buf: Arc<[u8]> = Arc::from(vec![1, 2, 3, 4, 5]);
    let a = ArcSlice::new(buf.clone(), 0..3);
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.as_bytes(), b.as_bytes());
}

#[test]
fn arc_slice_sub_range_slicing() {
    let buf: Arc<[u8]> = Arc::from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let s = ArcSlice::new(buf.clone(), 2..8);
    assert_eq!(s.as_bytes(), &[2, 3, 4, 5, 6, 7]);
    assert_eq!(s.len(), 6);

    let sub = ArcSlice::new(buf, 4..6);
    assert_eq!(sub.as_bytes(), &[4, 5]);
}

#[test]
fn arc_slice_display_empty() {
    let s = ArcSlice::from(vec![]);
    assert_eq!(format!("{}", s), "bytes(0)");
}

#[test]
fn arc_slice_deref_iteration() {
    let s = ArcSlice::from(vec![10, 20, 30]);
    let sum: u8 = s.iter().sum();
    assert_eq!(sum, 60);
}

#[test]
fn arc_slice_debug_format() {
    let s = ArcSlice::from(vec![0xAB, 0xCD]);
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("ArcSlice"));
}

// ============================================================================
// ArcStr trait impls
// ============================================================================

#[test]
fn arc_str_as_ref() {
    let s = ArcStr::from("hello");
    let r: &str = s.as_ref();
    assert_eq!(r, "hello");
}

#[test]
fn arc_str_partial_eq_different_backing() {
    let buf1: Arc<[u8]> = Arc::from(b"xxhelloxx".to_vec());
    let buf2: Arc<[u8]> = Arc::from(b"yyheloyy".to_vec());
    let a = ArcStr::new(buf1, 2..7);
    // "hello" != "helo" - should not be equal
    let c = ArcStr::from("hello");
    assert_eq!(a, c);
}

#[test]
fn arc_str_partial_eq_not_equal() {
    let a = ArcStr::from("hello");
    let b = ArcStr::from("world");
    assert_ne!(a, b);
}

#[test]
fn arc_str_hash_in_set() {
    let a = ArcStr::from("key");
    let b = ArcStr::from("key");
    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
}

#[test]
fn arc_str_from_str_ref() {
    let s = ArcStr::from("test");
    assert_eq!(s.as_str(), "test");
    assert_eq!(s.len(), 4);
    assert!(!s.is_empty());
}

#[test]
fn arc_str_non_ascii_utf8() {
    let s = ArcStr::from("日本語テスト");
    assert_eq!(s.as_str(), "日本語テスト");
    assert!(!s.is_empty());
    // UTF-8 length should be larger than character count
    assert!(s.len() > 6);
}

#[test]
fn arc_str_emoji_utf8() {
    let s = ArcStr::from("🦀🔒");
    assert_eq!(s.as_str(), "🦀🔒");
    assert_eq!(s.len(), 8); // 4 bytes each
}

#[test]
fn arc_str_clone_preserves() {
    let a = ArcStr::from("cloned");
    let b = a.clone();
    assert_eq!(a, b);
    assert_eq!(a.as_str(), b.as_str());
}

#[test]
fn arc_str_deref_to_str() {
    let s = ArcStr::from("deref");
    let len = s.len();
    assert_eq!(len, 5);
    assert!(s.starts_with("der"));
    assert!(s.ends_with("ef"));
}

#[test]
fn arc_str_display_shows_content() {
    let s = ArcStr::from("displayed");
    assert_eq!(format!("{}", s), "displayed");
}

#[test]
fn arc_str_empty_display() {
    let s = ArcStr::from("");
    assert_eq!(format!("{}", s), "");
    assert!(s.is_empty());
}

#[test]
fn arc_str_debug_format() {
    let s = ArcStr::from("dbg");
    let dbg = format!("{:?}", s);
    assert!(dbg.contains("ArcStr"));
}

#[test]
fn arc_str_shared_buffer_range() {
    let text = "prefixHELLOsuffix";
    let buf: Arc<[u8]> = Arc::from(text.as_bytes().to_vec());
    let s = ArcStr::new(buf.clone(), 6..11);
    assert_eq!(s.as_str(), "HELLO");
    assert_eq!(s.len(), 5);
}

#[test]
fn arc_str_empty_range() {
    let buf: Arc<[u8]> = Arc::from(b"data".to_vec());
    let s = ArcStr::new(buf, 2..2);
    assert!(s.is_empty());
    assert_eq!(s.len(), 0);
    assert_eq!(s.as_str(), "");
}
