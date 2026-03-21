// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `CoseData` shared-ownership CBOR bytes.

use std::sync::Arc;

use cose_primitives::CoseData;

#[test]
fn cose_data_new() {
    let data = CoseData::new(vec![1, 2, 3]);
    assert_eq!(data.as_bytes(), &[1, 2, 3]);
    assert_eq!(data.len(), 3);
    assert!(!data.is_empty());
}

#[test]
fn cose_data_from_slice() {
    let data = CoseData::from_slice(&[10, 20, 30]);
    assert_eq!(data.as_bytes(), &[10, 20, 30]);
}

#[test]
fn cose_data_slice() {
    let data = CoseData::new(vec![0, 1, 2, 3, 4]);
    assert_eq!(data.slice(&(1..4)), &[1, 2, 3]);
}

#[test]
fn cose_data_arc_sharing() {
    let data = CoseData::new(vec![5, 6, 7]);
    let arc = data.arc().clone();
    assert_eq!(&*arc, &[5, 6, 7]);
}

#[test]
fn cose_data_clone_is_cheap() {
    let data = CoseData::new(vec![1, 2, 3]);
    let cloned = data.clone();
    assert!(Arc::ptr_eq(data.arc(), cloned.arc()));
}

#[test]
fn cose_data_empty() {
    let data = CoseData::new(vec![]);
    assert!(data.is_empty());
}

#[test]
fn cose_data_is_streamed() {
    let buffered = CoseData::new(vec![1, 2, 3]);
    assert!(!buffered.is_streamed());
}
