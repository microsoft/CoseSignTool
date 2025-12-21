// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `CoseHeaderMap` container behavior.
//!
//! Verifies helper semantics like `.clear()` and the intended behavior that
//! unprotected headers do not preserve an encoded-map byte representation.

use cosesign1_common::{parse_cose_sign1, CoseHeaderMap};

#[test]
fn cose_header_map_clear_empties_encoded_and_map() {
    // Start with a non-empty map by parsing a minimal COSE_Sign1.
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&protected_map).unwrap();
    enc.map(1).unwrap();
    enc.i64(4).unwrap();
    enc.bytes(b"kid").unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let parsed = parse_cose_sign1(&msg).expect("parse");

    let mut h: CoseHeaderMap = parsed.protected_headers.clone();
    assert!(!h.encoded_map_cbor().is_empty());
    assert!(!h.map().is_empty());

    h.clear();
    assert!(h.encoded_map_cbor().is_empty());
    assert!(h.map().is_empty());
}

#[test]
fn unprotected_encoded_map_cbor_is_empty_by_design() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&protected_map).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let parsed = parse_cose_sign1(&msg).expect("parse");
    assert!(parsed.unprotected_headers.encoded_map_cbor().is_empty());
}

#[test]
fn header_getters_return_none_on_type_mismatch_for_bytes_and_array() {
    // protected headers: { 4: -7, 33: h'0102' }
    let mut protected = Vec::new();
    let mut p = minicbor::Encoder::new(&mut protected);
    p.map(2).unwrap();
    p.i64(4).unwrap();
    p.i64(-7).unwrap();
    p.i64(33).unwrap();
    p.bytes(&[1u8, 2]).unwrap();

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let parsed = parse_cose_sign1(&msg).expect("parse");

    // get_bytes on an int value
    assert!(parsed.protected_headers.get_bytes(4).is_none());
    // get_array on a bytes value
    assert!(parsed.protected_headers.get_array(33).is_none());
}
