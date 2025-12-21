// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for decoding unprotected header maps.
//!
//! Unprotected headers are encoded inline as a CBOR map and are not included in
//! the Sig_structure bytes.

use cosesign1_common::parse_cose_sign1;

#[test]
fn unprotected_headers_decode_non_empty_map() {
    // protected headers: { 1: -7 }
    let protected = vec![0xa1, 0x01, 0x26];

    let mut msg = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut msg);
    enc.array(4).unwrap();

    // protected header bstr
    enc.bytes(&protected).unwrap();

    // unprotected header map
    enc.map(3).unwrap();
    // 4 => kid
    enc.i64(4).unwrap();
    enc.bytes(b"kid-1").unwrap();
    // 33 => x5c-like array
    enc.i64(33).unwrap();
    enc.array(1).unwrap();
    enc.bytes(b"cert").unwrap();
    // 5 => null
    enc.i64(5).unwrap();
    enc.null().unwrap();

    // payload
    enc.bytes(b"p").unwrap();

    // signature
    enc.bytes(&[]).unwrap();

    let parsed = parse_cose_sign1(&msg).expect("parse");

    assert_eq!(parsed.unprotected_headers.get_bytes(4), Some(b"kid-1".as_slice()));
    assert!(matches!(parsed.unprotected_headers.get_array(33), Some(_)));
}
