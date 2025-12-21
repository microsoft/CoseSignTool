// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Positive COSE_Sign1 parsing tests.
//!
//! These focus on accepted encodings (tagged/untagged, detached payload) and
//! basic header-map decoding behavior.

use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1, HeaderValue};
use minicbor::{Encoder};

// Helper to build a minimal, mostly-well-formed COSE_Sign1.
fn make_basic_sign1(tagged: bool, detached: bool) -> Vec<u8> {
    // COSE_Sign1 = [ protected : bstr, unprotected : map, payload : bstr / nil, signature : bstr ]
    let protected = {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap(); // alg
        enc.i64(-7).unwrap(); // ES256
        buf
    };

    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    if tagged {
        enc.tag(minicbor::data::Tag::new(18)).unwrap();
    }
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    if detached {
        enc.null().unwrap();
    } else {
        enc.bytes(b"payload").unwrap();
    }
    enc.bytes(b"sig").unwrap();
    out
}

#[test]
fn parse_accepts_tagged_and_untagged() {
    for tagged in [false, true] {
        let cose = make_basic_sign1(tagged, false);
        let parsed = parse_cose_sign1(&cose).expect("parse");
        assert_eq!(parsed.signature, b"sig");
        assert_eq!(parsed.payload.as_deref(), Some(b"payload".as_slice()));
        assert_eq!(parsed.protected_headers.get_i64(1), Some(-7));
    }
}

#[test]
fn parse_supports_detached_payload() {
    let cose = make_basic_sign1(false, true);
    let parsed = parse_cose_sign1(&cose).expect("parse");
    assert!(parsed.payload.is_none());
    // Detached payload must be provided externally for Sig_structure encoding.
    let sig_struct = encode_signature1_sig_structure(&parsed, Some(b"external")).expect("sig");
    assert!(!sig_struct.is_empty());
}

#[test]
fn parse_rejects_wrong_array_length() {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(3).unwrap();
    enc.bytes(&[]).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"x").unwrap();

    let err = parse_cose_sign1(&out).unwrap_err();
    assert!(err.contains("array length"));
}

#[test]
fn parse_rejects_unexpected_tag() {
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.tag(minicbor::data::Tag::new(999)).unwrap();
    enc.array(4).unwrap();
    enc.bytes(&[]).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(b"s").unwrap();

    let err = parse_cose_sign1(&out).unwrap_err();
    assert!(err.contains("unexpected CBOR tag"));
}

#[test]
fn header_map_decodes_arrays() {
    let protected = {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(1).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.bytes(b"der").unwrap();
        buf
    };

    let mut cose = Vec::new();
    let mut enc = Encoder::new(&mut cose);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"payload").unwrap();
    enc.bytes(b"sig").unwrap();

    let parsed = parse_cose_sign1(&cose).expect("parse");
    let x5c = parsed.protected_headers.get_array(33).unwrap();
    assert_eq!(x5c.len(), 1);
    match &x5c[0] {
        HeaderValue::Bytes(b) => assert_eq!(b, b"der"),
        _ => panic!("expected bytes"),
    }
}
