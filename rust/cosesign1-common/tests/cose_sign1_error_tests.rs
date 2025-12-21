// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Negative tests for COSE_Sign1 parsing.
//!
//! These tests intentionally construct malformed COSE_Sign1 structures to
//! validate error handling and ensure we return clear diagnostics instead of
//! panicking.

use cosesign1_common::parse_cose_sign1;

// Helper to build a minimal COSE_Sign1 with controlled type mistakes.
fn encode_sign1(protected: &[u8], unprotected_is_map: bool, payload_kind: PayloadKind, signature_is_bytes: bool) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);

    enc.array(4).unwrap();
    enc.bytes(protected).unwrap();

    if unprotected_is_map {
        enc.map(0).unwrap();
    } else {
        enc.array(0).unwrap();
    }

    match payload_kind {
        PayloadKind::Bytes => {
            enc.bytes(b"payload").unwrap();
        }
        PayloadKind::Null => {
            enc.null().unwrap();
        }
        PayloadKind::Text => {
            enc.str("payload").unwrap();
        }
    };

    if signature_is_bytes {
        enc.bytes(&[0u8; 64]).unwrap();
    } else {
        enc.str("not-bytes").unwrap();
    }

    out
}

enum PayloadKind {
    Bytes,
    Null,
    Text,
}

#[test]
fn parse_rejects_unprotected_not_map() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let msg = encode_sign1(&protected_map, false, PayloadKind::Bytes, true);

    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unprotected"));
}

#[test]
fn parse_rejects_payload_wrong_type() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let msg = encode_sign1(&protected_map, true, PayloadKind::Text, true);

    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("payload"));
}

#[test]
fn parse_rejects_signature_not_bytes() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let msg = encode_sign1(&protected_map, true, PayloadKind::Bytes, false);

    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("signature"));
}

#[test]
fn parse_rejects_protected_header_not_map() {
    // Protected bstr contains CBOR array instead of map.
    let mut protected = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut protected);
    enc.array(0).unwrap();

    let msg = encode_sign1(&protected, true, PayloadKind::Bytes, true);
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.to_lowercase().contains("expected map"), "err was: {err}");
}

#[test]
fn parse_rejects_trailing_bytes() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let mut msg = encode_sign1(&protected_map, true, PayloadKind::Bytes, true);
    msg.push(0x00);

    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("trailing bytes"));
}

#[test]
fn parse_accepts_detached_payload_null() {
    let protected_map = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let msg = encode_sign1(&protected_map, true, PayloadKind::Null, true);

    let parsed = parse_cose_sign1(&msg).expect("parse");
    assert!(parsed.payload.is_none());
}
