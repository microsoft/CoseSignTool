// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;

fn build_minimal_sign1_array() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(b"\xa0").unwrap(); // protected header bytes: empty map
    enc.encode_map(0).unwrap(); // unprotected header: empty map
    enc.encode_null().unwrap(); // payload: null
    enc.encode_bstr(b"sig").unwrap(); // signature
    enc.into_bytes()
}

#[test]
fn decode_sign1_minimal() {
    // Build a minimal COSE_Sign1:
    // [ protected: bstr, unprotected: {}, payload: null, signature: bstr ]
    let cbor = build_minimal_sign1_array();
    let msg = CoseSign1Message::parse(&cbor).unwrap();
    assert_eq!(b"\xa0".as_slice(), msg.protected.as_bytes());
    assert_eq!(None, msg.payload);
    assert_eq!(b"sig".as_slice(), msg.signature.as_slice());
}

#[test]
fn decode_accepts_standard_cose_tag_18_short_form() {
    let mut tagged = vec![0xD2u8]; // tag(18), additional info 18
    tagged.extend(build_minimal_sign1_array());
    let msg = CoseSign1Message::parse(&tagged).unwrap();
    assert_eq!(b"sig".as_slice(), msg.signature.as_slice());
}

#[test]
fn decode_accepts_tag_18_with_uint8_uint16_uint32_uint64_encodings() {
    let sign1 = build_minimal_sign1_array();

    // uint8 (ai=24)
    let mut t = vec![0xD8u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1Message::parse(&t).is_ok());

    // uint16 (ai=25)
    let mut t = vec![0xD9u8, 0x00u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1Message::parse(&t).is_ok());

    // uint32 (ai=26)
    let mut t = vec![0xDAu8, 0x00u8, 0x00u8, 0x00u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1Message::parse(&t).is_ok());

    // uint64 (ai=27)
    let mut t = vec![0xDBu8, 0, 0, 0, 0, 0, 0, 0, 0x12u8];
    t.extend(sign1);
    assert!(CoseSign1Message::parse(&t).is_ok());
}

#[test]
fn decode_rejects_unexpected_tag_value() {
    let mut tagged = vec![0xD1u8]; // tag(17)
    tagged.extend(build_minimal_sign1_array());
    let err = CoseSign1Message::parse(&tagged).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("unexpected") || s.contains("tag"));
}

#[test]
fn decode_rejects_invalid_tag_encoding() {
    // tag(ai=24) with missing following byte
    let tagged = vec![0xD8u8];
    let err = CoseSign1Message::parse(&tagged).unwrap_err();
    let s = err.to_string();
    eprintln!("Error message 1: {}", s);
    // Error should mention CBOR or decode issue
    assert!(s.to_lowercase().contains("cbor") || s.to_lowercase().contains("decode") || s.to_lowercase().contains("incomplete"));

    // tag(ai=28) is not valid for our decoder
    let tagged = vec![0xDCu8, 0x00u8];
    let err = CoseSign1Message::parse(&tagged).unwrap_err();
    let s = err.to_string();
    eprintln!("Error message 2: {}", s);
    // Error should mention CBOR or decode issue
    assert!(s.to_lowercase().contains("cbor") || s.to_lowercase().contains("decode") || s.to_lowercase().contains("invalid"));
}

#[test]
fn decode_rejects_arrays_with_missing_or_extra_items() {
    // Missing signature (array of 3)
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(b"\xa0").unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    let buf = enc.into_bytes();
    let err = CoseSign1Message::parse(&buf).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("4") || s.contains("elements") || s.contains("Sign1"));

    // Extra item (array of 5)
    let mut enc = p.encoder();
    enc.encode_array(5).unwrap();
    enc.encode_bstr(b"\xa0").unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    enc.encode_i64(1).unwrap();
    let buf = enc.into_bytes();
    let err = CoseSign1Message::parse(&buf).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("4") || s.contains("elements") || s.contains("Sign1"));
}

#[test]
fn decode_rejects_empty_input() {
    let err = CoseSign1Message::parse(&[]).unwrap_err();
    let s = err.to_string();
    assert!(s.to_lowercase().contains("cbor") || s.to_lowercase().contains("empty") || s.to_lowercase().contains("incomplete"));
}
