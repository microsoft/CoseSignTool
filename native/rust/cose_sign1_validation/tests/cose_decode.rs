// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::CoseSign1;
use tinycbor::{Encode, Encoder};

fn build_minimal_sign1_array() -> Vec<u8> {
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(4).unwrap();
    b"\xa0".as_slice().encode(&mut enc).unwrap(); // protected header bytes: empty map
    enc.map(0).unwrap(); // unprotected header: empty map
    Option::<&[u8]>::None.encode(&mut enc).unwrap(); // payload: null
    b"sig".as_slice().encode(&mut enc).unwrap(); // signature
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn decode_sign1_minimal() {
    // Build a minimal COSE_Sign1:
    // [ protected: bstr, unprotected: {}, payload: null, signature: bstr ]
    let cbor = build_minimal_sign1_array();
    let msg = CoseSign1::from_cbor(&cbor).unwrap();
    assert_eq!(b"\xa0".as_slice(), msg.protected_header);
    assert_eq!(None, msg.payload);
    assert_eq!(b"sig".as_slice(), msg.signature);
}

#[test]
fn decode_accepts_standard_cose_tag_18_short_form() {
    let mut tagged = vec![0xD2u8]; // tag(18), additional info 18
    tagged.extend(build_minimal_sign1_array());
    let msg = CoseSign1::from_cbor(&tagged).unwrap();
    assert_eq!(b"sig".as_slice(), msg.signature);
}

#[test]
fn decode_accepts_tag_18_with_uint8_uint16_uint32_uint64_encodings() {
    let sign1 = build_minimal_sign1_array();

    // uint8 (ai=24)
    let mut t = vec![0xD8u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1::from_cbor(&t).is_ok());

    // uint16 (ai=25)
    let mut t = vec![0xD9u8, 0x00u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1::from_cbor(&t).is_ok());

    // uint32 (ai=26)
    let mut t = vec![0xDAu8, 0x00u8, 0x00u8, 0x00u8, 0x12u8];
    t.extend(sign1.iter().copied());
    assert!(CoseSign1::from_cbor(&t).is_ok());

    // uint64 (ai=27)
    let mut t = vec![0xDBu8, 0, 0, 0, 0, 0, 0, 0, 0x12u8];
    t.extend(sign1);
    assert!(CoseSign1::from_cbor(&t).is_ok());
}

#[test]
fn decode_rejects_unexpected_tag_value() {
    let mut tagged = vec![0xD1u8]; // tag(17)
    tagged.extend(build_minimal_sign1_array());
    let err = CoseSign1::from_cbor(&tagged).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("unexpected CBOR tag"));
}

#[test]
fn decode_rejects_invalid_tag_encoding() {
    // tag(ai=24) with missing following byte
    let tagged = vec![0xD8u8];
    let err = CoseSign1::from_cbor(&tagged).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("invalid CBOR tag encoding"));

    // tag(ai=28) is not valid for our decoder
    let tagged = vec![0xDCu8, 0x00u8];
    let err = CoseSign1::from_cbor(&tagged).unwrap_err();
    let s = err.to_string();
    assert!(s.contains("invalid CBOR tag encoding"));
}

#[test]
fn decode_rejects_arrays_with_missing_or_extra_items() {
    // Missing signature (array of 3)
    let mut buf = vec![0u8; 64];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(3).unwrap();
    b"\xa0".as_slice().encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    assert!(matches!(
        CoseSign1::from_cbor(&buf).unwrap_err(),
        cose_sign1_validation::cose::CoseDecodeError::NotSign1
    ));

    // Extra item (array of 5)
    let mut buf = vec![0u8; 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());
    enc.array(5).unwrap();
    b"\xa0".as_slice().encode(&mut enc).unwrap();
    enc.map(0).unwrap();
    Option::<&[u8]>::None.encode(&mut enc).unwrap();
    b"sig".as_slice().encode(&mut enc).unwrap();
    1i64.encode(&mut enc).unwrap();
    let used = buf_len - enc.0.len();
    buf.truncate(used);
    assert!(matches!(
        CoseSign1::from_cbor(&buf).unwrap_err(),
        cose_sign1_validation::cose::CoseDecodeError::NotSign1
    ));
}

#[test]
fn decode_rejects_empty_input() {
    let err = CoseSign1::from_cbor(&[]).unwrap_err();
    assert!(matches!(
        err,
        cose_sign1_validation::cose::CoseDecodeError::Cbor(_)
    ));
}
