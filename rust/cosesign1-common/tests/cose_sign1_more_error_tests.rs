// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_common::parse_cose_sign1;

#[test]
fn parse_rejects_top_level_not_array() {
    let mut bytes = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut bytes);
    enc.map(0).unwrap();

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("not an array"), "err was: {err}");
}

#[test]
fn parse_rejects_indefinite_length_array() {
    // Indefinite-length array start + break.
    let bytes = vec![0x9f, 0xff];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.to_lowercase().contains("indefinite"), "err was: {err}");
}

#[test]
fn parse_reports_failed_to_read_cbor_tag_when_truncated() {
    // Tag with additional byte required but missing.
    let bytes = vec![0xd8];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("failed to read CBOR tag"), "err was: {err}");
}

#[test]
fn parse_reports_failed_to_read_protected_headers_when_not_bstr() {
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.array(4).unwrap();

    // Protected headers must be bstr, but we encode a map instead.
    enc.map(0).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[]).unwrap();

    let err = parse_cose_sign1(&out).unwrap_err();
    assert!(err.contains("protected headers"), "err was: {err}");
}

#[test]
fn parse_reports_failed_to_read_payload_bytes_when_truncated() {
    // COSE_Sign1 array(4):
    // protected: empty bstr (=> empty protected header map)
    // unprotected: map(0)
    // payload: bstr len=3 but only 1 byte present
    // signature: (never reached)
    let bytes = vec![0x84, 0x40, 0xa0, 0x43, 0x01];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("failed to read payload"), "err was: {err}");
}

#[test]
fn parse_reports_failed_to_read_protected_bstr_when_truncated() {
    // array(4), protected is bstr len=3 but only 1 byte present.
    let bytes = vec![0x84, 0x43, 0x01];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("protected headers"), "err was: {err}");
}

#[test]
fn parse_reports_unprotected_map_decode_error_when_truncated_map_header() {
    // COSE_Sign1 array(4):
    // protected: empty bstr
    // unprotected: map with u32 length, but missing the 4 length bytes
    let bytes = vec![0x84, 0x40, 0xba];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("failed to read map"), "err was: {err}");
}

#[test]
fn parse_reports_failed_to_read_signature_bytes_when_truncated() {
    // COSE_Sign1 array(4):
    // protected: empty bstr
    // unprotected: map(0)
    // payload: empty bstr
    // signature: bstr len=3 but only 1 byte present
    let bytes = vec![0x84, 0x40, 0xa0, 0x40, 0x43, 0x01];

    let err = parse_cose_sign1(&bytes).unwrap_err();
    assert!(err.contains("failed to read signature"), "err was: {err}");
}
