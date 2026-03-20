// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting uncovered FFI headermap accessor paths in lib.rs:
//! - headermap_get_int_inner: Uint branch (lines 345-352)
//! - headermap_get_bytes_inner: Bytes branch (lines 395-400)
//! - headermap_get_text_inner: Text branch (lines 438-440)

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives_ffi::message::message_parse_inner;
use cose_sign1_primitives_ffi::*;
use std::ffi::CStr;
use std::ptr;

/// Build COSE_Sign1 bytes with specific protected header entries.
/// The protected header is a bstr-wrapped CBOR map.
fn build_cose_with_headers(
    header_entries: &[(
        i64,
        &dyn Fn(&mut cbor_primitives_everparse::EverParseEncoder),
    )],
) -> Vec<u8> {
    let p = EverParseCborProvider;

    // Encode protected header map
    let mut hdr = p.encoder();
    hdr.encode_map(header_entries.len()).unwrap();
    for (label, encode_value) in header_entries {
        hdr.encode_i64(*label).unwrap();
        encode_value(&mut hdr);
    }
    let hdr_bytes = hdr.into_bytes();

    // Encode COSE_Sign1 array
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&hdr_bytes).unwrap(); // protected
    enc.encode_map(0).unwrap(); // unprotected
    enc.encode_bstr(b"payload").unwrap(); // payload
    enc.encode_bstr(b"sig").unwrap(); // signature
    enc.into_bytes()
}

/// Parse COSE bytes and return a message handle. Caller must free.
fn parse_message(bytes: &[u8]) -> *mut CoseSign1MessageHandle {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_parse_inner(bytes.as_ptr(), bytes.len(), &mut msg, &mut err);
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
    assert_eq!(rc, COSE_SIGN1_OK, "failed to parse COSE message");
    assert!(!msg.is_null());
    msg
}

/// Get protected headers handle from a message. Caller must free.
fn get_protected_headers(msg: *const CoseSign1MessageHandle) -> *mut CoseHeaderMapHandle {
    let mut hdrs: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = message_protected_headers_inner(msg, &mut hdrs);
    assert_eq!(rc, COSE_SIGN1_OK);
    assert!(!hdrs.is_null());
    hdrs
}

// -----------------------------------------------------------------------
// Tests for headermap_get_bytes_inner (lines 395-400)
// -----------------------------------------------------------------------

#[test]
fn headermap_get_bytes_returns_bytes_value() {
    // Protected header: { 100: h'DEADBEEF' }
    let cose = build_cose_with_headers(&[(
        100,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            enc.encode_bstr(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        },
    )]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    let mut out_bytes: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let rc = headermap_get_bytes_inner(hdrs, 100, &mut out_bytes, &mut out_len);
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(out_len, 4);
    let slice = unsafe { std::slice::from_raw_parts(out_bytes, out_len) };
    assert_eq!(slice, &[0xDE, 0xAD, 0xBE, 0xEF]);

    // Non-existent label returns not-found
    let rc2 = headermap_get_bytes_inner(hdrs, 999, &mut out_bytes, &mut out_len);
    assert_eq!(rc2, COSE_SIGN1_ERR_HEADER_NOT_FOUND);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn headermap_get_bytes_null_params() {
    let mut out_bytes: *const u8 = ptr::null();
    let mut out_len: usize = 0;

    // Null headers
    let rc = headermap_get_bytes_inner(ptr::null(), 1, &mut out_bytes, &mut out_len);
    assert_ne!(rc, COSE_SIGN1_OK);

    // Null out_bytes
    let cose = build_cose_with_headers(&[(
        100,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            enc.encode_bstr(&[0x01]).unwrap();
        },
    )]);
    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    let rc = headermap_get_bytes_inner(hdrs, 100, ptr::null_mut(), &mut out_len);
    assert_ne!(rc, COSE_SIGN1_OK);

    let rc = headermap_get_bytes_inner(hdrs, 100, &mut out_bytes, ptr::null_mut());
    assert_ne!(rc, COSE_SIGN1_OK);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

// -----------------------------------------------------------------------
// Tests for headermap_get_text_inner (lines 438-440)
// -----------------------------------------------------------------------

#[test]
fn headermap_get_text_returns_text_value() {
    // Protected header: { 3: "application/cose" }
    // Label 3 is content_type
    let cose = build_cose_with_headers(&[(
        3,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            enc.encode_tstr("application/cose").unwrap();
        },
    )]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    let text_ptr = headermap_get_text_inner(hdrs, 3);
    assert!(!text_ptr.is_null());
    let text = unsafe { CStr::from_ptr(text_ptr) }
        .to_string_lossy()
        .to_string();
    assert_eq!(text, "application/cose");
    unsafe { cose_sign1_string_free(text_ptr) };

    // Non-existent label returns null
    let text_ptr2 = headermap_get_text_inner(hdrs, 999);
    assert!(text_ptr2.is_null());

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn headermap_get_text_null_headers() {
    let text_ptr = headermap_get_text_inner(ptr::null(), 3);
    assert!(text_ptr.is_null());
}

// -----------------------------------------------------------------------
// Tests for headermap_get_int_inner Uint branch (lines 345-352)
// We need a header with unsigned int > i64::MAX to get CoseHeaderValue::Uint.
// But encode_u64 with value <= i64::MAX gets parsed as Int, not Uint.
// So we encode a raw CBOR uint with major type 0 and value > i64::MAX.
// -----------------------------------------------------------------------

#[test]
fn headermap_get_int_for_regular_int() {
    // Protected header: { 1: -7 } (alg = ES256)
    let cose = build_cose_with_headers(&[(
        1,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            enc.encode_i64(-7).unwrap();
        },
    )]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    let mut out_val: i64 = 0;
    let rc = headermap_get_int_inner(hdrs, 1, &mut out_val);
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(out_val, -7);

    // Non-existent label
    let rc2 = headermap_get_int_inner(hdrs, 999, &mut out_val);
    assert_eq!(rc2, COSE_SIGN1_ERR_HEADER_NOT_FOUND);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn headermap_get_int_uint_overflow() {
    // Encode a CBOR uint > i64::MAX. Major type 0, additional info 27 (8 bytes),
    // value = 0x8000000000000000 = i64::MAX + 1.
    // This will be parsed as CoseHeaderValue::Uint(9223372036854775808).
    let cose = build_cose_with_headers(&[(
        99,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            // Encode raw bytes for CBOR uint > i64::MAX
            // Major type 0, additional info 27 (0x1B), followed by 8 bytes
            enc.encode_raw(&[0x1B, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .unwrap();
        },
    )]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    // The uint value > i64::MAX should return FFI_ERR_INVALID_ARGUMENT
    let mut out_val: i64 = 0;
    let rc = headermap_get_int_inner(hdrs, 99, &mut out_val);
    assert_eq!(rc, COSE_SIGN1_ERR_INVALID_ARGUMENT);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn headermap_get_int_uint_in_range() {
    // Encode a CBOR uint that fits in i64. Value = 42.
    // Major type 0, additional info 24 (0x18), value 42 (0x2A).
    // This gets parsed as Int(42), NOT Uint(42), because 42 <= i64::MAX.
    // The Uint branch at line 345 requires value > i64::MAX parsed as Uint.
    // Let's use a value just at i64::MAX = 9223372036854775807.
    let cose = build_cose_with_headers(&[(
        98,
        &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
            // CBOR uint, value = i64::MAX = 0x7FFFFFFFFFFFFFFF
            enc.encode_raw(&[0x1B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
                .unwrap();
        },
    )]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    // i64::MAX gets parsed as Int(i64::MAX)
    let mut out_val: i64 = 0;
    let rc = headermap_get_int_inner(hdrs, 98, &mut out_val);
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(out_val, i64::MAX);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}

// -----------------------------------------------------------------------
// Tests for headermap_contains_inner and headermap_len_inner
// -----------------------------------------------------------------------

#[test]
fn headermap_contains_and_len() {
    let cose = build_cose_with_headers(&[
        (
            1,
            &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
                enc.encode_i64(-7).unwrap();
            },
        ),
        (
            3,
            &|enc: &mut cbor_primitives_everparse::EverParseEncoder| {
                enc.encode_tstr("text/plain").unwrap();
            },
        ),
    ]);

    let msg = parse_message(&cose);
    let hdrs = get_protected_headers(msg);

    // Contains
    assert!(headermap_contains_inner(hdrs, 1));
    assert!(headermap_contains_inner(hdrs, 3));
    assert!(!headermap_contains_inner(hdrs, 999));

    // Len
    assert_eq!(headermap_len_inner(hdrs), 2);

    // Null headers
    assert!(!headermap_contains_inner(ptr::null(), 1));
    assert_eq!(headermap_len_inner(ptr::null()), 0);

    unsafe { cose_headermap_free(hdrs as *mut _) };
    unsafe { cose_sign1_message_free(msg) };
}
