// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for COSE_Sign1 parsing.
//!
//! These tests focus on the byte-level CBOR/COSE parsing entry points:
//! - `parse_cose_sign1` (in-memory)
//! - `parse_cose_sign1_from_reader*` (streaming)
//!
//! The intent is to cover both "happy path" parsing and the error messages
//! returned for malformed inputs.

mod common;

use common::*;
use minicbor::data::Tag;

/// Rejects empty input, unexpected tags, and trailing bytes.
#[test]
fn parse_rejects_empty_and_rejects_unexpected_tag_and_trailing_bytes() {
    assert!(cosesign1::parse_cose_sign1(&[])
        .unwrap_err()
        .contains("empty input"));

    // Unexpected tag (not 18).
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.tag(Tag::new(19)).unwrap();
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let msg = enc.into_writer();
    let err = cosesign1::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unexpected CBOR tag"));

    // Trailing bytes after a valid COSE_Sign1.
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let mut msg_with_trailing = msg.clone();
    msg_with_trailing.push(0x00);
    let err = cosesign1::parse_cose_sign1(&msg_with_trailing).unwrap_err();
    assert!(err.contains("trailing bytes after COSE_Sign1"));
}

/// Validates reader-based parsing and enforcement of `max_len`.
#[test]
fn parse_from_reader_variants_work_and_enforce_max_len() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);

    let parsed = cosesign1::parse_cose_sign1_from_reader(std::io::Cursor::new(msg.clone())).unwrap();
    assert_eq!(parsed.payload.as_deref(), Some(b"hello".as_slice()));

    let parsed = cosesign1::parse_cose_sign1_from_reader_with_max_len(std::io::Cursor::new(msg.clone()), msg.len()).unwrap();
    assert_eq!(parsed.payload.as_deref(), Some(b"hello".as_slice()));

    let err = cosesign1::parse_cose_sign1_from_reader_with_max_len(std::io::Cursor::new(msg), 1).unwrap_err();
    assert!(err.contains("exceeded max length"));
}

/// Validates IO error reporting for reader-based parsing.
#[test]
fn parse_from_reader_reports_io_errors() {
    let err = cosesign1::parse_cose_sign1_from_reader(ErrorReadSeek { err: "boom" }).unwrap_err();
    assert!(err.contains("failed to read COSE_Sign1 bytes"));
}

/// Rejects protected header bytes that contain trailing CBOR bytes.
#[test]
fn parse_rejects_protected_header_map_with_trailing_bytes() {
    let mut protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    protected.push(0x00);

    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = cosesign1::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("trailing bytes"));
}

/// Rejects wrong CBOR item types for the protected headers and signature.
#[test]
fn parse_reports_non_bstr_protected_headers_and_non_bstr_signature() {
    // protected should be bstr, but here it's int
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.i64(1).unwrap();
    enc.map(0).unwrap();
    enc.null().unwrap();
    enc.bytes(&[]).unwrap();
    let bad_protected = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&bad_protected).is_err());

    // signature should be bstr, but here it's int
    let protected = encode_protected_header_bytes(&[]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.i64(1).unwrap();
    let bad_sig = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&bad_sig).is_err());
}

/// Rejects protected header bytes that decode to a non-map CBOR value.
#[test]
fn parse_reports_protected_header_bytes_that_are_not_a_cbor_map() {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.i64(1).unwrap();
    let protected = enc.into_writer();
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = cosesign1::parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read map"));
}

/// Exercises several parse error branches for malformed COSE_Sign1 structures.
#[test]
fn cose_sign1_parse_error_paths_are_exercised() {
    // Empty input.
    assert!(cosesign1::parse_cose_sign1(&[]).is_err());

    // Wrong array length.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(3).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    let wrong_len = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&wrong_len).is_err());

    // Unprotected headers not a map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.array(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_unprotected = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&wrong_unprotected).is_err());

    // Payload wrong type.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.i64(1).unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_payload = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&wrong_payload).is_err());

    // Protected header map contains trailing bytes.
    let mut protected_with_trailing = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    protected_with_trailing.extend_from_slice(&[0x00]);
    let bad = encode_cose_sign1(false, &protected_with_trailing, &[], Some(b"hello"), &[0u8; 64]);
    assert!(cosesign1::parse_cose_sign1(&bad).is_err());

    // Protected header map uses an unsupported key type.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.bytes(b"not allowed").unwrap();
    enc.i64(1).unwrap();
    let protected_bad_key = enc.into_writer();
    let bad2 = encode_cose_sign1(false, &protected_bad_key, &[], Some(b"hello"), &[0u8; 64]);
    assert!(cosesign1::parse_cose_sign1(&bad2).is_err());
}

/// Exercises "top-level not array" and a truncated CBOR tag header.
#[test]
fn cose_parse_reports_top_level_not_array_and_truncated_tag() {
    // Not an array.
    assert!(cosesign1::parse_cose_sign1(&[0x01]).is_err());

    // Truncated tag header (tag with 1-byte argument but missing that byte).
    assert!(cosesign1::parse_cose_sign1(&[0xD8]).is_err());
}

/// Exercises type checking for protected and signature elements.
#[test]
fn cose_parse_reports_wrong_item_types_for_protected_and_signature() {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    // protected should be bstr, but here it's int
    enc.i64(1).unwrap();
    enc.map(0).unwrap();
    enc.null().unwrap();
    enc.bytes(&[]).unwrap();
    let bad_protected = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&bad_protected).is_err());

    let protected = encode_protected_header_bytes(&[]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    // signature should be bstr, but here it's int
    enc.i64(1).unwrap();
    let bad_sig = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&bad_sig).is_err());
}

/// Explicitly rejects wrong COSE tag and trailing bytes.
#[test]
fn parse_rejects_wrong_tag_and_trailing_bytes() {
    // Wrong tag.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.tag(Tag::new(19)).unwrap();
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_tag = enc.into_writer();
    assert!(cosesign1::parse_cose_sign1(&wrong_tag).is_err());

    // Trailing bytes.
    let mut good = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    good.extend_from_slice(&[0x00, 0x01]);
    assert!(cosesign1::parse_cose_sign1(&good).is_err());
}
