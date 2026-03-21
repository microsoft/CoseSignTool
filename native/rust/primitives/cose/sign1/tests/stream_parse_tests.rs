// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoseSign1Message streaming parse.

use std::io::Cursor;
use std::sync::Arc;

use cbor_primitives::CborEncoder;
use cbor_primitives_everparse::EverParseEncoder;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::CoseData;

/// Helper: build a COSE_Sign1 message as raw bytes.
///
/// Structure: `Tag(18) [bstr(protected), unprotected_map, bstr(payload)/null, bstr(sig)]`
fn build_cose_sign1(
    protected: &[u8],
    payload: Option<&[u8]>,
    signature: &[u8],
    tagged: bool,
) -> Vec<u8> {
    let mut enc = EverParseEncoder::new();
    if tagged {
        enc.encode_tag(18).unwrap();
    }
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected).unwrap();
    enc.encode_map(0).unwrap(); // empty unprotected
    match payload {
        Some(p) => enc.encode_bstr(p).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(signature).unwrap();
    enc.into_bytes()
}

/// Helper: build a COSE_Sign1 message with a non-empty unprotected header.
fn build_cose_sign1_with_unprotected(
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Vec<u8> {
    let mut enc = EverParseEncoder::new();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected).unwrap();
    // Unprotected: {33: "application/cose"}
    enc.encode_map(1).unwrap();
    enc.encode_u32(33).unwrap(); // content-type label
    enc.encode_tstr("application/cose").unwrap();
    enc.encode_bstr(payload).unwrap();
    enc.encode_bstr(signature).unwrap();
    enc.into_bytes()
}

// ─── parse_stream basic ─────────────────────────────────────────────────────

#[test]
fn parse_stream_tagged_minimal() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let payload: &[u8] = b"test payload";
    let signature: &[u8] = &[0xAA; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");

    // Verify it is marked as streamed
    assert!(msg.is_streamed());

    // Protected header should be parseable
    assert_eq!(msg.alg(), Some(-7));

    // payload() returns None for streamed messages
    assert!(msg.payload().is_none());

    // But we can use payload_reader()
    let mut reader = msg.payload_reader().expect("should have payload reader");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf).unwrap();
    assert_eq!(buf, b"test payload");

    // Signature should be accessible
    assert_eq!(msg.signature(), &[0xAA; 32]);
}

#[test]
fn parse_stream_untagged() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let payload: &[u8] = b"hello world";
    let signature: &[u8] = &[0xBB; 64];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, false);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");

    assert!(msg.is_streamed());
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.signature(), &[0xBB; 64]);

    let mut reader = msg.payload_reader().unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf).unwrap();
    assert_eq!(buf, b"hello world");
}

#[test]
fn parse_stream_detached_payload() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let signature: &[u8] = &[0xCC; 32];
    let bytes = build_cose_sign1(&protected, None, signature, true);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");

    assert!(msg.is_streamed());
    assert!(msg.payload().is_none());
    assert!(msg.payload_reader().is_none());
    assert_eq!(msg.signature(), &[0xCC; 32]);
}

#[test]
fn parse_stream_with_unprotected_headers() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let payload: &[u8] = b"data";
    let signature: &[u8] = &[0xDD; 48];
    let bytes = build_cose_sign1_with_unprotected(&protected, payload, signature);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");

    assert!(msg.is_streamed());
    assert_eq!(msg.alg(), Some(-7));

    // Unprotected header should be accessible
    let unprotected = msg.unprotected_headers();
    assert!(!unprotected.is_empty());

    assert_eq!(msg.signature(), &[0xDD; 48]);
}

// ─── Streamed vs Buffered consistency ────────────────────────────────────────

#[test]
fn parse_stream_matches_parse_headers_and_signature() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let payload: &[u8] = b"consistency check payload";
    let signature: &[u8] = &[0xEE; 64];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let buffered_msg = CoseSign1Message::parse(&bytes).expect("buffered parse");
    let streamed_msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes.clone())).expect("stream parse");

    // Headers should match
    assert_eq!(buffered_msg.alg(), streamed_msg.alg());
    assert_eq!(
        buffered_msg.protected_header_bytes(),
        streamed_msg.protected_header_bytes()
    );

    // Signatures should match
    assert_eq!(buffered_msg.signature(), streamed_msg.signature());

    // Payload should match (buffered has it inline, streamed reads it)
    let buffered_payload = buffered_msg.payload().unwrap();
    let mut reader = streamed_msg.payload_reader().unwrap();
    let mut streamed_payload = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut streamed_payload).unwrap();
    assert_eq!(buffered_payload, &streamed_payload[..]);
}

// ─── Large payload ──────────────────────────────────────────────────────────

#[test]
fn parse_stream_large_payload() {
    // 64 KB payload to verify the streaming path handles non-trivial sizes
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26]; // {1: -7}
    let payload: Vec<u8> = vec![0x42; 65536];
    let signature: &[u8] = &[0xFF; 32];
    let bytes = build_cose_sign1(&protected, Some(&payload), signature, true);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");

    // Payload should NOT be in memory
    assert!(msg.payload().is_none());

    // Read it through payload_reader
    let mut reader = msg.payload_reader().expect("should have reader");
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf).unwrap();
    assert_eq!(buf.len(), 65536);
    assert!(buf.iter().all(|&b| b == 0x42));
}

// ─── CoseData::from_stream ─────────────────────────────────────────────────

#[test]
fn cose_data_from_stream_creates_streamed_variant() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let payload: &[u8] = b"test";
    let signature: &[u8] = &[0x11; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let data = CoseData::from_stream(Cursor::new(bytes)).expect("from_stream should succeed");

    assert!(data.is_streamed());
    // Backing buffer should contain protected + unprotected + signature
    // but NOT the payload
    let buf = data.as_bytes();
    // protected (3 bytes) + unprotected (1 byte: 0xa0) + signature (32 bytes)
    assert_eq!(buf.len(), 3 + 1 + 32);
}

#[test]
fn cose_data_from_stream_payload_location() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let payload: &[u8] = b"payload data here";
    let signature: &[u8] = &[0x22; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let data = CoseData::from_stream(Cursor::new(bytes)).expect("from_stream should succeed");

    let (offset, len) = data
        .stream_payload_location()
        .expect("should have payload location");
    assert_eq!(len as usize, payload.len());
    assert!(offset > 0); // payload is not at byte 0
}

#[test]
fn cose_data_from_stream_null_payload() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let signature: &[u8] = &[0x33; 32];
    let bytes = build_cose_sign1(&protected, None, signature, true);

    let data = CoseData::from_stream(Cursor::new(bytes)).expect("from_stream should succeed");

    assert!(data.stream_payload_location().is_none());
}

#[test]
fn cose_data_read_stream_payload() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let payload: &[u8] = b"readable payload";
    let signature: &[u8] = &[0x44; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let data = CoseData::from_stream(Cursor::new(bytes)).expect("from_stream should succeed");

    let read_payload = data
        .read_stream_payload()
        .expect("should return Some")
        .expect("read should succeed");
    assert_eq!(read_payload, b"readable payload");
}

// ─── Error cases ────────────────────────────────────────────────────────────

#[test]
fn parse_stream_wrong_tag_fails() {
    // Build with wrong tag
    let mut enc = EverParseEncoder::new();
    enc.encode_tag(99).unwrap(); // wrong tag
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    let bytes = enc.into_bytes();

    assert!(CoseSign1Message::parse_stream(Cursor::new(bytes)).is_err());
}

#[test]
fn parse_stream_wrong_array_len_fails() {
    let mut enc = EverParseEncoder::new();
    enc.encode_tag(18).unwrap();
    enc.encode_array(3).unwrap(); // wrong: need 4
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(&[]).unwrap();
    let bytes = enc.into_bytes();

    assert!(CoseSign1Message::parse_stream(Cursor::new(bytes)).is_err());
}

#[test]
fn cose_data_from_stream_empty_input_fails() {
    let bytes: Vec<u8> = vec![];
    assert!(CoseData::from_stream(Cursor::new(bytes)).is_err());
}

// ─── Clone behavior ─────────────────────────────────────────────────────────

#[test]
fn streamed_cose_data_clone_shares_source() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let payload: &[u8] = b"shared";
    let signature: &[u8] = &[0x55; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let data1 = CoseData::from_stream(Cursor::new(bytes)).expect("from_stream should succeed");
    let data2 = data1.clone();

    // Both should reference the same header_buf
    assert!(Arc::ptr_eq(data1.arc(), data2.arc()));
}

#[test]
fn streamed_message_clone_preserves_access() {
    let protected: Vec<u8> = vec![0xa1, 0x01, 0x26];
    let payload: &[u8] = b"cloned payload";
    let signature: &[u8] = &[0x66; 32];
    let bytes = build_cose_sign1(&protected, Some(payload), signature, true);

    let msg =
        CoseSign1Message::parse_stream(Cursor::new(bytes)).expect("parse_stream should succeed");
    let cloned = msg.clone();

    assert_eq!(cloned.alg(), Some(-7));
    assert_eq!(cloned.signature(), &[0x66; 32]);
}
