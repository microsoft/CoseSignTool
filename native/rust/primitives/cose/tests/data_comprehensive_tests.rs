// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for `CoseData` covering buffered construction,
//! streamed construction, and all accessors.

use std::io::Cursor;
use std::sync::Arc;

use cose_primitives::{CoseData, CoseError};
// ============================================================================
// Buffered constructors
// ============================================================================

#[test]
fn cose_data_from_arc() {
    let arc: Arc<[u8]> = Arc::from(vec![10, 20, 30]);
    let data = CoseData::from_arc(arc.clone());
    assert_eq!(data.as_bytes(), &[10, 20, 30]);
    assert!(Arc::ptr_eq(data.arc(), &arc));
}

#[test]
fn cose_data_buffered_debug() {
    let data = CoseData::new(vec![1, 2, 3]);
    let dbg = format!("{:?}", data);
    assert!(dbg.contains("Buffered"));
    assert!(dbg.contains("len"));
}

#[test]
fn cose_data_buffered_is_not_streamed() {
    let data = CoseData::new(vec![1]);
    assert!(!data.is_streamed());
}

#[test]
fn cose_data_buffered_stream_payload_location_is_none() {
    let data = CoseData::new(vec![1, 2, 3]);
    assert!(data.stream_payload_location().is_none());
}

#[test]
fn cose_data_buffered_read_stream_payload_is_none() {
    let data = CoseData::new(vec![1, 2, 3]);
    assert!(data.read_stream_payload().is_none());
}

// ============================================================================
// Streamed constructor (from_stream)
// ============================================================================

/// Build a minimal COSE_Sign1 CBOR message in memory for stream parsing.
fn build_cose_sign1_bytes(payload: &[u8]) -> Vec<u8> {
    // Tag(18) + Array(4)
    let mut buf = Vec::new();

    // CBOR Tag 18
    buf.push(0xD8);
    buf.push(18);

    // Array of 4 items
    buf.push(0x84);

    // Item 1: Protected header (bstr wrapping empty map 0xA0)
    buf.push(0x41); // bstr(1)
    buf.push(0xA0); // empty map

    // Item 2: Unprotected header (empty map)
    buf.push(0xA0);

    // Item 3: Payload (bstr)
    if payload.len() < 24 {
        buf.push(0x40 | payload.len() as u8);
    } else {
        buf.push(0x58);
        buf.push(payload.len() as u8);
    }
    buf.extend_from_slice(payload);

    // Item 4: Signature (bstr of 32 zero bytes)
    buf.push(0x58);
    buf.push(32);
    buf.extend_from_slice(&[0u8; 32]);

    buf
}

#[test]
fn cose_data_from_stream_basic() {
    let payload = b"hello world";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    assert!(data.is_streamed());
}

#[test]
fn cose_data_from_stream_payload_location() {
    let payload = b"test payload";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let location = data.stream_payload_location();
    assert!(location.is_some());
    let (offset, len) = location.unwrap();
    assert_eq!(len as usize, payload.len());
    assert!(offset > 0);
}

#[test]
fn cose_data_from_stream_read_payload() {
    let payload = b"read me back";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let read_result = data.read_stream_payload();
    assert!(read_result.is_some());
    let buf = read_result.unwrap().expect("read should succeed");
    assert_eq!(&buf, payload);
}

#[test]
fn cose_data_from_stream_debug() {
    let payload = b"debug";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let dbg = format!("{:?}", data);
    assert!(dbg.contains("Streamed"));
    assert!(dbg.contains("payload_offset"));
    assert!(dbg.contains("payload_len"));
}

#[test]
fn cose_data_from_stream_as_bytes_returns_header_buf() {
    let payload = b"data";
    let cbor = build_cose_sign1_bytes(payload);
    let cbor_len = cbor.len();
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    // header_buf contains: protected + unprotected_raw + signature
    let bytes = data.as_bytes();
    assert!(!bytes.is_empty());
    // Should NOT contain the full original message
    assert!(bytes.len() < cbor_len);
}

#[test]
fn cose_data_from_stream_arc_returns_header_buf_arc() {
    let payload = b"arc test";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let arc = data.arc();
    assert_eq!(arc.as_ref(), data.as_bytes());
}

#[test]
fn cose_data_from_stream_slice() {
    let payload = b"slicing";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let all = data.slice(&(0..data.len()));
    assert_eq!(all, data.as_bytes());
}

#[test]
fn cose_data_from_stream_clone_is_cheap() {
    let payload = b"clone";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let cloned = data.clone();
    assert!(data.is_streamed());
    assert!(cloned.is_streamed());
    assert!(Arc::ptr_eq(data.arc(), cloned.arc()));
}

// ============================================================================
// Streamed with null/detached payload
// ============================================================================

/// Build COSE_Sign1 with null payload.
fn build_cose_sign1_null_payload() -> Vec<u8> {
    let mut buf = Vec::new();
    // Tag(18)
    buf.push(0xD8);
    buf.push(18);
    // Array(4)
    buf.push(0x84);
    // Protected header (bstr wrapping empty map)
    buf.push(0x41);
    buf.push(0xA0);
    // Unprotected header (empty map)
    buf.push(0xA0);
    // Payload: null
    buf.push(0xF6);
    // Signature (bstr of 32 zero bytes)
    buf.push(0x58);
    buf.push(32);
    buf.extend_from_slice(&[0u8; 32]);
    buf
}

#[test]
fn cose_data_from_stream_null_payload() {
    let cbor = build_cose_sign1_null_payload();
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    assert!(data.is_streamed());
    assert!(data.stream_payload_location().is_none());
    assert!(data.read_stream_payload().is_none());
}

// ============================================================================
// Error cases
// ============================================================================

#[test]
fn cose_data_from_stream_wrong_tag() {
    let mut cbor = Vec::new();
    // Tag 99 instead of 18
    cbor.push(0xD8);
    cbor.push(99);
    cbor.push(0x84);
    cbor.push(0x40); // empty bstr
    cbor.push(0xA0); // empty map
    cbor.push(0xF6); // null
    cbor.push(0x40); // empty bstr

    let cursor = Cursor::new(cbor);
    let result = CoseData::from_stream(cursor);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, CoseError::InvalidMessage(_)));
}

#[test]
fn cose_data_from_stream_wrong_array_len() {
    let mut cbor = Vec::new();
    // Tag 18
    cbor.push(0xD8);
    cbor.push(18);
    // Array of 3 (wrong, needs 4)
    cbor.push(0x83);
    cbor.push(0x40);
    cbor.push(0xA0);
    cbor.push(0xF6);

    let cursor = Cursor::new(cbor);
    let result = CoseData::from_stream(cursor);
    assert!(result.is_err());
}

#[test]
fn cose_data_from_stream_no_tag() {
    // COSE_Sign1 without tag — just array(4) directly
    let mut cbor = Vec::new();
    cbor.push(0x84); // Array(4)
    cbor.push(0x41); // bstr(1)
    cbor.push(0xA0); // empty map (protected)
    cbor.push(0xA0); // empty map (unprotected)
                     // payload
    cbor.push(0x44); // bstr(4)
    cbor.extend_from_slice(b"test");
    // signature
    cbor.push(0x44); // bstr(4)
    cbor.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let cursor = Cursor::new(cbor);
    let data = CoseData::from_stream(cursor).expect("tagless COSE should parse");
    assert!(data.is_streamed());
    let payload = data.read_stream_payload().unwrap().unwrap();
    assert_eq!(payload, b"test");
}

#[test]
fn cose_data_from_stream_indefinite_array() {
    let mut cbor = Vec::new();
    cbor.push(0xD8);
    cbor.push(18);
    // Indefinite-length array
    cbor.push(0x9F);
    cbor.push(0x40);
    cbor.push(0xA0);
    cbor.push(0xF6);
    cbor.push(0x40);
    cbor.push(0xFF); // break

    let cursor = Cursor::new(cbor);
    let result = CoseData::from_stream(cursor);
    assert!(result.is_err());
}

// ============================================================================
// CoseData len/is_empty for streamed
// ============================================================================

#[test]
fn cose_data_streamed_len_is_header_buf_len() {
    let payload = b"payload data";
    let cbor = build_cose_sign1_bytes(payload);
    let cursor = Cursor::new(cbor);

    let data = CoseData::from_stream(cursor).expect("from_stream should succeed");
    let bytes_len = data.as_bytes().len();
    assert_eq!(data.len(), bytes_len);
    assert!(!data.is_empty());
}
