// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the streaming CBOR decoder.

use std::io::Cursor;

use cbor_primitives::{CborStreamDecoder, CborType};
use cbor_primitives_everparse::EverparseStreamDecoder;

// ─── peek_type ───────────────────────────────────────────────────────────────

#[test]
fn stream_peek_type_unsigned_int() {
    let data = vec![0x05]; // uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::UnsignedInt);
    // peek should not consume
    assert_eq!(dec.position(), 0);
}

#[test]
fn stream_peek_type_negative_int() {
    let data = vec![0x20]; // nint -1
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::NegativeInt);
}

#[test]
fn stream_peek_type_byte_string() {
    let data = vec![0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::ByteString);
}

#[test]
fn stream_peek_type_text_string() {
    let data = vec![0x63, b'a', b'b', b'c']; // tstr "abc"
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::TextString);
}

#[test]
fn stream_peek_type_array() {
    let data = vec![0x82, 0x01, 0x02]; // [1, 2]
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::Array);
}

#[test]
fn stream_peek_type_map() {
    let data = vec![0xa1, 0x01, 0x02]; // {1: 2}
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::Map);
}

#[test]
fn stream_peek_type_tag() {
    let data = vec![0xd8, 0x12, 0x01]; // tag(18) followed by uint 1
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::Tag);
}

#[test]
fn stream_peek_type_bool_false() {
    let data = vec![0xf4]; // false
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::Bool);
}

#[test]
fn stream_peek_type_null() {
    let data = vec![0xf6]; // null
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.peek_type().unwrap(), CborType::Null);
}

// ─── decode_u64 ──────────────────────────────────────────────────────────────

#[test]
fn stream_decode_u64_inline() {
    let data = vec![0x17]; // 23 (largest inline)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_u64().unwrap(), 23);
    assert_eq!(dec.position(), 1);
}

#[test]
fn stream_decode_u64_one_byte() {
    let data = vec![0x18, 0x64]; // 100
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_u64().unwrap(), 100);
    assert_eq!(dec.position(), 2);
}

#[test]
fn stream_decode_u64_two_bytes() {
    let data = vec![0x19, 0x03, 0xe8]; // 1000
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_u64().unwrap(), 1000);
}

#[test]
fn stream_decode_u64_four_bytes() {
    let data = vec![0x1a, 0x00, 0x0f, 0x42, 0x40]; // 1_000_000
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_u64().unwrap(), 1_000_000);
}

#[test]
fn stream_decode_u64_eight_bytes() {
    // 2^32 = 4294967296
    let data = vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_u64().unwrap(), 4_294_967_296);
}

// ─── decode_i64 ──────────────────────────────────────────────────────────────

#[test]
fn stream_decode_i64_positive() {
    let data = vec![0x0a]; // 10
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_i64().unwrap(), 10);
}

#[test]
fn stream_decode_i64_negative() {
    let data = vec![0x29]; // -10 (major type 1, arg 9 → -1-9 = -10)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_i64().unwrap(), -10);
}

#[test]
fn stream_decode_i64_negative_one() {
    let data = vec![0x20]; // -1
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_i64().unwrap(), -1);
}

// ─── decode_bstr_owned ───────────────────────────────────────────────────────

#[test]
fn stream_decode_bstr_empty() {
    let data = vec![0x40]; // bstr(0)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_bstr_owned().unwrap(), Vec::<u8>::new());
}

#[test]
fn stream_decode_bstr_with_content() {
    let data = vec![0x44, 0xDE, 0xAD, 0xBE, 0xEF]; // bstr(4) h'DEADBEEF'
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(
        dec.decode_bstr_owned().unwrap(),
        vec![0xDE, 0xAD, 0xBE, 0xEF]
    );
    assert_eq!(dec.position(), 5);
}

// ─── decode_bstr_header_offset ───────────────────────────────────────────────

#[test]
fn stream_decode_bstr_header_offset_returns_position_and_length() {
    // bstr(4) at offset 0: header is 1 byte, content starts at offset 1
    let data = vec![0x44, 0x01, 0x02, 0x03, 0x04];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(offset, 1); // content starts after the 1-byte header
    assert_eq!(len, 4);
    // Position should be at the start of content, not past it
    assert_eq!(dec.position(), 1);
}

#[test]
fn stream_decode_bstr_header_offset_two_byte_length() {
    // bstr with 2-byte length: 0x59 0x01 0x00 → length 256
    let mut data = vec![0x59, 0x01, 0x00]; // header: 3 bytes
    data.extend(vec![0xAA; 256]); // content: 256 bytes
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(offset, 3); // 1 initial byte + 2 length bytes
    assert_eq!(len, 256);
}

// ─── decode_tstr_owned ───────────────────────────────────────────────────────

#[test]
fn stream_decode_tstr_empty() {
    let data = vec![0x60]; // tstr(0)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_tstr_owned().unwrap(), "");
}

#[test]
fn stream_decode_tstr_hello() {
    let data = vec![0x65, b'h', b'e', b'l', b'l', b'o'];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_tstr_owned().unwrap(), "hello");
}

#[test]
fn stream_decode_tstr_invalid_utf8() {
    let data = vec![0x62, 0xff, 0xfe]; // tstr(2) with invalid UTF-8
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.decode_tstr_owned().is_err());
}

// ─── decode_array_len / decode_map_len ───────────────────────────────────────

#[test]
fn stream_decode_array_len() {
    let data = vec![0x84, 0x01, 0x02, 0x03, 0x04]; // array(4)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_array_len().unwrap(), Some(4));
}

#[test]
fn stream_decode_map_len() {
    let data = vec![0xa2, 0x01, 0x02, 0x03, 0x04]; // map(2)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_map_len().unwrap(), Some(2));
}

#[test]
fn stream_decode_empty_map() {
    let data = vec![0xa0]; // map(0)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_map_len().unwrap(), Some(0));
}

// ─── decode_tag ──────────────────────────────────────────────────────────────

#[test]
fn stream_decode_tag_18() {
    let data = vec![0xd8, 0x12]; // tag(18)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_tag().unwrap(), 18);
}

#[test]
fn stream_decode_tag_small() {
    let data = vec![0xc1]; // tag(1)
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_tag().unwrap(), 1);
}

// ─── decode_bool / decode_null / is_null ─────────────────────────────────────

#[test]
fn stream_decode_bool_true() {
    let data = vec![0xf5]; // true
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.decode_bool().unwrap());
}

#[test]
fn stream_decode_bool_false() {
    let data = vec![0xf4]; // false
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(!dec.decode_bool().unwrap());
}

#[test]
fn stream_decode_null() {
    let data = vec![0xf6]; // null
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.decode_null().unwrap();
    assert_eq!(dec.position(), 1);
}

#[test]
fn stream_is_null_true() {
    let data = vec![0xf6]; // null
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.is_null().unwrap());
    // is_null should not consume the byte
    assert_eq!(dec.position(), 0);
}

#[test]
fn stream_is_null_false() {
    let data = vec![0x05]; // uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(!dec.is_null().unwrap());
}

// ─── skip ────────────────────────────────────────────────────────────────────

#[test]
fn stream_skip_integer() {
    let data = vec![0x18, 0x64, 0x05]; // uint 100, then uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.decode_u64().unwrap(), 5);
}

#[test]
fn stream_skip_bstr() {
    let data = vec![0x44, 0x01, 0x02, 0x03, 0x04, 0x05]; // bstr(4) then uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 5);
    assert_eq!(dec.decode_u64().unwrap(), 5);
}

#[test]
fn stream_skip_array() {
    // [1, 2, 3] then uint 42
    let data = vec![0x83, 0x01, 0x02, 0x03, 0x18, 0x2a];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.decode_u64().unwrap(), 42);
}

#[test]
fn stream_skip_nested_map() {
    // {1: {2: 3}} then uint 99
    let data = vec![0xa1, 0x01, 0xa1, 0x02, 0x03, 0x18, 0x63];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.decode_u64().unwrap(), 99);
}

#[test]
fn stream_skip_tag() {
    // tag(18) uint(5) then uint 42
    let data = vec![0xd8, 0x12, 0x05, 0x18, 0x2a];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.decode_u64().unwrap(), 42);
}

// ─── decode_raw_owned ────────────────────────────────────────────────────────

#[test]
fn stream_decode_raw_owned_integer() {
    let data = vec![0x18, 0x64, 0x05]; // uint 100, then uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let raw = dec.decode_raw_owned().unwrap();
    assert_eq!(raw, vec![0x18, 0x64]);
    assert_eq!(dec.decode_u64().unwrap(), 5);
}

#[test]
fn stream_decode_raw_owned_map() {
    // {1: -7} = a1 01 26
    let data = vec![0xa1, 0x01, 0x26, 0x05];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let raw = dec.decode_raw_owned().unwrap();
    assert_eq!(raw, vec![0xa1, 0x01, 0x26]);
    // Should be positioned at the next item
    assert_eq!(dec.decode_u64().unwrap(), 5);
}

// ─── skip_n_bytes ────────────────────────────────────────────────────────────

#[test]
fn stream_skip_n_bytes() {
    let data = vec![0x44, 0x01, 0x02, 0x03, 0x04, 0x05]; // bstr(4) then uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(offset, 1);
    assert_eq!(len, 4);
    dec.skip_n_bytes(len).unwrap();
    assert_eq!(dec.position(), 5);
    assert_eq!(dec.decode_u64().unwrap(), 5);
}

// ─── position tracking ──────────────────────────────────────────────────────

#[test]
fn stream_position_tracks_correctly() {
    // tag(18) array(4) bstr(3) content...
    let data = vec![
        0xd8, 0x12, // tag(18) → 2 bytes
        0x84, // array(4) → 1 byte
        0x43, 0xa1, 0x01, 0x26, // bstr(3) with {1:-7} → 4 bytes
    ];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.position(), 0);
    let _tag = dec.decode_tag().unwrap();
    assert_eq!(dec.position(), 2);
    let _len = dec.decode_array_len().unwrap();
    assert_eq!(dec.position(), 3);
    let _bstr = dec.decode_bstr_owned().unwrap();
    assert_eq!(dec.position(), 7);
}

// ─── error cases ─────────────────────────────────────────────────────────────

#[test]
fn stream_decode_u64_on_bstr_fails() {
    let data = vec![0x44, 0x01, 0x02, 0x03, 0x04]; // bstr, not uint
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.decode_u64().is_err());
}

#[test]
fn stream_decode_bstr_on_uint_fails() {
    let data = vec![0x05]; // uint 5, not bstr
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.decode_bstr_owned().is_err());
}

#[test]
fn stream_peek_on_empty_fails() {
    let data: Vec<u8> = vec![];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.peek_type().is_err());
}

#[test]
fn stream_decode_null_on_non_null_fails() {
    let data = vec![0x05]; // uint 5
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.decode_null().is_err());
}

// ─── Full COSE_Sign1 round-trip via stream decoder ───────────────────────────

#[test]
fn stream_decode_cose_sign1_structure() {
    // Build a COSE_Sign1 message: tag(18) [bstr(protected), {}, bstr(payload), bstr(sig)]
    use cbor_primitives::CborEncoder;
    use cbor_primitives_everparse::EverParseEncoder;

    let mut enc = EverParseEncoder::new();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    // Protected header: {1: -7}
    let protected = vec![0xa1, 0x01, 0x26];
    enc.encode_bstr(&protected).unwrap();
    // Unprotected header: empty map
    enc.encode_map(0).unwrap();
    // Payload: "hello"
    enc.encode_bstr(b"hello").unwrap();
    // Signature: 32 bytes of 0xAA
    enc.encode_bstr(&[0xAA; 32]).unwrap();
    let message_bytes = enc.into_bytes();

    // Parse using stream decoder
    let mut dec = EverparseStreamDecoder::new(Cursor::new(message_bytes));

    // Tag
    assert_eq!(dec.peek_type().unwrap(), CborType::Tag);
    assert_eq!(dec.decode_tag().unwrap(), 18);

    // Array(4)
    assert_eq!(dec.decode_array_len().unwrap(), Some(4));

    // Protected header bstr
    let prot = dec.decode_bstr_owned().unwrap();
    assert_eq!(prot, vec![0xa1, 0x01, 0x26]);

    // Unprotected map — use decode_raw_owned
    let unprotected_raw = dec.decode_raw_owned().unwrap();
    assert_eq!(unprotected_raw, vec![0xa0]); // empty map

    // Payload — get header offset only
    let (payload_offset, payload_len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(payload_len, 5);
    // Skip payload content
    dec.skip_n_bytes(payload_len).unwrap();

    // Verify we can read the payload by seeking back
    let reader = dec.reader_mut();
    use std::io::{Read, Seek, SeekFrom};
    reader.seek(SeekFrom::Start(payload_offset)).unwrap();
    let mut payload_buf = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload_buf).unwrap();
    assert_eq!(payload_buf, b"hello");

    // Seek forward to continue
    let current_pos = dec.position();
    dec.reader_mut().seek(SeekFrom::Start(current_pos)).unwrap();

    // Signature bstr
    let sig = dec.decode_bstr_owned().unwrap();
    assert_eq!(sig, vec![0xAA; 32]);
}
