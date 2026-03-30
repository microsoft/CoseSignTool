// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for the EverParse stream decoder targeting uncovered paths:
//! large bstr headers, indefinite-length containers, nested structures,
//! simple values, and decode_raw_owned for complex items.

use std::io::Cursor;

use cbor_primitives::CborStreamDecoder;
use cbor_primitives_everparse::EverparseStreamDecoder;

// ============================================================================
// decode_bstr_header_offset with various bstr sizes
// ============================================================================

#[test]
fn bstr_header_1byte_length() {
    // bstr with 1-byte length (24..255): 0x58 <len>
    let payload = vec![0xAB; 30];
    let mut data = vec![0x58, 30]; // bstr(30)
    data.extend_from_slice(&payload);

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(len, 30);
    assert_eq!(offset, 2); // 1 byte initial + 1 byte length
}

#[test]
fn bstr_header_2byte_length() {
    // bstr with 2-byte length: 0x59 <u16>
    let payload_len: u16 = 300;
    let payload = vec![0xCC; payload_len as usize];
    let mut data = vec![0x59];
    data.extend_from_slice(&payload_len.to_be_bytes());
    data.extend_from_slice(&payload);

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(len, 300);
    assert_eq!(offset, 3); // 1 + 2
}

#[test]
fn bstr_header_4byte_length() {
    // bstr with 4-byte length: 0x5A <u32>
    let payload_len: u32 = 70_000;
    let payload = vec![0xDD; payload_len as usize];
    let mut data = vec![0x5A];
    data.extend_from_slice(&payload_len.to_be_bytes());
    data.extend_from_slice(&payload);

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(len, 70_000);
    assert_eq!(offset, 5); // 1 + 4
}

#[test]
fn bstr_header_inline_length() {
    // bstr with inline length (0..23): 0x40..0x57
    let payload = vec![0xEE; 5];
    let mut data = vec![0x45]; // bstr(5)
    data.extend_from_slice(&payload);

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(len, 5);
    assert_eq!(offset, 1); // just 1 byte initial
}

// ============================================================================
// Indefinite-length containers
// ============================================================================

#[test]
fn skip_indefinite_length_array() {
    // Indefinite array: 0x9F <items> 0xFF
    let mut data = vec![0x9F]; // indefinite array
    data.push(0x01); // uint 1
    data.push(0x02); // uint 2
    data.push(0x03); // uint 3
    data.push(0xFF); // break

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    // After skip, position should be past the entire array
    assert_eq!(dec.position(), 5);
}

#[test]
fn skip_indefinite_length_map() {
    // Indefinite map: 0xBF <key> <val> ... 0xFF
    let mut data = vec![0xBF]; // indefinite map
    data.push(0x01); // key: uint 1
    data.push(0x61); // val: tstr(1)
    data.push(b'a');
    data.push(0x02); // key: uint 2
    data.push(0x61); // val: tstr(1)
    data.push(b'b');
    data.push(0xFF); // break

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 8);
}

#[test]
fn skip_indefinite_length_bstr() {
    // Indefinite byte string: 0x5F <chunk1> <chunk2> 0xFF
    let mut data = vec![0x5F]; // indefinite bstr
    data.push(0x42); // bstr(2) chunk
    data.extend_from_slice(&[0x01, 0x02]);
    data.push(0x41); // bstr(1) chunk
    data.push(0x03);
    data.push(0xFF); // break

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 7);
}

#[test]
fn skip_indefinite_length_tstr() {
    // Indefinite text string: 0x7F <chunk1> <chunk2> 0xFF
    let mut data = vec![0x7F]; // indefinite tstr
    data.push(0x63); // tstr(3)
    data.extend_from_slice(b"abc");
    data.push(0x62); // tstr(2)
    data.extend_from_slice(b"de");
    data.push(0xFF); // break

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 9);
}

// ============================================================================
// Nested structures
// ============================================================================

#[test]
fn skip_nested_array_in_map() {
    // Map(1) { 1: [2, 3] }
    let data = vec![
        0xA1, // map(1)
        0x01, // key: uint 1
        0x82, // val: array(2)
        0x02, // uint 2
        0x03, // uint 3
    ];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 5);
}

#[test]
fn decode_raw_owned_map() {
    // Map(1) { 1: 2 }
    let data = vec![0xA1, 0x01, 0x02];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data.clone()));
    let raw = dec.decode_raw_owned().unwrap();
    assert_eq!(raw, data);
}

#[test]
fn decode_raw_owned_nested_array() {
    // Array(2) [ array(1)[1], 2 ]
    let data = vec![0x82, 0x81, 0x01, 0x02];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data.clone()));
    let raw = dec.decode_raw_owned().unwrap();
    assert_eq!(raw, data);
}

#[test]
fn decode_raw_owned_tag() {
    // Tag(18) uint(42)
    let data = vec![0xD8, 18, 0x18, 42];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data.clone()));
    let raw = dec.decode_raw_owned().unwrap();
    assert_eq!(raw, data);
}

// ============================================================================
// Simple values: bool, null, undefined
// ============================================================================

#[test]
fn skip_bool_values() {
    let data = vec![0xF4, 0xF5]; // false, true

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap(); // false
    assert_eq!(dec.position(), 1);
    dec.skip().unwrap(); // true
    assert_eq!(dec.position(), 2);
}

#[test]
fn skip_null_value() {
    let data = vec![0xF6]; // null

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 1);
}

#[test]
fn skip_undefined_value() {
    let data = vec![0xF7]; // undefined

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 1);
}

#[test]
fn skip_float16() {
    // Float16: 0xF9 + 2 bytes
    let data = vec![0xF9, 0x3C, 0x00]; // f16: 1.0

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 3);
}

#[test]
fn skip_float32() {
    // Float32: 0xFA + 4 bytes
    let data = vec![0xFA, 0x41, 0x20, 0x00, 0x00]; // f32: 10.0

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 5);
}

#[test]
fn skip_float64() {
    // Float64: 0xFB + 8 bytes
    let data = vec![0xFB, 0x40, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // f64: 10.0

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 9);
}

#[test]
fn skip_simple_value_1byte() {
    // Simple value with 1-byte payload: 0xF8 <val>
    let data = vec![0xF8, 255]; // simple(255)

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 2);
}

// ============================================================================
// Tags
// ============================================================================

#[test]
fn skip_tag_with_nested_content() {
    // Tag(1) bstr(3) [0x01, 0x02, 0x03]
    let data = vec![0xC1, 0x43, 0x01, 0x02, 0x03];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 5);
}

#[test]
fn decode_tag_18() {
    let data = vec![0xD8, 18, 0x00]; // Tag(18) uint(0)

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let tag = dec.decode_tag().unwrap();
    assert_eq!(tag, 18);
}

// ============================================================================
// peek_type doesn't consume
// ============================================================================

#[test]
fn peek_type_does_not_advance_position() {
    let data = vec![0x01, 0x02]; // uint 1, uint 2

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let pos_before = dec.position();
    let _typ = dec.peek_type().unwrap();
    assert_eq!(dec.position(), pos_before);

    // Can still decode the value
    let val = dec.decode_u64().unwrap();
    assert_eq!(val, 1);
}

#[test]
fn peek_type_multiple_times() {
    let data = vec![0x82, 0x01, 0x02]; // array(2) [1, 2]

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    // Peek multiple times — position stays at 0
    let t1 = dec.peek_type().unwrap();
    let t2 = dec.peek_type().unwrap();
    assert_eq!(t1, t2);
    assert_eq!(dec.position(), 0);
}

// ============================================================================
// Skip complex nested structures
// ============================================================================

#[test]
fn skip_complex_cose_like_structure() {
    // Simulates COSE_Sign1: Tag(18) Array(4) [bstr, map, bstr, bstr]
    let mut data = Vec::new();
    data.push(0xD8); // Tag
    data.push(18);
    data.push(0x84); // Array(4)
    data.push(0x43); // bstr(3)
    data.extend_from_slice(&[0x01, 0x02, 0x03]);
    data.push(0xA1); // map(1)
    data.push(0x01); // key: 1
    data.push(0x02); // value: 2
    data.push(0x44); // bstr(4)
    data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    data.push(0x42); // bstr(2)
    data.extend_from_slice(&[0xEE, 0xFF]);

    let total_len = data.len();
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position() as usize, total_len);
}

#[test]
fn skip_deeply_nested_array() {
    // [[[[1]]]]
    let data = vec![
        0x81, // array(1)
        0x81, // array(1)
        0x81, // array(1)
        0x81, // array(1)
        0x01, // uint 1
    ];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 5);
}

// ============================================================================
// skip_n_bytes
// ============================================================================

#[test]
fn skip_n_bytes_advances_position() {
    let data = vec![0x00; 100];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip_n_bytes(50).unwrap();
    assert_eq!(dec.position(), 50);
    dec.skip_n_bytes(30).unwrap();
    assert_eq!(dec.position(), 80);
}

// ============================================================================
// Negative integer decoding
// ============================================================================

#[test]
fn skip_negative_int() {
    // Negative int -1: 0x20
    let data = vec![0x20];

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 1);
}

#[test]
fn skip_negative_int_1byte_arg() {
    // Negative int with 1-byte argument: 0x38 <val> → -(val+1)
    let data = vec![0x38, 100]; // -101

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    dec.skip().unwrap();
    assert_eq!(dec.position(), 2);
}

// ============================================================================
// reader_mut access
// ============================================================================

#[test]
fn reader_mut_accessible() {
    let data = vec![0x01, 0x02, 0x03];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let _reader = dec.reader_mut();
    // Just verify we can access it without panic
}

// ============================================================================
// into_inner recovers reader
// ============================================================================

#[test]
fn into_inner_returns_original_reader() {
    let original = vec![0x01, 0x02, 0x03];
    let dec = EverparseStreamDecoder::new(Cursor::new(original.clone()));
    let cursor = dec.into_inner();
    assert_eq!(cursor.into_inner(), original);
}

// ============================================================================
// Error cases
// ============================================================================

#[test]
fn decode_bstr_header_offset_on_non_bstr_fails() {
    let data = vec![0x01]; // uint, not bstr

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_bstr_header_offset();
    assert!(result.is_err());
}

#[test]
fn decode_bstr_header_offset_indefinite_fails() {
    let data = vec![0x5F]; // indefinite bstr

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_bstr_header_offset();
    assert!(result.is_err());
}

#[test]
fn decode_tag_on_non_tag_fails() {
    let data = vec![0x01]; // uint, not tag

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_tag();
    assert!(result.is_err());
}

#[test]
fn decode_bool_on_non_bool_fails() {
    let data = vec![0x01]; // uint, not bool

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_bool();
    assert!(result.is_err());
}

#[test]
fn decode_null_on_non_null_fails() {
    let data = vec![0x01]; // uint, not null

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_null();
    assert!(result.is_err());
}

#[test]
fn decode_array_len_on_non_array_fails() {
    let data = vec![0x01]; // uint, not array

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_array_len();
    assert!(result.is_err());
}

#[test]
fn decode_map_len_on_non_map_fails() {
    let data = vec![0x01]; // uint, not map

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_map_len();
    assert!(result.is_err());
}

#[test]
fn decode_i64_negative_values() {
    // -1 = 0x20
    let data = vec![0x20];
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.decode_i64().unwrap(), -1);

    // -100 = 0x38, 99
    let data2 = vec![0x38, 99];
    let mut dec2 = EverparseStreamDecoder::new(Cursor::new(data2));
    assert_eq!(dec2.decode_i64().unwrap(), -100);
}

#[test]
fn decode_indefinite_array_len() {
    let data = vec![0x9F]; // indefinite array
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let len = dec.decode_array_len().unwrap();
    assert_eq!(len, None);
}

#[test]
fn decode_indefinite_map_len() {
    let data = vec![0xBF]; // indefinite map
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let len = dec.decode_map_len().unwrap();
    assert_eq!(len, None);
}

#[test]
fn is_null_true() {
    let data = vec![0xF6]; // null
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(dec.is_null().unwrap());
}

#[test]
fn is_null_false() {
    let data = vec![0x01]; // uint 1
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert!(!dec.is_null().unwrap());
}

#[test]
fn decode_tstr_owned_success() {
    // tstr(5) "hello"
    let mut data = vec![0x65];
    data.extend_from_slice(b"hello");
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let s = dec.decode_tstr_owned().unwrap();
    assert_eq!(s, "hello");
}

#[test]
fn decode_tstr_on_non_tstr_fails() {
    let data = vec![0x01]; // uint
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_tstr_owned();
    assert!(result.is_err());
}

#[test]
fn decode_tstr_indefinite_fails() {
    let data = vec![0x7F]; // indefinite tstr
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_tstr_owned();
    assert!(result.is_err());
}

#[test]
fn decode_bstr_indefinite_fails() {
    let data = vec![0x5F]; // indefinite bstr
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_bstr_owned();
    assert!(result.is_err());
}

#[test]
fn decode_u64_on_non_uint_fails() {
    let data = vec![0x20]; // negative int
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_u64();
    assert!(result.is_err());
}

#[test]
fn decode_i64_on_non_int_fails() {
    let data = vec![0x40]; // bstr
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let result = dec.decode_i64();
    assert!(result.is_err());
}

#[test]
fn position_starts_at_zero() {
    let data = vec![0x01];
    let dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.position(), 0);
}

#[test]
fn position_after_decode() {
    let data = vec![0x01, 0x02]; // uint 1, uint 2
    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    assert_eq!(dec.position(), 0);
    dec.decode_u64().unwrap();
    assert_eq!(dec.position(), 1);
    dec.decode_u64().unwrap();
    assert_eq!(dec.position(), 2);
}

#[test]
fn skip_8byte_length_bstr() {
    // bstr with 8-byte length header: 0x5B <u64>
    // We can't actually create a 4GB+ bstr, but we can test the header parsing
    // by making a small one with 8-byte length
    let payload_len: u64 = 10;
    let payload = vec![0xAA; payload_len as usize];
    let mut data = vec![0x5B]; // bstr with 8-byte length
    data.extend_from_slice(&payload_len.to_be_bytes());
    data.extend_from_slice(&payload);

    let mut dec = EverparseStreamDecoder::new(Cursor::new(data));
    let (offset, len) = dec.decode_bstr_header_offset().unwrap();
    assert_eq!(len, 10);
    assert_eq!(offset, 9); // 1 + 8
}
