// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for RawCbor scalar decoding methods.

use cbor_primitives::RawCbor;

// ─── try_as_i64 ─────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_i64_small_uint() {
    let data = [0x05]; // uint 5
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(5));
}

#[test]
fn raw_cbor_try_as_i64_one_byte_uint() {
    let data = [0x18, 0x64]; // uint 100
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(100));
}

#[test]
fn raw_cbor_try_as_i64_two_byte_uint() {
    let data = [0x19, 0x01, 0x00]; // uint 256
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(256));
}

#[test]
fn raw_cbor_try_as_i64_four_byte_uint() {
    let data = [0x1a, 0x00, 0x01, 0x00, 0x00]; // uint 65536
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(65536));
}

#[test]
fn raw_cbor_try_as_i64_eight_byte_uint() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // uint 2^32
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(4294967296));
}

#[test]
fn raw_cbor_try_as_i64_negative() {
    let data = [0x20]; // nint -1
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(-1));
}

#[test]
fn raw_cbor_try_as_i64_negative_100() {
    let data = [0x38, 0x63]; // nint -100
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), Some(-100));
}

#[test]
fn raw_cbor_try_as_i64_large_negative() {
    // nint with value > i64::MAX → should return None
    let data = [0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), None);
}

#[test]
fn raw_cbor_try_as_i64_non_int() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_i64(), None);
}

#[test]
fn raw_cbor_try_as_i64_empty() {
    let data: &[u8] = &[];
    let raw = RawCbor::new(data);
    assert_eq!(raw.try_as_i64(), None);
}

// ─── try_as_u64 ─────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_u64_small() {
    let data = [0x05]; // uint 5
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), Some(5));
}

#[test]
fn raw_cbor_try_as_u64_one_byte() {
    let data = [0x18, 0xff]; // uint 255
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), Some(255));
}

#[test]
fn raw_cbor_try_as_u64_two_byte() {
    let data = [0x19, 0x01, 0x00]; // uint 256
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), Some(256));
}

#[test]
fn raw_cbor_try_as_u64_four_byte() {
    let data = [0x1a, 0x00, 0x01, 0x00, 0x00]; // uint 65536
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), Some(65536));
}

#[test]
fn raw_cbor_try_as_u64_eight_byte() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // uint 2^32
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), Some(4294967296));
}

#[test]
fn raw_cbor_try_as_u64_non_uint() {
    let data = [0x20]; // nint -1
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), None);
}

#[test]
fn raw_cbor_try_as_u64_empty() {
    let data: &[u8] = &[];
    let raw = RawCbor::new(data);
    assert_eq!(raw.try_as_u64(), None);
}

// ─── try_as_bool ────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_bool_false() {
    let data = [0xf4]; // false
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bool(), Some(false));
}

#[test]
fn raw_cbor_try_as_bool_true() {
    let data = [0xf5]; // true
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bool(), Some(true));
}

#[test]
fn raw_cbor_try_as_bool_not_bool() {
    let data = [0x01]; // uint 1
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bool(), None);
}

// ─── try_as_str ─────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_str_simple() {
    let data = [0x63, b'a', b'b', b'c']; // tstr "abc"
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_str(), Some("abc"));
}

#[test]
fn raw_cbor_try_as_str_empty() {
    let data = [0x60]; // tstr ""
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_str(), Some(""));
}

#[test]
fn raw_cbor_try_as_str_not_tstr() {
    let data = [0x01]; // uint 1
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_str(), None);
}

// ─── try_as_bstr ────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_bstr_simple() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4)
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bstr(), Some(&[0x01, 0x02, 0x03, 0x04][..]));
}

#[test]
fn raw_cbor_try_as_bstr_empty() {
    let data = [0x40]; // bstr(0)
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bstr(), Some(&[][..]));
}

#[test]
fn raw_cbor_try_as_bstr_not_bstr() {
    let data = [0x01]; // uint 1
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_bstr(), None);
}

// ─── major_type ─────────────────────────────────────────────────────────────

#[test]
fn raw_cbor_major_type_uint() {
    let raw = RawCbor::new(&[0x05]);
    assert_eq!(raw.major_type(), Some(0));
}

#[test]
fn raw_cbor_major_type_nint() {
    let raw = RawCbor::new(&[0x20]);
    assert_eq!(raw.major_type(), Some(1));
}

#[test]
fn raw_cbor_major_type_bstr() {
    let raw = RawCbor::new(&[0x44, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(raw.major_type(), Some(2));
}

#[test]
fn raw_cbor_major_type_tstr() {
    let raw = RawCbor::new(&[0x63, b'a', b'b', b'c']);
    assert_eq!(raw.major_type(), Some(3));
}

#[test]
fn raw_cbor_major_type_array() {
    let raw = RawCbor::new(&[0x82, 0x01, 0x02]);
    assert_eq!(raw.major_type(), Some(4));
}

#[test]
fn raw_cbor_major_type_map() {
    let raw = RawCbor::new(&[0xa1, 0x01, 0x02]);
    assert_eq!(raw.major_type(), Some(5));
}

#[test]
fn raw_cbor_major_type_tag() {
    let raw = RawCbor::new(&[0xc1, 0x01]);
    assert_eq!(raw.major_type(), Some(6));
}

#[test]
fn raw_cbor_major_type_simple() {
    let raw = RawCbor::new(&[0xf4]); // false
    assert_eq!(raw.major_type(), Some(7));
}

#[test]
fn raw_cbor_major_type_empty() {
    let raw = RawCbor::new(&[]);
    assert_eq!(raw.major_type(), None);
}

// ─── as_bytes / as_ref ──────────────────────────────────────────────────────

#[test]
fn raw_cbor_as_bytes() {
    let data = [0x01, 0x02, 0x03];
    let raw = RawCbor::new(&data);
    assert_eq!(raw.as_bytes(), &[0x01, 0x02, 0x03]);
}

#[test]
fn raw_cbor_as_ref() {
    let data = [0x01, 0x02];
    let raw = RawCbor::new(&data);
    let r: &[u8] = raw.as_ref();
    assert_eq!(r, &[0x01, 0x02]);
}

// ─── decode_uint_arg edge cases ─────────────────────────────────────────────

#[test]
fn raw_cbor_try_as_u64_truncated_two_byte() {
    let data = [0x19, 0x01]; // 2-byte arg but only 1 byte
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), None);
}

#[test]
fn raw_cbor_try_as_u64_truncated_four_byte() {
    let data = [0x1a, 0x00, 0x01]; // 4-byte arg but only 2 bytes
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), None);
}

#[test]
fn raw_cbor_try_as_u64_truncated_eight_byte() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01]; // 8-byte arg but only 4 bytes
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), None);
}

#[test]
fn raw_cbor_try_as_u64_invalid_additional() {
    // additional info 28 is reserved
    let data = [0x1c];
    let raw = RawCbor::new(&data);
    assert_eq!(raw.try_as_u64(), None);
}
