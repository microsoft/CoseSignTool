// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for RawCbor edge cases: integer overflow, invalid UTF-8,
//! truncated byte/text strings.

use cbor_primitives::RawCbor;

// ========== try_as_i64: unsigned int > i64::MAX ==========

#[test]
fn try_as_i64_unsigned_overflow() {
    // CBOR unsigned int = u64::MAX (0x1B FF FF FF FF FF FF FF FF)
    // This is > i64::MAX so try_from should return None.
    let bytes = [0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_i64().is_none());
}

#[test]
fn try_as_i64_unsigned_at_i64_max() {
    // CBOR unsigned int = i64::MAX (0x7FFFFFFFFFFFFFFF) => should succeed
    let val = i64::MAX as u64;
    let bytes = [
        0x1B,
        (val >> 56) as u8,
        (val >> 48) as u8,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ];
    let raw = RawCbor::new(&bytes);
    assert_eq!(raw.try_as_i64(), Some(i64::MAX));
}

#[test]
fn try_as_i64_unsigned_just_over_i64_max() {
    // CBOR unsigned int = i64::MAX + 1 => should be None
    let val = i64::MAX as u64 + 1;
    let bytes = [
        0x1B,
        (val >> 56) as u8,
        (val >> 48) as u8,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_i64().is_none());
}

// ========== try_as_str: truncated text ==========

#[test]
fn try_as_str_truncated() {
    // Text string claiming length 10 but only 3 bytes follow.
    // Major type 3, additional 10 → 0x6A, then only 3 bytes.
    let bytes = [0x6A, b'a', b'b', b'c'];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_str().is_none());
}

#[test]
fn try_as_str_invalid_utf8() {
    // Text string with 2 bytes that are not valid UTF-8.
    let bytes = [0x62, 0xFF, 0xFE]; // tstr(2) + invalid bytes
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_str().is_none());
}

// ========== try_as_bstr: truncated ==========

#[test]
fn try_as_bstr_truncated() {
    // Byte string claiming length 10 but only 2 bytes follow.
    // Major type 2, additional 10 → 0x4A, then only 2 bytes.
    let bytes = [0x4A, 0x01, 0x02];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_bstr().is_none());
}

// ========== try_as_i64: negative integer overflow ==========

#[test]
fn try_as_i64_negative_overflow() {
    // CBOR negative integer: -1 - u64::MAX overflows i64.
    // Major type 1, value = u64::MAX.
    // Encoded: 0x3B FF FF FF FF FF FF FF FF
    let bytes = [0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_i64().is_none());
}

#[test]
fn try_as_i64_negative_at_limit() {
    // Most negative i64: -1 - 0x7FFFFFFFFFFFFFFF = i64::MIN
    // val = 0x7FFFFFFFFFFFFFFF, result = -1 - val = -0x8000000000000000 = i64::MIN
    let val: u64 = i64::MAX as u64;
    let bytes = [
        0x3B,
        (val >> 56) as u8,
        (val >> 48) as u8,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ];
    let raw = RawCbor::new(&bytes);
    assert_eq!(raw.try_as_i64(), Some(i64::MIN));
}

#[test]
fn try_as_i64_negative_just_past_limit() {
    // val = i64::MAX + 1 = 0x8000000000000000 → overflow
    let val: u64 = i64::MAX as u64 + 1;
    let bytes = [
        0x3B,
        (val >> 56) as u8,
        (val >> 48) as u8,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ];
    let raw = RawCbor::new(&bytes);
    assert!(raw.try_as_i64().is_none());
}
