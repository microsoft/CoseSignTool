// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for EverParse CBOR decoder.

use cbor_primitives::{CborDecoder, CborEncoder, CborSimple, CborType};
use cbor_primitives_everparse::{EverparseCborDecoder, EverparseCborEncoder};

// ─── peek_type ───────────────────────────────────────────────────────────────

#[test]
fn peek_type_unsigned_int() {
    let data = [0x05]; // uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::UnsignedInt);
}

#[test]
fn peek_type_negative_int() {
    let data = [0x20]; // nint -1
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::NegativeInt);
}

#[test]
fn peek_type_byte_string() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::ByteString);
}

#[test]
fn peek_type_text_string() {
    let data = [0x63, b'a', b'b', b'c']; // tstr "abc"
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::TextString);
}

#[test]
fn peek_type_array() {
    let data = [0x82, 0x01, 0x02]; // [1, 2]
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Array);
}

#[test]
fn peek_type_map() {
    let data = [0xa1, 0x01, 0x02]; // {1: 2}
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Map);
}

#[test]
fn peek_type_tag() {
    let data = [0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0]; // tag(1) uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Tag);
}

#[test]
fn peek_type_bool_false() {
    let data = [0xf4]; // false
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Bool);
}

#[test]
fn peek_type_bool_true() {
    let data = [0xf5]; // true
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Bool);
}

#[test]
fn peek_type_null() {
    let data = [0xf6]; // null
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Null);
}

#[test]
fn peek_type_undefined() {
    let data = [0xf7]; // undefined
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Undefined);
}

#[test]
fn peek_type_float16() {
    let data = [0xf9, 0x3c, 0x00]; // f16 1.0
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Float16);
}

#[test]
fn peek_type_float32() {
    let data = [0xfa, 0x47, 0xc3, 0x50, 0x00]; // f32
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Float32);
}

#[test]
fn peek_type_float64() {
    let mut buf = vec![0xfb];
    buf.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
    let mut dec = EverparseCborDecoder::new(&buf);
    assert_eq!(dec.peek_type().unwrap(), CborType::Float64);
}

#[test]
fn peek_type_break() {
    let data = [0xff]; // break
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Break);
}

#[test]
fn peek_type_simple_low() {
    let data = [0xe0]; // simple(0)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Simple);
}

#[test]
fn peek_type_simple_one_byte() {
    let data = [0xf8, 0xff]; // simple(255)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Simple);
}

#[test]
fn peek_type_empty_returns_eof() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.peek_type().is_err());
}

// ─── is_break / is_null / is_undefined ───────────────────────────────────────

#[test]
fn is_break_on_break_code() {
    let data = [0xff];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.is_break().unwrap());
}

#[test]
fn is_break_on_non_break() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(!dec.is_break().unwrap());
}

#[test]
fn is_null_on_null() {
    let data = [0xf6];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.is_null().unwrap());
}

#[test]
fn is_null_on_non_null() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(!dec.is_null().unwrap());
}

#[test]
fn is_undefined_on_undefined() {
    let data = [0xf7];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.is_undefined().unwrap());
}

#[test]
fn is_undefined_on_non_undefined() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(!dec.is_undefined().unwrap());
}

// ─── Unsigned integers ──────────────────────────────────────────────────────

#[test]
fn decode_u8_small() {
    let data = [0x05]; // 5
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_u8_one_byte() {
    let data = [0x18, 0xff]; // 255
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_u8().unwrap(), 255);
}

#[test]
fn decode_u16_value() {
    let data = [0x19, 0x01, 0x00]; // 256
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_u16().unwrap(), 256);
}

#[test]
fn decode_u32_value() {
    let data = [0x1a, 0x00, 0x01, 0x00, 0x00]; // 65536
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_u32().unwrap(), 65536);
}

#[test]
fn decode_u64_value() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // 2^32
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_u64().unwrap(), 4294967296);
}

#[test]
fn decode_u8_overflow() {
    let data = [0x19, 0x01, 0x00]; // 256, too big for u8
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_u8().is_err());
}

#[test]
fn decode_u16_overflow() {
    let data = [0x1a, 0x00, 0x01, 0x00, 0x00]; // 65536, too big for u16
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_u16().is_err());
}

#[test]
fn decode_u32_overflow() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // 2^32, too big for u32
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_u32().is_err());
}

// ─── Negative / signed integers ─────────────────────────────────────────────

#[test]
fn decode_i8_positive() {
    let data = [0x05]; // 5
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i8().unwrap(), 5);
}

#[test]
fn decode_i8_negative() {
    let data = [0x20]; // -1
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i8().unwrap(), -1);
}

#[test]
fn decode_i16_value() {
    let data = [0x39, 0x01, 0x00]; // -257
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i16().unwrap(), -257);
}

#[test]
fn decode_i32_value() {
    let data = [0x3a, 0x00, 0x01, 0x00, 0x00]; // -65537
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i32().unwrap(), -65537);
}

#[test]
fn decode_i64_positive_large() {
    let data = [0x1a, 0x00, 0x0f, 0x42, 0x40]; // 1000000
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i64().unwrap(), 1000000);
}

#[test]
fn decode_i64_negative_large() {
    let data = [0x3a, 0x00, 0x0f, 0x42, 0x3f]; // -1000000
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i64().unwrap(), -1000000);
}

#[test]
fn decode_i128_positive() {
    let data = [0x05]; // 5
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i128().unwrap(), 5i128);
}

#[test]
fn decode_i128_negative() {
    let data = [0x38, 0x63]; // -100
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i128().unwrap(), -100i128);
}

#[test]
fn decode_i128_type_error() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr, not int
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i128().is_err());
}

#[test]
fn decode_i8_overflow() {
    let data = [0x19, 0x01, 0x00]; // 256, too big for i8
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i8().is_err());
}

#[test]
fn decode_i16_overflow() {
    let data = [0x1a, 0x00, 0x01, 0x00, 0x00]; // 65536, too big for i16
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i16().is_err());
}

#[test]
fn decode_i32_overflow() {
    let data = [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]; // 2^32
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i32().is_err());
}

#[test]
fn decode_i64_positive_overflow() {
    // u64 value > i64::MAX
    let data = [0x1b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // 2^63
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i64().is_err());
}

#[test]
fn decode_i64_negative_overflow() {
    // neg int with value > i64::MAX
    let data = [0x3b, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i64().is_err());
}

#[test]
fn decode_u64_wrong_type() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr, not uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_u64().is_err());
}

#[test]
fn decode_i64_wrong_type() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr, not int
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_i64().is_err());
}

// ─── Byte strings ───────────────────────────────────────────────────────────

#[test]
fn decode_bstr_empty() {
    let data = [0x40]; // bstr(0)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_bstr().unwrap(), b"");
}

#[test]
fn decode_bstr_data() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4) with payload
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_bstr().unwrap(), &[0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_bstr_wrong_type() {
    let data = [0x01]; // uint, not bstr
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_bstr().is_err());
}

#[test]
fn decode_bstr_header_definite() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4)
    let mut dec = EverparseCborDecoder::new(&data);
    let len = dec.decode_bstr_header().unwrap();
    assert_eq!(len, Some(4));
}

#[test]
fn decode_bstr_header_indefinite() {
    // bstr indefinite: 0x5f chunks... 0xff
    let data = [0x5f, 0x42, 0x01, 0x02, 0xff];
    let mut dec = EverparseCborDecoder::new(&data);
    let len = dec.decode_bstr_header().unwrap();
    assert_eq!(len, None);
}

#[test]
fn decode_bstr_header_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_bstr_header().is_err());
}

#[test]
fn decode_bstr_header_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_bstr_header().is_err());
}

// ─── Text strings ───────────────────────────────────────────────────────────

#[test]
fn decode_tstr_empty() {
    let data = [0x60]; // tstr(0) ""
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_tstr().unwrap(), "");
}

#[test]
fn decode_tstr_data() {
    let data = [0x63, b'a', b'b', b'c']; // tstr "abc"
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_tstr().unwrap(), "abc");
}

#[test]
fn decode_tstr_wrong_type() {
    let data = [0x01]; // uint, not tstr
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_tstr().is_err());
}

#[test]
fn decode_tstr_header_definite() {
    let data = [0x63, b'a', b'b', b'c']; // tstr(3)
    let mut dec = EverparseCborDecoder::new(&data);
    let len = dec.decode_tstr_header().unwrap();
    assert_eq!(len, Some(3));
}

#[test]
fn decode_tstr_header_indefinite() {
    let data = [0x7f, 0x61, b'a', 0xff]; // tstr indefinite
    let mut dec = EverparseCborDecoder::new(&data);
    let len = dec.decode_tstr_header().unwrap();
    assert_eq!(len, None);
}

#[test]
fn decode_tstr_header_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_tstr_header().is_err());
}

#[test]
fn decode_tstr_header_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_tstr_header().is_err());
}

// ─── Arrays ─────────────────────────────────────────────────────────────────

#[test]
fn decode_array_len_definite() {
    let data = [0x82, 0x01, 0x02]; // [1, 2]
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_array_len().unwrap(), Some(2));
}

#[test]
fn decode_array_len_indefinite() {
    let data = [0x9f, 0x01, 0x02, 0xff]; // [_ 1, 2]
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_array_len().unwrap(), None);
}

#[test]
fn decode_array_len_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_array_len().is_err());
}

#[test]
fn decode_array_len_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_array_len().is_err());
}

// ─── Maps ───────────────────────────────────────────────────────────────────

#[test]
fn decode_map_len_definite() {
    let data = [0xa1, 0x01, 0x02]; // {1: 2}
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_map_len().unwrap(), Some(1));
}

#[test]
fn decode_map_len_indefinite() {
    let data = [0xbf, 0x01, 0x02, 0xff]; // {_ 1: 2}
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_map_len().unwrap(), None);
}

#[test]
fn decode_map_len_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_map_len().is_err());
}

#[test]
fn decode_map_len_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_map_len().is_err());
}

// ─── Tags ───────────────────────────────────────────────────────────────────

#[test]
fn decode_tag_value() {
    let data = [0xc1, 0x1a, 0x51, 0x4b, 0x67, 0xb0]; // tag(1) uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_tag().unwrap(), 1);
}

#[test]
fn decode_tag_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_tag().is_err());
}

#[test]
fn decode_tag_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_tag().is_err());
}

// ─── Bool / Null / Undefined / Simple ───────────────────────────────────────

#[test]
fn decode_bool_false() {
    let data = [0xf4];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(!dec.decode_bool().unwrap());
}

#[test]
fn decode_bool_true() {
    let data = [0xf5];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_bool().unwrap());
}

#[test]
fn decode_bool_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_bool().is_err());
}

#[test]
fn decode_null_ok() {
    let data = [0xf6];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_null().is_ok());
}

#[test]
fn decode_null_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_null().is_err());
}

#[test]
fn decode_undefined_ok() {
    let data = [0xf7];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_undefined().is_ok());
}

#[test]
fn decode_undefined_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_undefined().is_err());
}

#[test]
fn decode_simple_false() {
    let data = [0xf4];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::False);
}

#[test]
fn decode_simple_true() {
    let data = [0xf5];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::True);
}

#[test]
fn decode_simple_null() {
    let data = [0xf6];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Null);
}

#[test]
fn decode_simple_undefined() {
    let data = [0xf7];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Undefined);
}

#[test]
fn decode_simple_unassigned() {
    // simple(16) = 0xe0 | 16 = 0xf0
    let data = [0xf0]; // simple(16)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Unassigned(16));
}

#[test]
fn decode_simple_one_byte_arg() {
    // simple(255) = 0xf8, 0xff
    let data = [0xf8, 0xff];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Unassigned(255));
}

#[test]
fn decode_simple_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_simple().is_err());
}

// ─── Floats ─────────────────────────────────────────────────────────────────

#[test]
fn decode_f16_one_point_zero() {
    let data = [0xf9, 0x3c, 0x00]; // f16 1.0
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert!((val - 1.0f32).abs() < f32::EPSILON);
}

#[test]
fn decode_f16_zero() {
    let data = [0xf9, 0x00, 0x00]; // f16 +0.0
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert_eq!(val, 0.0f32);
}

#[test]
fn decode_f16_negative_zero() {
    let data = [0xf9, 0x80, 0x00]; // f16 -0.0
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert!(val.is_sign_negative());
    assert_eq!(val, 0.0f32);
}

#[test]
fn decode_f16_infinity() {
    let data = [0xf9, 0x7c, 0x00]; // f16 +Inf
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert!(val.is_infinite() && val.is_sign_positive());
}

#[test]
fn decode_f16_nan() {
    let data = [0xf9, 0x7e, 0x00]; // f16 NaN
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert!(val.is_nan());
}

#[test]
fn decode_f16_subnormal() {
    // Smallest positive subnormal f16: 0x0001 = 5.960464e-8
    let data = [0xf9, 0x00, 0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f16().unwrap();
    assert!(val > 0.0 && val < 0.001);
}

#[test]
fn decode_f16_wrong_type() {
    let data = [0x01]; // uint
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f16().is_err());
}

#[test]
fn decode_f16_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_f16().is_err());
}

#[test]
fn decode_f16_truncated() {
    let data = [0xf9, 0x3c]; // missing second byte
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f16().is_err());
}

#[test]
fn decode_f32_value() {
    let data = [0xfa, 0x47, 0xc3, 0x50, 0x00]; // f32 100000.0
    let mut dec = EverparseCborDecoder::new(&data);
    let val = dec.decode_f32().unwrap();
    assert!((val - 100000.0f32).abs() < 1.0);
}

#[test]
fn decode_f32_wrong_type() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f32().is_err());
}

#[test]
fn decode_f32_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_f32().is_err());
}

#[test]
fn decode_f32_truncated() {
    let data = [0xfa, 0x47, 0xc3]; // missing bytes
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f32().is_err());
}

#[test]
fn decode_f64_value() {
    let mut buf = vec![0xfb];
    buf.extend_from_slice(&3.14f64.to_bits().to_be_bytes());
    let mut dec = EverparseCborDecoder::new(&buf);
    let val = dec.decode_f64().unwrap();
    assert!((val - 3.14f64).abs() < f64::EPSILON);
}

#[test]
fn decode_f64_wrong_type() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f64().is_err());
}

#[test]
fn decode_f64_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_f64().is_err());
}

#[test]
fn decode_f64_truncated() {
    let data = [0xfb, 0x40, 0x09]; // missing bytes
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_f64().is_err());
}

// ─── Break ──────────────────────────────────────────────────────────────────

#[test]
fn decode_break_ok() {
    let data = [0xff];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_break().is_ok());
}

#[test]
fn decode_break_wrong_type() {
    let data = [0x01];
    let mut dec = EverparseCborDecoder::new(&data);
    assert!(dec.decode_break().is_err());
}

#[test]
fn decode_break_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_break().is_err());
}

// ─── skip (and decode_raw) ──────────────────────────────────────────────────

#[test]
fn skip_uint() {
    let data = [0x18, 0x64, 0x05]; // 100 followed by 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_bstr() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04, 0x05]; // bstr(4) then uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_array() {
    let data = [0x82, 0x01, 0x02, 0x05]; // [1,2] then uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_map() {
    let data = [0xa1, 0x01, 0x02, 0x05]; // {1:2} then uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_float32() {
    // f32 followed by uint 5
    let buf = vec![0xfa, 0x41, 0x20, 0x00, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&buf);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_float64() {
    let mut buf = vec![0xfb];
    buf.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
    buf.push(0x05);
    let mut dec = EverparseCborDecoder::new(&buf);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_float16() {
    let buf = vec![0xf9, 0x3c, 0x00, 0x05]; // f16 1.0 then uint 5
    let mut dec = EverparseCborDecoder::new(&buf);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_tagged_item() {
    // tag(1) followed by uint(42), then uint 5
    let data = [0xc1, 0x18, 0x2a, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_bool() {
    let data = [0xf5, 0x05]; // true then uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_null() {
    let data = [0xf6, 0x05]; // null then uint 5
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_uint() {
    let data = [0x18, 0x64]; // uint 100
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0x18, 0x64]);
}

#[test]
fn decode_raw_bstr() {
    let data = [0x44, 0x01, 0x02, 0x03, 0x04]; // bstr(4)
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0x44, 0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn decode_raw_float32() {
    let data = [0xfa, 0x41, 0x20, 0x00, 0x00]; // f32
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0xfa, 0x41, 0x20, 0x00, 0x00]);
}

// ─── skip_raw_item with non-deterministic CBOR (unsorted maps) ──────────────

#[test]
fn skip_unsorted_map() {
    // Map with keys in reverse order: {2:0, 1:0} -- non-deterministic
    // a2 02 00 01 00 followed by uint 5
    let data = [0xa2, 0x02, 0x00, 0x01, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_nested_unsorted_map() {
    // Map {2: {4:0, 3:0}, 1: 0} -- deeply non-deterministic
    // a2 02 a2 04 00 03 00 01 00 followed by uint 5
    let data = [0xa2, 0x02, 0xa2, 0x04, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_unsorted_map() {
    // Map with keys in reverse order: {2:0, 1:0}
    let data = [0xa2, 0x02, 0x00, 0x01, 0x00];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0xa2, 0x02, 0x00, 0x01, 0x00]);
}

// ─── remaining / position ───────────────────────────────────────────────────

#[test]
fn remaining_and_position() {
    let data = [0x01, 0x02, 0x03]; // three uint values
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.position(), 0);
    assert_eq!(dec.remaining().len(), 3);

    dec.decode_u8().unwrap();
    assert_eq!(dec.position(), 1);
    assert_eq!(dec.remaining().len(), 2);
}

// ─── Encode-then-decode roundtrips ──────────────────────────────────────────

#[test]
fn roundtrip_integers() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(0).unwrap();
    enc.encode_u8(23).unwrap();
    enc.encode_u8(24).unwrap();
    enc.encode_u8(255).unwrap();
    enc.encode_u16(256).unwrap();
    enc.encode_u32(65536).unwrap();
    enc.encode_i64(-1).unwrap();
    enc.encode_i64(-100).unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_u8().unwrap(), 0);
    assert_eq!(dec.decode_u8().unwrap(), 23);
    assert_eq!(dec.decode_u8().unwrap(), 24);
    assert_eq!(dec.decode_u8().unwrap(), 255);
    assert_eq!(dec.decode_u16().unwrap(), 256);
    assert_eq!(dec.decode_u32().unwrap(), 65536);
    assert_eq!(dec.decode_i64().unwrap(), -1);
    assert_eq!(dec.decode_i64().unwrap(), -100);
}

#[test]
fn roundtrip_strings() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bstr(b"hello").unwrap();
    enc.encode_tstr("world").unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_bstr().unwrap(), b"hello");
    assert_eq!(dec.decode_tstr().unwrap(), "world");
}

#[test]
fn roundtrip_bool_null_undefined() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bool(true).unwrap();
    enc.encode_bool(false).unwrap();
    enc.encode_null().unwrap();
    enc.encode_undefined().unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert!(dec.decode_bool().unwrap());
    assert!(!dec.decode_bool().unwrap());
    dec.decode_null().unwrap();
    dec.decode_undefined().unwrap();
}

#[test]
fn roundtrip_array_and_map() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array(2).unwrap();
    enc.encode_u8(1).unwrap();
    enc.encode_u8(2).unwrap();
    enc.encode_map(1).unwrap();
    enc.encode_tstr("key").unwrap();
    enc.encode_tstr("val").unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_array_len().unwrap(), Some(2));
    assert_eq!(dec.decode_u8().unwrap(), 1);
    assert_eq!(dec.decode_u8().unwrap(), 2);
    assert_eq!(dec.decode_map_len().unwrap(), Some(1));
    assert_eq!(dec.decode_tstr().unwrap(), "key");
    assert_eq!(dec.decode_tstr().unwrap(), "val");
}

#[test]
fn roundtrip_tag() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tag(1).unwrap();
    enc.encode_u64(1363896240).unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_tag().unwrap(), 1);
    assert_eq!(dec.decode_u64().unwrap(), 1363896240);
}

#[test]
fn roundtrip_simple_values() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::False).unwrap();
    enc.encode_simple(CborSimple::True).unwrap();
    enc.encode_simple(CborSimple::Null).unwrap();
    enc.encode_simple(CborSimple::Undefined).unwrap();
    enc.encode_simple(CborSimple::Unassigned(16)).unwrap();
    enc.encode_simple(CborSimple::Unassigned(255)).unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::False);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::True);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Null);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Undefined);
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Unassigned(16));
    assert_eq!(dec.decode_simple().unwrap(), CborSimple::Unassigned(255));
}

// ─── skip on empty input ────────────────────────────────────────────────────

#[test]
fn skip_empty_input() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.skip().is_err());
}

#[test]
fn decode_raw_empty() {
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    assert!(dec.decode_raw().is_err());
}

// ─── Multiple sequential items ──────────────────────────────────────────────

#[test]
fn decode_sequence_of_items() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(42).unwrap();
    enc.encode_tstr("hello").unwrap();
    enc.encode_bstr(b"\x01\x02").unwrap();
    enc.encode_bool(true).unwrap();
    enc.encode_null().unwrap();
    let bytes = enc.into_bytes();

    let mut dec = EverparseCborDecoder::new(&bytes);
    assert_eq!(dec.decode_u8().unwrap(), 42);
    assert_eq!(dec.decode_tstr().unwrap(), "hello");
    assert_eq!(dec.decode_bstr().unwrap(), &[0x01, 0x02]);
    assert!(dec.decode_bool().unwrap());
    dec.decode_null().unwrap();
    assert!(dec.remaining().is_empty());
}

// ─── make_parse_error tests ──────────────────────────────────────────────────
// These trigger make_parse_error by attempting to decode data that cbor_det_parse
// rejects (floats, indefinite-length, non-deterministic CBOR).

#[test]
fn make_parse_error_float16() {
    // f16 value: 0xf9 followed by 2 bytes
    let data = [0xf9, 0x3c, 0x00]; // f16: 1.0
    let mut dec = EverparseCborDecoder::new(&data);
    // peek_type works (reads major type 7 + additional info 25)
    assert_eq!(dec.peek_type().unwrap(), CborType::Float16);
    // decode_f16 should work (implemented separately from EverParse)
    let val = dec.decode_f16().unwrap();
    assert!((val - 1.0).abs() < 0.001);
}

#[test]
fn make_parse_error_float32() {
    // f32 value: 0xfa followed by 4 bytes (3.14)
    let data = [0xfa, 0x40, 0x48, 0xf5, 0xc3]; // f32: ~3.14
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Float32);
    let val = dec.decode_f32().unwrap();
    assert!((val - 3.14).abs() < 0.01);
}

#[test]
fn make_parse_error_float64() {
    // f64 value: 0xfb followed by 8 bytes
    let data = [0xfb, 0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18]; // pi
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Float64);
    let val = dec.decode_f64().unwrap();
    assert!((val - std::f64::consts::PI).abs() < 0.0001);
}

#[test]
fn make_parse_error_indefinite_bstr() {
    // Indefinite-length bstr: 0x5f [chunks...] 0xff
    // EverParse rejects this, but decode_bstr_header returns None
    let data = [0x5f, 0x41, 0xAA, 0xff]; // _bstr(h'AA', break)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::ByteString);
    let header = dec.decode_bstr_header().unwrap();
    assert!(header.is_none()); // indefinite
}

#[test]
fn make_parse_error_indefinite_tstr() {
    // Indefinite-length tstr: 0x7f [chunks...] 0xff
    let data = [0x7f, 0x61, 0x61, 0xff]; // _tstr("a", break)
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::TextString);
    let header = dec.decode_tstr_header().unwrap();
    assert!(header.is_none()); // indefinite
}

#[test]
fn make_parse_error_break_code() {
    // Break code: 0xff - EverParse rejects standalone break
    let data = [0xff];
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Break);
}

// ─── skip_raw_item: indefinite-length strings ────────────────────────────────

#[test]
fn skip_indefinite_bstr() {
    // _bstr(h'AA', h'BB', break), then uint 5
    let data = [0x5f, 0x41, 0xAA, 0x41, 0xBB, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_indefinite_tstr() {
    // _tstr("a", "b", break), then uint 5
    let data = [0x7f, 0x61, 0x61, 0x61, 0x62, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_indefinite_array() {
    // _array(1, 2, 3, break), then uint 5
    let data = [0x9f, 0x01, 0x02, 0x03, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_indefinite_map() {
    // _map(1:2, 3:4, break), then uint 5
    let data = [0xbf, 0x01, 0x02, 0x03, 0x04, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_definite_bstr() {
    // bstr(3) with content, then uint 5
    let data = [0x43, 0xAA, 0xBB, 0xCC, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_definite_tstr() {
    // tstr("abc"), then uint 5
    let data = [0x63, 0x61, 0x62, 0x63, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_float32_nondet() {
    // f32: 1.0 (0xfa 0x3f800000), then uint 5
    let data = [0xfa, 0x3f, 0x80, 0x00, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_float64_nondet() {
    // f64: 1.0 (0xfb + 8 bytes), then uint 5
    let data = [0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_simple_value_one_byte() {
    // Simple value 0..23: simple(10) = 0xea, then uint 5
    let data = [0xea, 0x05]; // simple(10)
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_simple_value_two_byte() {
    // Simple value 24: simple(32) = 0xf8 0x20, then uint 5
    let data = [0xf8, 0x20, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_break_code() {
    // break = 0xff (major 7, additional 31), skip should consume 1 byte
    let data = [0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn skip_invalid_additional_info() {
    // Major type 7 with invalid additional info (28..30 are reserved)
    let data = [0xfc]; // major 7, additional 28
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_truncated_float32() {
    // f32 needs 5 bytes but only 3 available
    let data = [0xfa, 0x3f, 0x80];
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_indefinite_bstr_eof() {
    // Indefinite bstr without break
    let data = [0x5f, 0x41, 0xAA];
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_indefinite_array_eof() {
    // Indefinite array without break
    let data = [0x9f, 0x01, 0x02];
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_indefinite_map_eof() {
    // Indefinite map without break
    let data = [0xbf, 0x01, 0x02];
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_definite_bstr_truncated() {
    // bstr(10) but only 3 bytes of content
    let data = [0x4a, 0x01, 0x02, 0x03];
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.skip();
    assert!(result.is_err());
}

#[test]
fn skip_tag_with_content() {
    // tag(1, uint 42): 0xc1 0x18 0x2a, then uint 5
    let data = [0xc1, 0x18, 0x2a, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    dec.skip().unwrap();
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_indefinite_array() {
    // Indefinite array: [_ 1, 2, break]
    let data = [0x9f, 0x01, 0x02, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0x9f, 0x01, 0x02, 0xff]);
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_indefinite_map() {
    // Indefinite map: {_ 1:2, break}
    let data = [0xbf, 0x01, 0x02, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0xbf, 0x01, 0x02, 0xff]);
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_indefinite_bstr() {
    // Indefinite bstr: _bstr(h'AA', break)
    let data = [0x5f, 0x41, 0xAA, 0xff, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0x5f, 0x41, 0xAA, 0xff]);
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_tag() {
    // tag(1, uint 42): 0xc1 0x18 0x2a, then uint 5
    let data = [0xc1, 0x18, 0x2a, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw, &[0xc1, 0x18, 0x2a]);
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

#[test]
fn decode_raw_float64() {
    // f64: 0xfb + 8 bytes, then uint 5
    let data = [0xfb, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05];
    let mut dec = EverparseCborDecoder::new(&data);
    let raw = dec.decode_raw().unwrap();
    assert_eq!(raw.len(), 9); // 1 + 8
    assert_eq!(dec.decode_u8().unwrap(), 5);
}

// ─── view_to_cbor_type (triggered by type-mismatch errors) ───────────────────

#[test]
fn decode_i64_on_bstr_gives_type_error() {
    // Attempt to decode a bstr as i64 → triggers view_to_cbor_type
    let data = [0x42, 0xAA, 0xBB]; // bstr(2)
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_i64();
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("ByteString") || err_msg.contains("type"));
}

#[test]
fn decode_u64_on_tstr_gives_type_error() {
    // Attempt to decode a tstr as u64 → triggers view_to_cbor_type
    let data = [0x63, 0x61, 0x62, 0x63]; // tstr("abc")
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_u64();
    assert!(result.is_err());
}

#[test]
fn decode_bstr_on_uint_gives_type_error() {
    // Attempt to decode uint as bstr → triggers view_to_cbor_type
    let data = [0x18, 0x2a]; // uint(42)
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_bstr();
    assert!(result.is_err());
}

#[test]
fn decode_tstr_on_array_gives_type_error() {
    let data = [0x82, 0x01, 0x02]; // array(2) [1, 2]
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_tstr();
    assert!(result.is_err());
}

#[test]
fn decode_bool_on_map_gives_type_error() {
    let data = [0xa1, 0x01, 0x02]; // map(1) {1: 2}
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_bool();
    assert!(result.is_err());
}

#[test]
fn decode_tag_on_null_gives_type_error() {
    let data = [0xf6]; // null
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_tag();
    assert!(result.is_err());
}

#[test]
fn decode_null_on_bool_gives_type_error() {
    let data = [0xf5]; // true
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_null();
    assert!(result.is_err());
}

#[test]
fn decode_undefined_on_int_gives_type_error() {
    let data = [0x05]; // uint(5)
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_undefined();
    assert!(result.is_err());
}

#[test]
fn decode_i64_on_tagged_gives_type_error() {
    let data = [0xc1, 0x18, 0x2a]; // tag(1, 42)
    let mut dec = EverparseCborDecoder::new(&data);
    let result = dec.decode_i64();
    assert!(result.is_err());
}

#[test]
fn decode_i64_on_negint_gives_correct_value() {
    // Negative int is valid for decode_i64
    let data = [0x38, 0x63]; // -100
    let mut dec = EverparseCborDecoder::new(&data);
    assert_eq!(dec.decode_i64().unwrap(), -100);
}