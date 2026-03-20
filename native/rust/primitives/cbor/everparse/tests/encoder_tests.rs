// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for EverParse CBOR encoders (EverparseCborEncoder and EverParseEncoder).

use cbor_primitives::{CborEncoder, CborSimple};
use cbor_primitives_everparse::{EverParseEncoder, EverparseCborEncoder};

// ─── EverparseCborEncoder (full encoder with floats) ────────────────────────

#[test]
fn encoder_default() {
    let enc = EverparseCborEncoder::default();
    assert!(enc.as_bytes().is_empty());
}

#[test]
fn encoder_with_capacity() {
    let enc = EverparseCborEncoder::with_capacity(100);
    assert!(enc.as_bytes().is_empty());
}

#[test]
fn encode_u8_small() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x05]);
}

#[test]
fn encode_u8_one_byte_arg() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(24).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 24]);
}

#[test]
fn encode_u8_max() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(255).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 0xff]);
}

#[test]
fn encode_u16_small() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u16(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x05]);
}

#[test]
fn encode_u16_two_byte() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u16(256).unwrap();
    assert_eq!(enc.as_bytes(), &[0x19, 0x01, 0x00]);
}

#[test]
fn encode_u32_small() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u32(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x05]);
}

#[test]
fn encode_u32_four_byte() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u32(65536).unwrap();
    assert_eq!(enc.as_bytes(), &[0x1a, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn encode_u64_small() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u64(0).unwrap();
    assert_eq!(enc.as_bytes(), &[0x00]);
}

#[test]
fn encode_u64_eight_byte() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u64(u64::MAX).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0x1b);
    assert_eq!(&bytes[1..], &u64::MAX.to_be_bytes());
}

#[test]
fn encode_i8_positive() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i8(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x05]);
}

#[test]
fn encode_i8_negative() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i8(-1).unwrap();
    assert_eq!(enc.as_bytes(), &[0x20]); // major 1, arg 0
}

#[test]
fn encode_i16_negative() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i16(-257).unwrap();
    assert_eq!(enc.as_bytes(), &[0x39, 0x01, 0x00]); // major 1, 2-byte arg 256
}

#[test]
fn encode_i32_negative() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i32(-65537).unwrap();
    assert_eq!(enc.as_bytes(), &[0x3a, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn encode_i64_positive() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i64(100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 0x64]);
}

#[test]
fn encode_i64_negative() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i64(-100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x38, 0x63]); // major 1, arg 99
}

#[test]
fn encode_i128_positive() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i128(100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 0x64]);
}

#[test]
fn encode_i128_negative() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_i128(-100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x38, 0x63]);
}

#[test]
fn encode_i128_positive_overflow() {
    let mut enc = EverparseCborEncoder::new();
    let result = enc.encode_i128((u64::MAX as i128) + 1);
    assert!(result.is_err());
}

#[test]
fn encode_i128_negative_overflow() {
    let mut enc = EverparseCborEncoder::new();
    let result = enc.encode_i128(-(u64::MAX as i128) - 2);
    assert!(result.is_err());
}

#[test]
fn encode_i128_negative_max() {
    // The largest negative CBOR can represent: -(2^64)
    let mut enc = EverparseCborEncoder::new();
    let result = enc.encode_i128(-(u64::MAX as i128) - 1);
    assert!(result.is_ok());
}

#[test]
fn encode_bstr() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bstr(b"hello").unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0x45); // major 2, len 5
    assert_eq!(&bytes[1..], b"hello");
}

#[test]
fn encode_bstr_empty() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bstr(b"").unwrap();
    assert_eq!(enc.as_bytes(), &[0x40]);
}

#[test]
fn encode_bstr_header() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bstr_header(10).unwrap();
    assert_eq!(enc.as_bytes(), &[0x4a]);
}

#[test]
fn encode_bstr_indefinite_begin() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bstr_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x5f]);
}

#[test]
fn encode_tstr() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tstr("abc").unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0x63); // major 3, len 3
    assert_eq!(&bytes[1..], b"abc");
}

#[test]
fn encode_tstr_header() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tstr_header(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x65]);
}

#[test]
fn encode_tstr_indefinite_begin() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tstr_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x7f]);
}

#[test]
fn encode_array() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array(3).unwrap();
    assert_eq!(enc.as_bytes(), &[0x83]);
}

#[test]
fn encode_array_indefinite_begin() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_array_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x9f]);
}

#[test]
fn encode_map() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_map(2).unwrap();
    assert_eq!(enc.as_bytes(), &[0xa2]);
}

#[test]
fn encode_map_indefinite_begin() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_map_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0xbf]);
}

#[test]
fn encode_tag() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_tag(1).unwrap();
    assert_eq!(enc.as_bytes(), &[0xc1]);
}

#[test]
fn encode_bool_true() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bool(true).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf5]);
}

#[test]
fn encode_bool_false() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_bool(false).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf4]);
}

#[test]
fn encode_null() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_null().unwrap();
    assert_eq!(enc.as_bytes(), &[0xf6]);
}

#[test]
fn encode_undefined() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_undefined().unwrap();
    assert_eq!(enc.as_bytes(), &[0xf7]);
}

#[test]
fn encode_simple_false() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::False).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf4]);
}

#[test]
fn encode_simple_true() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::True).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf5]);
}

#[test]
fn encode_simple_null() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::Null).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf6]);
}

#[test]
fn encode_simple_undefined() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::Undefined).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf7]);
}

#[test]
fn encode_simple_unassigned_small() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::Unassigned(16)).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf0]); // 0xe0 | 16
}

#[test]
fn encode_simple_unassigned_one_byte() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_simple(CborSimple::Unassigned(255)).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf8, 0xff]);
}

#[test]
fn encode_f16() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(1.0).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf9, 0x3c, 0x00]);
}

#[test]
fn encode_f16_zero() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(0.0).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf9, 0x00, 0x00]);
}

#[test]
fn encode_f16_infinity() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(f32::INFINITY).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf9, 0x7c, 0x00]);
}

#[test]
fn encode_f16_negative_infinity() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(f32::NEG_INFINITY).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf9, 0xfc, 0x00]);
}

#[test]
fn encode_f16_nan() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(f32::NAN).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0xf9);
    // NaN has exponent 0x1f and non-zero mantissa
    let bits = u16::from_be_bytes([bytes[1], bytes[2]]);
    assert_eq!(bits & 0x7c00, 0x7c00); // exponent all 1s
    assert_ne!(bits & 0x03ff, 0); // mantissa non-zero
}

#[test]
fn encode_f16_overflow() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(100000.0).unwrap(); // too big → becomes infinity
    assert_eq!(enc.as_bytes(), &[0xf9, 0x7c, 0x00]);
}

#[test]
fn encode_f16_subnormal() {
    let mut enc = EverparseCborEncoder::new();
    // f16 subnormal range: ~6.0e-8 to ~6.1e-5
    // Use 0.00005 which is safely in the subnormal range (exponent 112)
    enc.encode_f16(0.00005).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0xf9);
}

#[test]
fn encode_f16_tiny_to_zero() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f16(1e-20).unwrap(); // too small for f16 → zero
    assert_eq!(enc.as_bytes(), &[0xf9, 0x00, 0x00]);
}

#[test]
fn encode_f32() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f32(100000.0).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0xfa);
    let val = f32::from_bits(u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]));
    assert!((val - 100000.0).abs() < f32::EPSILON);
}

#[test]
fn encode_f64() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_f64(3.14).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0xfb);
    let val = f64::from_bits(u64::from_be_bytes([
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
    ]));
    assert!((val - 3.14).abs() < f64::EPSILON);
}

#[test]
fn encode_break() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_break().unwrap();
    assert_eq!(enc.as_bytes(), &[0xff]);
}

#[test]
fn encode_raw() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_raw(&[0x01, 0x02, 0x03]).unwrap();
    assert_eq!(enc.as_bytes(), &[0x01, 0x02, 0x03]);
}

#[test]
fn into_bytes() {
    let mut enc = EverparseCborEncoder::new();
    enc.encode_u8(42).unwrap();
    let bytes = enc.into_bytes();
    assert_eq!(bytes, vec![0x18, 0x2a]);
}

// ─── EverParseEncoder (no floats) ───────────────────────────────────────────

#[test]
fn everparse_encoder_default() {
    let enc = EverParseEncoder::default();
    assert!(enc.as_bytes().is_empty());
}

#[test]
fn everparse_encoder_with_capacity() {
    let enc = EverParseEncoder::with_capacity(100);
    assert!(enc.as_bytes().is_empty());
}

#[test]
fn everparse_encoder_u8() {
    let mut enc = EverParseEncoder::new();
    enc.encode_u8(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x05]);
}

#[test]
fn everparse_encoder_u16() {
    let mut enc = EverParseEncoder::new();
    enc.encode_u16(256).unwrap();
    assert_eq!(enc.as_bytes(), &[0x19, 0x01, 0x00]);
}

#[test]
fn everparse_encoder_u32() {
    let mut enc = EverParseEncoder::new();
    enc.encode_u32(65536).unwrap();
    assert_eq!(enc.as_bytes(), &[0x1a, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn everparse_encoder_u64() {
    let mut enc = EverParseEncoder::new();
    enc.encode_u64(u64::MAX).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes[0], 0x1b);
}

#[test]
fn everparse_encoder_i8() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i8(-1).unwrap();
    assert_eq!(enc.as_bytes(), &[0x20]);
}

#[test]
fn everparse_encoder_i16() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i16(-257).unwrap();
    assert_eq!(enc.as_bytes(), &[0x39, 0x01, 0x00]);
}

#[test]
fn everparse_encoder_i32() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i32(-65537).unwrap();
    assert_eq!(enc.as_bytes(), &[0x3a, 0x00, 0x01, 0x00, 0x00]);
}

#[test]
fn everparse_encoder_i64_positive() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i64(100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 0x64]);
}

#[test]
fn everparse_encoder_i64_negative() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i64(-100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x38, 0x63]);
}

#[test]
fn everparse_encoder_i128_positive() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i128(100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x18, 0x64]);
}

#[test]
fn everparse_encoder_i128_negative() {
    let mut enc = EverParseEncoder::new();
    enc.encode_i128(-100).unwrap();
    assert_eq!(enc.as_bytes(), &[0x38, 0x63]);
}

#[test]
fn everparse_encoder_i128_overflow() {
    let mut enc = EverParseEncoder::new();
    assert!(enc.encode_i128((u64::MAX as i128) + 1).is_err());
    let mut enc2 = EverParseEncoder::new();
    assert!(enc2.encode_i128(-(u64::MAX as i128) - 2).is_err());
}

#[test]
fn everparse_encoder_bstr() {
    let mut enc = EverParseEncoder::new();
    enc.encode_bstr(b"hi").unwrap();
    assert_eq!(enc.as_bytes(), &[0x42, b'h', b'i']);
}

#[test]
fn everparse_encoder_bstr_header() {
    let mut enc = EverParseEncoder::new();
    enc.encode_bstr_header(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x45]);
}

#[test]
fn everparse_encoder_bstr_indefinite() {
    let mut enc = EverParseEncoder::new();
    enc.encode_bstr_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x5f]);
}

#[test]
fn everparse_encoder_tstr() {
    let mut enc = EverParseEncoder::new();
    enc.encode_tstr("hi").unwrap();
    assert_eq!(enc.as_bytes(), &[0x62, b'h', b'i']);
}

#[test]
fn everparse_encoder_tstr_header() {
    let mut enc = EverParseEncoder::new();
    enc.encode_tstr_header(5).unwrap();
    assert_eq!(enc.as_bytes(), &[0x65]);
}

#[test]
fn everparse_encoder_tstr_indefinite() {
    let mut enc = EverParseEncoder::new();
    enc.encode_tstr_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x7f]);
}

#[test]
fn everparse_encoder_array() {
    let mut enc = EverParseEncoder::new();
    enc.encode_array(3).unwrap();
    assert_eq!(enc.as_bytes(), &[0x83]);
}

#[test]
fn everparse_encoder_array_indefinite() {
    let mut enc = EverParseEncoder::new();
    enc.encode_array_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0x9f]);
}

#[test]
fn everparse_encoder_map() {
    let mut enc = EverParseEncoder::new();
    enc.encode_map(2).unwrap();
    assert_eq!(enc.as_bytes(), &[0xa2]);
}

#[test]
fn everparse_encoder_map_indefinite() {
    let mut enc = EverParseEncoder::new();
    enc.encode_map_indefinite_begin().unwrap();
    assert_eq!(enc.as_bytes(), &[0xbf]);
}

#[test]
fn everparse_encoder_tag() {
    let mut enc = EverParseEncoder::new();
    enc.encode_tag(42).unwrap();
    assert_eq!(enc.as_bytes(), &[0xd8, 0x2a]);
}

#[test]
fn everparse_encoder_bool() {
    let mut enc = EverParseEncoder::new();
    enc.encode_bool(true).unwrap();
    enc.encode_bool(false).unwrap();
    assert_eq!(enc.as_bytes(), &[0xf5, 0xf4]);
}

#[test]
fn everparse_encoder_null() {
    let mut enc = EverParseEncoder::new();
    enc.encode_null().unwrap();
    assert_eq!(enc.as_bytes(), &[0xf6]);
}

#[test]
fn everparse_encoder_undefined() {
    let mut enc = EverParseEncoder::new();
    enc.encode_undefined().unwrap();
    assert_eq!(enc.as_bytes(), &[0xf7]);
}

#[test]
fn everparse_encoder_simple_values() {
    let mut enc = EverParseEncoder::new();
    enc.encode_simple(CborSimple::False).unwrap();
    enc.encode_simple(CborSimple::True).unwrap();
    enc.encode_simple(CborSimple::Null).unwrap();
    enc.encode_simple(CborSimple::Undefined).unwrap();
    enc.encode_simple(CborSimple::Unassigned(16)).unwrap();
    enc.encode_simple(CborSimple::Unassigned(255)).unwrap();
    let bytes = enc.as_bytes();
    assert_eq!(bytes, &[0xf4, 0xf5, 0xf6, 0xf7, 0xf0, 0xf8, 0xff]);
}

#[test]
fn everparse_encoder_f16_not_supported() {
    let mut enc = EverParseEncoder::new();
    assert!(enc.encode_f16(1.0).is_err());
}

#[test]
fn everparse_encoder_f32_not_supported() {
    let mut enc = EverParseEncoder::new();
    assert!(enc.encode_f32(1.0).is_err());
}

#[test]
fn everparse_encoder_f64_not_supported() {
    let mut enc = EverParseEncoder::new();
    assert!(enc.encode_f64(1.0).is_err());
}

#[test]
fn everparse_encoder_break() {
    let mut enc = EverParseEncoder::new();
    enc.encode_break().unwrap();
    assert_eq!(enc.as_bytes(), &[0xff]);
}

#[test]
fn everparse_encoder_raw() {
    let mut enc = EverParseEncoder::new();
    enc.encode_raw(&[0xde, 0xad]).unwrap();
    assert_eq!(enc.as_bytes(), &[0xde, 0xad]);
}

#[test]
fn everparse_encoder_into_bytes() {
    let mut enc = EverParseEncoder::new();
    enc.encode_u8(42).unwrap();
    let bytes = enc.into_bytes();
    assert_eq!(bytes, vec![0x18, 0x2a]);
}

// ─── EverParseCborProvider ──────────────────────────────────────────────────

#[test]
fn provider_encoder_and_decoder() {
    use cbor_primitives::{CborDecoder, CborProvider};
    use cbor_primitives_everparse::EverParseCborProvider;

    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_u8(42).unwrap();
    enc.encode_tstr("hello").unwrap();
    let bytes = enc.into_bytes();

    let mut dec = provider.decoder(&bytes);
    assert_eq!(dec.decode_u8().unwrap(), 42);
    assert_eq!(dec.decode_tstr().unwrap(), "hello");
}

#[test]
fn provider_encoder_with_capacity() {
    use cbor_primitives::CborProvider;
    use cbor_primitives_everparse::EverParseCborProvider;

    let provider = EverParseCborProvider;
    let enc = provider.encoder_with_capacity(1024);
    assert!(enc.as_bytes().is_empty());
}

// ─── Error Display ──────────────────────────────────────────────────────────

#[test]
fn error_display() {
    use cbor_primitives_everparse::EverparseError;

    let e = EverparseError::UnexpectedEof;
    assert!(format!("{}", e).contains("unexpected end"));

    let e = EverparseError::InvalidUtf8;
    assert!(format!("{}", e).contains("UTF-8"));

    let e = EverparseError::Overflow;
    assert!(format!("{}", e).contains("overflow"));

    let e = EverparseError::InvalidData("bad".into());
    assert!(format!("{}", e).contains("bad"));

    let e = EverparseError::Encoding("enc".into());
    assert!(format!("{}", e).contains("enc"));

    let e = EverparseError::Decoding("dec".into());
    assert!(format!("{}", e).contains("dec"));

    let e = EverparseError::VerificationFailed("vf".into());
    assert!(format!("{}", e).contains("vf"));

    let e = EverparseError::NotSupported("ns".into());
    assert!(format!("{}", e).contains("ns"));

    let e = EverparseError::UnexpectedType {
        expected: cbor_primitives::CborType::UnsignedInt,
        found: cbor_primitives::CborType::ByteString,
    };
    assert!(format!("{}", e).contains("unexpected CBOR type"));
}

#[test]
fn error_is_std_error() {
    use cbor_primitives_everparse::EverparseError;

    let e = EverparseError::UnexpectedEof;
    let _: &dyn std::error::Error = &e;
}
