// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests targeting uncovered error paths in the EverParse CBOR decoder.

use cbor_primitives::{CborDecoder, CborType};
use cbor_primitives_everparse::EverparseCborDecoder;

// ─── make_parse_error paths (lines 42-67) ────────────────────────────────────
// These are triggered when cbor_det_parse fails and parse_next_item calls
// make_parse_error to produce a descriptive error.

#[test]
fn parse_error_on_empty_input_returns_eof() {
    // Line 44: remaining is empty → UnexpectedEof
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        err.to_string().contains("unexpected end of input")
            || err.to_string().contains("EOF")
            || format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn parse_error_float16_not_supported() {
    // Lines 51-55: major type 7, additional_info 25 (f16) → float error
    let data: &[u8] = &[0xf9, 0x3c, 0x00]; // f16 1.0
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("floating-point"),
        "expected float error, got: {err:?}"
    );
}

#[test]
fn parse_error_float32_not_supported() {
    // Lines 51-55: major type 7, additional_info 26 (f32) → float error
    let data: &[u8] = &[0xfa, 0x41, 0x20, 0x00, 0x00]; // f32 10.0
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("floating-point"),
        "expected float error, got: {err:?}"
    );
}

#[test]
fn parse_error_float64_not_supported() {
    // Lines 51-55: major type 7, additional_info 27 (f64) → float error
    let mut data = vec![0xfb];
    data.extend_from_slice(&1.0f64.to_bits().to_be_bytes());
    let mut dec = EverparseCborDecoder::new(&data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("floating-point"),
        "expected float error, got: {err:?}"
    );
}

#[test]
fn parse_error_break_not_supported() {
    // Lines 56-58: major type 7, additional_info 31 (break) → break error
    let data: &[u8] = &[0xff]; // break code
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("break") || format!("{err:?}").contains("indefinite"),
        "expected break/indefinite error, got: {err:?}"
    );
}

#[test]
fn parse_error_major7_invalid_additional_info() {
    // Line 59: major type 7, additional_info not in 25..=27 or 31
    // additional_info=28 → 0xe0 | 28 = 0xfc
    let data: &[u8] = &[0xfc];
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("invalid CBOR data"),
        "expected invalid CBOR data error, got: {err:?}"
    );
}

#[test]
fn parse_error_indefinite_length_encoding() {
    // Lines 61-64: non-major-7 with additional_info 31 → indefinite-length error
    // 0x5f = major type 2 (bstr), additional_info 31 (indefinite)
    let data: &[u8] = &[0x5f, 0x41, 0xAA, 0xff]; // indefinite bstr with chunk + break
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("indefinite-length"),
        "expected indefinite-length error, got: {err:?}"
    );
}

#[test]
fn parse_error_non_deterministic_cbor() {
    // Line 66: non-major-7, additional_info != 31, but invalid/non-deterministic
    // Use non-deterministic encoding: value 0 encoded with 1-byte additional (0x18, 0x00)
    // which is non-canonical (should be encoded as just 0x00).
    let data: &[u8] = &[0x18, 0x00]; // uint with non-minimal encoding
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("non-deterministic") || format!("{err:?}").contains("invalid"),
        "expected non-deterministic error, got: {err:?}"
    );
}

// ─── view_to_cbor_type paths (lines 74, 82-84) ──────────────────────────────
// Triggered via type mismatch errors where the found type comes from view_to_cbor_type.

#[test]
fn view_to_cbor_type_negative_int() {
    // Line 74: NegInt64 → CborType::NegativeInt
    let data: &[u8] = &[0x20]; // nint -1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_bstr().unwrap_err();
    assert!(
        format!("{err:?}").contains("NegativeInt"),
        "expected NegativeInt in error, got: {err:?}"
    );
}

#[test]
fn view_to_cbor_type_null_mismatch() {
    // Line 82: SimpleValue(22) → CborType::Null
    let data: &[u8] = &[0xf6]; // null
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("Null"),
        "expected Null in error, got: {err:?}"
    );
}

#[test]
fn view_to_cbor_type_undefined_mismatch() {
    // Line 83: SimpleValue(23) → CborType::Undefined
    let data: &[u8] = &[0xf7]; // undefined
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("Undefined"),
        "expected Undefined in error, got: {err:?}"
    );
}

#[test]
fn view_to_cbor_type_simple_mismatch() {
    // Line 84: SimpleValue with value not 20-23 → CborType::Simple
    let data: &[u8] = &[0xf0]; // simple(16)
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_u64().unwrap_err();
    assert!(
        format!("{err:?}").contains("Simple"),
        "expected Simple in error, got: {err:?}"
    );
}

// ─── decode_raw_argument truncation (lines 94, 108, 113, 118) ───────────────

#[test]
fn decode_raw_argument_empty_eof() {
    // Line 94: decode_raw_argument on empty → UnexpectedEof
    // Triggered via decode_tag on empty input
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn decode_raw_argument_truncated_1byte() {
    // Line 108: additional_info == 25 (needs 3 bytes) but only 2 bytes available
    // 0xc0 | 25 = 0xd9 → tag with 2-byte argument, but truncated
    let data: &[u8] = &[0xd9, 0x01]; // tag header needing 2 arg bytes, only 1 present
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn decode_raw_argument_truncated_2byte_arg() {
    // Line 108: additional_info == 24 needs 2 bytes total, only header present
    let data: &[u8] = &[0xd8]; // tag with 1-byte arg, but no arg byte
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn decode_raw_argument_truncated_4byte() {
    // Line 113: additional_info == 26 needs 5 bytes, but truncated
    // 0xda = tag with 4-byte argument
    let data: &[u8] = &[0xda, 0x01, 0x02]; // only 3 bytes, need 5
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn decode_raw_argument_truncated_8byte() {
    // Line 118: additional_info == 27 needs 9 bytes, but truncated
    // 0xdb = tag with 8-byte argument
    let data: &[u8] = &[0xdb, 0x01, 0x02, 0x03]; // only 4 bytes, need 9
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

// ─── skip_raw_item paths ────────────────────────────────────────────────────

#[test]
fn skip_raw_item_definite_array() {
    // Lines 195-197: skip_raw_item for definite-length array via skip() fallback
    // Build an array that EverParse rejects (non-deterministic) but skip_raw_item handles.
    // Use a definite-length array containing a float (which EverParse can't parse as a whole).
    // 0x81 = array(1), 0xf9 0x3c 0x00 = f16(1.0)
    let data: &[u8] = &[0x81, 0xf9, 0x3c, 0x00];
    let mut dec = EverparseCborDecoder::new(data);
    // EverParse can't parse this array (contains float), so skip falls through to skip_raw_item
    let result = dec.skip();
    // This should succeed via skip_raw_item
    assert!(result.is_ok(), "skip definite array failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_raw_item_tag() {
    // Lines 228-230: skip_raw_item for tag wrapping a float
    // 0xc1 = tag(1), 0xf9 0x3c 0x00 = f16(1.0)
    let data: &[u8] = &[0xc1, 0xf9, 0x3c, 0x00];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip tag failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_raw_item_major7_simple_24() {
    // Line 236: major type 7, additional_info 24 → skip 2 bytes
    // 0xf8 0x20 = simple(32), which EverParse deterministic parser can handle,
    // but let's use it inside a non-deterministic context so skip falls through.
    // Actually, simple(32) encoded as 0xf8 0x20 may parse fine with EverParse,
    // so we need it nested in something EverParse rejects.
    // Use a definite array with a float: [simple(32), f16(1.0)]
    let data: &[u8] = &[0x82, 0xf8, 0x20, 0xf9, 0x3c, 0x00];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip array with simple(32) + float failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_raw_item_truncated_major7() {
    // Line 249 region: major type 7 with truncated data
    // 0xfa = f32 needs 5 bytes, only provide 3
    // This must reach skip_raw_item, so wrap in something EverParse rejects.
    // Actually, a bare f32 header that's truncated will fail cbor_det_parse,
    // then skip_raw_item is called, which checks data.len() < skip.
    let data: &[u8] = &[0xfa, 0x01, 0x02]; // truncated f32
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.skip().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

// ─── peek_type edge cases (lines 285, 287) ──────────────────────────────────

#[test]
fn peek_type_simple_low_range() {
    // Line 285: additional_info < 20 (but not 20-23 range) → Simple
    // 0xe0 = simple(0) (major 7, additional_info 0)
    let data: &[u8] = &[0xe0];
    let mut dec = EverparseCborDecoder::new(data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Simple);

    // 0xe1 = simple(1) (major 7, additional_info 1)
    let data2: &[u8] = &[0xe1];
    let mut dec2 = EverparseCborDecoder::new(data2);
    assert_eq!(dec2.peek_type().unwrap(), CborType::Simple);

    // 0xf3 = simple(19) (major 7, additional_info 19)
    let data3: &[u8] = &[0xf3];
    let mut dec3 = EverparseCborDecoder::new(data3);
    assert_eq!(dec3.peek_type().unwrap(), CborType::Simple);
}

#[test]
fn peek_type_simple_high_range() {
    // Line 285: The wildcard for additional_info 28-30 (between defined ranges)
    // These are reserved/unassigned in CBOR but major type 7
    // 0xe0 | 28 = 0xfc → additional_info 28
    let data: &[u8] = &[0xfc]; // major 7, additional_info 28
    let mut dec = EverparseCborDecoder::new(data);
    assert_eq!(dec.peek_type().unwrap(), CborType::Simple);

    // 0xfd = major 7, additional_info 29
    let data2: &[u8] = &[0xfd];
    let mut dec2 = EverparseCborDecoder::new(data2);
    assert_eq!(dec2.peek_type().unwrap(), CborType::Simple);

    // 0xfe = major 7, additional_info 30
    let data3: &[u8] = &[0xfe];
    let mut dec3 = EverparseCborDecoder::new(data3);
    assert_eq!(dec3.peek_type().unwrap(), CborType::Simple);
}

// ─── Additional error paths ─────────────────────────────────────────────────

#[test]
fn skip_indefinite_map_via_skip_raw() {
    // Lines 204-216: indefinite-length map in skip_raw_item
    // Build a non-deterministic indefinite map with float values so EverParse
    // rejects it and skip falls through to skip_raw_item.
    // 0xbf = indefinite map, key=0x01 (uint 1), value=0xf9 0x3c 0x00 (f16 1.0), 0xff = break
    let data: &[u8] = &[0xbf, 0x01, 0xf9, 0x3c, 0x00, 0xff];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip indefinite map failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_definite_map_with_float_values() {
    // Lines 217-222: definite-length map with float values via skip_raw_item
    // 0xa1 = map(1), key=0x01 (uint 1), value=0xf9 0x3c 0x00 (f16 1.0)
    let data: &[u8] = &[0xa1, 0x01, 0xf9, 0x3c, 0x00];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip definite map with float failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_indefinite_bstr() {
    // Lines 156-169: indefinite-length byte string via skip_raw_item
    // 0x5f = indefinite bstr, 0x41 0xAA = bstr chunk "AA", 0xff = break
    // EverParse rejects indefinite-length, so falls through to skip_raw_item.
    let data: &[u8] = &[0x5f, 0x41, 0xAA, 0xff];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip indefinite bstr failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_indefinite_array() {
    // Lines 182-193: indefinite-length array via skip_raw_item
    // 0x9f = indefinite array, 0x01 = uint 1, 0x02 = uint 2, 0xff = break
    let data: &[u8] = &[0x9f, 0x01, 0x02, 0xff];
    let mut dec = EverparseCborDecoder::new(data);
    let result = dec.skip();
    assert!(result.is_ok(), "skip indefinite array failed: {result:?}");
    assert!(dec.remaining().is_empty());
}

#[test]
fn skip_raw_item_empty_returns_eof() {
    // Line 141: skip_raw_item on empty → UnexpectedEof
    let data: &[u8] = &[];
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.skip().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn skip_indefinite_bstr_missing_break() {
    // Line 161: indefinite bstr with no break → UnexpectedEof
    let data: &[u8] = &[0x5f, 0x41, 0xAA]; // indefinite bstr, one chunk, no break
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.skip().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn skip_indefinite_array_missing_break() {
    // Line 185: indefinite array empty after header → UnexpectedEof
    let data: &[u8] = &[0x9f]; // indefinite array, no items or break
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.skip().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn skip_indefinite_map_missing_break() {
    // Line 207: indefinite map empty after header → UnexpectedEof
    let data: &[u8] = &[0xbf]; // indefinite map, no items or break
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.skip().unwrap_err();
    assert!(
        format!("{err:?}").contains("UnexpectedEof"),
        "expected UnexpectedEof, got: {err:?}"
    );
}

#[test]
fn decode_bstr_header_type_mismatch() {
    // decode_bstr_header when data is not a bstr
    let data: &[u8] = &[0x01]; // uint 1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_bstr_header().unwrap_err();
    assert!(
        format!("{err:?}").contains("ByteString"),
        "expected ByteString type error, got: {err:?}"
    );
}

#[test]
fn decode_tstr_header_type_mismatch() {
    // decode_tstr_header when data is not a tstr
    let data: &[u8] = &[0x01]; // uint 1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tstr_header().unwrap_err();
    assert!(
        format!("{err:?}").contains("TextString"),
        "expected TextString type error, got: {err:?}"
    );
}

#[test]
fn decode_array_len_type_mismatch() {
    let data: &[u8] = &[0x01]; // uint 1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_array_len().unwrap_err();
    assert!(
        format!("{err:?}").contains("Array"),
        "expected Array type error, got: {err:?}"
    );
}

#[test]
fn decode_map_len_type_mismatch() {
    let data: &[u8] = &[0x01]; // uint 1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_map_len().unwrap_err();
    assert!(
        format!("{err:?}").contains("Map"),
        "expected Map type error, got: {err:?}"
    );
}

#[test]
fn decode_tag_type_mismatch() {
    let data: &[u8] = &[0x01]; // uint 1
    let mut dec = EverparseCborDecoder::new(data);
    let err = dec.decode_tag().unwrap_err();
    assert!(
        format!("{err:?}").contains("Tag"),
        "expected Tag type error, got: {err:?}"
    );
}
