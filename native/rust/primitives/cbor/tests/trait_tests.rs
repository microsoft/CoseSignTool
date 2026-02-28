// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests that verify trait definitions compile and have expected signatures.

use cbor_primitives::{CborDecoder, CborEncoder, CborError, CborProvider, CborSimple, CborType};

/// Verifies that CborType enum has all expected variants.
#[test]
fn test_cbor_type_variants() {
    let types = [
        CborType::UnsignedInt,
        CborType::NegativeInt,
        CborType::ByteString,
        CborType::TextString,
        CborType::Array,
        CborType::Map,
        CborType::Tag,
        CborType::Simple,
        CborType::Float16,
        CborType::Float32,
        CborType::Float64,
        CborType::Bool,
        CborType::Null,
        CborType::Undefined,
        CborType::Break,
    ];

    // Verify Clone, Copy, Debug, PartialEq, Eq
    for t in &types {
        let _ = *t; // Copy
        let _ = t.clone(); // Clone
        let _ = format!("{:?}", t); // Debug
        assert_eq!(*t, *t); // PartialEq, Eq
    }
}

/// Verifies that CborSimple enum has all expected variants.
#[test]
fn test_cbor_simple_variants() {
    let simples = [
        CborSimple::False,
        CborSimple::True,
        CborSimple::Null,
        CborSimple::Undefined,
        CborSimple::Unassigned(42),
    ];

    // Verify Clone, Copy, Debug, PartialEq, Eq
    for s in &simples {
        let _ = *s; // Copy
        let _ = s.clone(); // Clone
        let _ = format!("{:?}", s); // Debug
        assert_eq!(*s, *s); // PartialEq, Eq
    }
}

/// Verifies that CborError has all expected variants and implements required traits.
#[test]
fn test_cbor_error_variants() {
    let errors: Vec<CborError> = vec![
        CborError::UnexpectedType {
            expected: CborType::UnsignedInt,
            found: CborType::TextString,
        },
        CborError::UnexpectedEof,
        CborError::InvalidUtf8,
        CborError::Overflow,
        CborError::InvalidSimple(99),
        CborError::Custom("test error".to_string()),
    ];

    for e in &errors {
        // Verify Debug
        let _ = format!("{:?}", e);
        // Verify Display
        let _ = format!("{}", e);
        // Verify Clone
        let _ = e.clone();
    }

    // Verify std::error::Error implementation
    fn assert_error<E: std::error::Error>() {}
    assert_error::<CborError>();
}

/// Verifies CborEncoder trait has all required methods with correct signatures.
/// This is a compile-time check - the function itself doesn't need to run.
#[allow(dead_code)]
fn verify_encoder_trait<E: CborEncoder>() {
    fn check_encoder<E: CborEncoder>(mut enc: E) {
        // Major type 0: Unsigned integers
        let _ = enc.encode_u8(0u8);
        let _ = enc.encode_u16(0u16);
        let _ = enc.encode_u32(0u32);
        let _ = enc.encode_u64(0u64);

        // Major type 1: Negative integers
        let _ = enc.encode_i8(0i8);
        let _ = enc.encode_i16(0i16);
        let _ = enc.encode_i32(0i32);
        let _ = enc.encode_i64(0i64);
        let _ = enc.encode_i128(0i128);

        // Major type 2: Byte strings
        let _ = enc.encode_bstr(&[]);
        let _ = enc.encode_bstr_header(0u64);
        let _ = enc.encode_bstr_indefinite_begin();

        // Major type 3: Text strings
        let _ = enc.encode_tstr("");
        let _ = enc.encode_tstr_header(0u64);
        let _ = enc.encode_tstr_indefinite_begin();

        // Major type 4: Arrays
        let _ = enc.encode_array(0usize);
        let _ = enc.encode_array_indefinite_begin();

        // Major type 5: Maps
        let _ = enc.encode_map(0usize);
        let _ = enc.encode_map_indefinite_begin();

        // Major type 6: Tags
        let _ = enc.encode_tag(0u64);

        // Major type 7: Simple/Float
        let _ = enc.encode_bool(true);
        let _ = enc.encode_null();
        let _ = enc.encode_undefined();
        let _ = enc.encode_simple(CborSimple::Null);
        let _ = enc.encode_f16(0.0f32);
        let _ = enc.encode_f32(0.0f32);
        let _ = enc.encode_f64(0.0f64);
        let _ = enc.encode_break();

        // Raw bytes
        let _ = enc.encode_raw(&[]);

        // Output
        let _: &[u8] = enc.as_bytes();
        let _: Vec<u8> = enc.into_bytes();
    }

    // Verify error type bounds
    fn assert_error_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<<E as CborEncoder>::Error>();
}

/// Verifies CborDecoder trait has all required methods with correct signatures.
/// This is a compile-time check - the function itself doesn't need to run.
#[allow(dead_code)]
fn verify_decoder_trait<'a, D: CborDecoder<'a>>() {
    fn check_decoder<'a, D: CborDecoder<'a>>(mut dec: D) {
        // Type inspection
        let _: Result<CborType, D::Error> = dec.peek_type();
        let _: Result<bool, D::Error> = dec.is_break();
        let _: Result<bool, D::Error> = dec.is_null();
        let _: Result<bool, D::Error> = dec.is_undefined();

        // Major type 0/1: Integers
        let _: Result<u8, D::Error> = dec.decode_u8();
        let _: Result<u16, D::Error> = dec.decode_u16();
        let _: Result<u32, D::Error> = dec.decode_u32();
        let _: Result<u64, D::Error> = dec.decode_u64();
        let _: Result<i8, D::Error> = dec.decode_i8();
        let _: Result<i16, D::Error> = dec.decode_i16();
        let _: Result<i32, D::Error> = dec.decode_i32();
        let _: Result<i64, D::Error> = dec.decode_i64();
        let _: Result<i128, D::Error> = dec.decode_i128();

        // Major type 2: Byte strings
        let _: Result<&'a [u8], D::Error> = dec.decode_bstr();
        let _: Result<Option<u64>, D::Error> = dec.decode_bstr_header();

        // Major type 3: Text strings
        let _: Result<&'a str, D::Error> = dec.decode_tstr();
        let _: Result<Option<u64>, D::Error> = dec.decode_tstr_header();

        // Major type 4: Arrays
        let _: Result<Option<usize>, D::Error> = dec.decode_array_len();

        // Major type 5: Maps
        let _: Result<Option<usize>, D::Error> = dec.decode_map_len();

        // Major type 6: Tags
        let _: Result<u64, D::Error> = dec.decode_tag();

        // Major type 7: Simple/Float
        let _: Result<bool, D::Error> = dec.decode_bool();
        let _: Result<(), D::Error> = dec.decode_null();
        let _: Result<(), D::Error> = dec.decode_undefined();
        let _: Result<CborSimple, D::Error> = dec.decode_simple();
        let _: Result<f32, D::Error> = dec.decode_f16();
        let _: Result<f32, D::Error> = dec.decode_f32();
        let _: Result<f64, D::Error> = dec.decode_f64();
        let _: Result<(), D::Error> = dec.decode_break();

        // Navigation
        let _: Result<(), D::Error> = dec.skip();
        let _: &'a [u8] = dec.remaining();
        let _: usize = dec.position();
    }

    // Verify error type bounds
    fn assert_error_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<<D as CborDecoder<'a>>::Error>();
}

/// Verifies CborProvider trait has all required methods with correct signatures.
/// This is a compile-time check - the function itself doesn't need to run.
#[allow(dead_code)]
fn verify_provider_trait<P: CborProvider>() {
    fn check_provider<P: CborProvider>(provider: P, data: &[u8]) {
        let _: P::Encoder = provider.encoder();
        let _: P::Encoder = provider.encoder_with_capacity(1024);
        let _: P::Decoder<'_> = provider.decoder(data);
    }

    // Verify provider bounds
    fn assert_provider_bounds<P: Send + Sync + Clone + 'static>() {}
    assert_provider_bounds::<P>();

    // Verify encoder/decoder type bounds
    fn assert_encoder_bounds<E: CborEncoder>() {}
    assert_encoder_bounds::<P::Encoder>();

    // Verify error type bounds
    fn assert_error_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<P::Error>();
}
