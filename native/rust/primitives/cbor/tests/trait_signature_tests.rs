// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests that verify trait method signatures and bounds using mock implementations.

use cbor_primitives::{CborDecoder, CborEncoder, CborError, CborProvider, CborSimple, CborType};

// ============================================================================
// Mock Implementations for Testing
// ============================================================================

/// Mock encoder for testing trait bounds and method signatures.
struct MockEncoder {
    data: Vec<u8>,
}

impl CborEncoder for MockEncoder {
    type Error = CborError;

    fn encode_u8(&mut self, _value: u8) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_u16(&mut self, _value: u16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_u32(&mut self, _value: u32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_u64(&mut self, _value: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_i8(&mut self, _value: i8) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_i16(&mut self, _value: i16) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_i32(&mut self, _value: i32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_i64(&mut self, _value: i64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_i128(&mut self, _value: i128) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_bstr(&mut self, _data: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_bstr_header(&mut self, _len: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_bstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_tstr(&mut self, _data: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_tstr_header(&mut self, _len: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_tstr_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_array(&mut self, _len: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_array_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_map(&mut self, _len: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_map_indefinite_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_tag(&mut self, _tag: u64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_bool(&mut self, _value: bool) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_null(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_undefined(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_simple(&mut self, _value: CborSimple) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_f16(&mut self, _value: f32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_f32(&mut self, _value: f32) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_f64(&mut self, _value: f64) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_break(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn encode_raw(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Mock decoder for testing trait bounds and method signatures.
struct MockDecoder<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> CborDecoder<'a> for MockDecoder<'a> {
    type Error = CborError;

    fn peek_type(&mut self) -> Result<CborType, Self::Error> {
        Ok(CborType::UnsignedInt)
    }

    fn is_break(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn is_null(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn is_undefined(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn decode_u8(&mut self) -> Result<u8, Self::Error> {
        Ok(0)
    }

    fn decode_u16(&mut self) -> Result<u16, Self::Error> {
        Ok(0)
    }

    fn decode_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0)
    }

    fn decode_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn decode_i8(&mut self) -> Result<i8, Self::Error> {
        Ok(0)
    }

    fn decode_i16(&mut self) -> Result<i16, Self::Error> {
        Ok(0)
    }

    fn decode_i32(&mut self) -> Result<i32, Self::Error> {
        Ok(0)
    }

    fn decode_i64(&mut self) -> Result<i64, Self::Error> {
        Ok(0)
    }

    fn decode_i128(&mut self) -> Result<i128, Self::Error> {
        Ok(0)
    }

    fn decode_bstr(&mut self) -> Result<&'a [u8], Self::Error> {
        Ok(&[])
    }

    fn decode_bstr_header(&mut self) -> Result<Option<u64>, Self::Error> {
        Ok(Some(0))
    }

    fn decode_tstr(&mut self) -> Result<&'a str, Self::Error> {
        Ok("")
    }

    fn decode_tstr_header(&mut self) -> Result<Option<u64>, Self::Error> {
        Ok(Some(0))
    }

    fn decode_array_len(&mut self) -> Result<Option<usize>, Self::Error> {
        Ok(Some(0))
    }

    fn decode_map_len(&mut self) -> Result<Option<usize>, Self::Error> {
        Ok(Some(0))
    }

    fn decode_tag(&mut self) -> Result<u64, Self::Error> {
        Ok(0)
    }

    fn decode_bool(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }

    fn decode_null(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn decode_undefined(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn decode_simple(&mut self) -> Result<CborSimple, Self::Error> {
        Ok(CborSimple::Null)
    }

    fn decode_f16(&mut self) -> Result<f32, Self::Error> {
        Ok(0.0)
    }

    fn decode_f32(&mut self) -> Result<f32, Self::Error> {
        Ok(0.0)
    }

    fn decode_f64(&mut self) -> Result<f64, Self::Error> {
        Ok(0.0)
    }

    fn decode_break(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn skip(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn remaining(&self) -> &'a [u8] {
        &self.data[self.position..]
    }

    fn position(&self) -> usize {
        self.position
    }

    fn decode_raw(&mut self) -> Result<&'a [u8], Self::Error> {
        Ok(&[])
    }
}

/// Mock provider for testing trait bounds and method signatures.
#[derive(Clone)]
struct MockProvider;

impl CborProvider for MockProvider {
    type Encoder = MockEncoder;
    type Decoder<'a> = MockDecoder<'a>;
    type Error = CborError;

    fn encoder(&self) -> Self::Encoder {
        MockEncoder { data: Vec::new() }
    }

    fn encoder_with_capacity(&self, capacity: usize) -> Self::Encoder {
        MockEncoder {
            data: Vec::with_capacity(capacity),
        }
    }

    fn decoder<'a>(&self, data: &'a [u8]) -> Self::Decoder<'a> {
        MockDecoder { data, position: 0 }
    }
}

// ============================================================================
// CborEncoder Trait Signature Tests
// ============================================================================

#[test]
fn test_encoder_unsigned_int_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_u8(0u8).is_ok());
    assert!(enc.encode_u16(0u16).is_ok());
    assert!(enc.encode_u32(0u32).is_ok());
    assert!(enc.encode_u64(0u64).is_ok());
}

#[test]
fn test_encoder_signed_int_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_i8(0i8).is_ok());
    assert!(enc.encode_i16(0i16).is_ok());
    assert!(enc.encode_i32(0i32).is_ok());
    assert!(enc.encode_i64(0i64).is_ok());
    assert!(enc.encode_i128(0i128).is_ok());
}

#[test]
fn test_encoder_byte_string_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_bstr(&[]).is_ok());
    assert!(enc.encode_bstr_header(100).is_ok());
    assert!(enc.encode_bstr_indefinite_begin().is_ok());
}

#[test]
fn test_encoder_text_string_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_tstr("").is_ok());
    assert!(enc.encode_tstr_header(100).is_ok());
    assert!(enc.encode_tstr_indefinite_begin().is_ok());
}

#[test]
fn test_encoder_array_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_array(0).is_ok());
    assert!(enc.encode_array_indefinite_begin().is_ok());
}

#[test]
fn test_encoder_map_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_map(0).is_ok());
    assert!(enc.encode_map_indefinite_begin().is_ok());
}

#[test]
fn test_encoder_tag_method() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_tag(0).is_ok());
}

#[test]
fn test_encoder_simple_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_bool(true).is_ok());
    assert!(enc.encode_null().is_ok());
    assert!(enc.encode_undefined().is_ok());
    assert!(enc.encode_simple(CborSimple::Null).is_ok());
}

#[test]
fn test_encoder_float_methods() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_f16(0.0f32).is_ok());
    assert!(enc.encode_f32(0.0f32).is_ok());
    assert!(enc.encode_f64(0.0f64).is_ok());
}

#[test]
fn test_encoder_break_method() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_break().is_ok());
}

#[test]
fn test_encoder_raw_method() {
    let mut enc = MockEncoder { data: Vec::new() };

    assert!(enc.encode_raw(&[1, 2, 3]).is_ok());
}

#[test]
fn test_encoder_output_methods() {
    let mut enc = MockEncoder { data: Vec::new() };
    enc.encode_raw(&[1, 2, 3]).unwrap();

    let bytes_ref = enc.as_bytes();
    assert_eq!(bytes_ref, &[1, 2, 3]);

    let bytes_owned = enc.into_bytes();
    assert_eq!(bytes_owned, vec![1, 2, 3]);
}

#[test]
fn test_encoder_error_bounds() {
    fn assert_error_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<<MockEncoder as CborEncoder>::Error>();
}

// ============================================================================
// CborDecoder Trait Signature Tests
// ============================================================================

#[test]
fn test_decoder_type_inspection_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.peek_type().is_ok());
    assert!(dec.is_break().is_ok());
    assert!(dec.is_null().is_ok());
    assert!(dec.is_undefined().is_ok());
}

#[test]
fn test_decoder_unsigned_int_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_u8().is_ok());
    assert!(dec.decode_u16().is_ok());
    assert!(dec.decode_u32().is_ok());
    assert!(dec.decode_u64().is_ok());
}

#[test]
fn test_decoder_signed_int_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_i8().is_ok());
    assert!(dec.decode_i16().is_ok());
    assert!(dec.decode_i32().is_ok());
    assert!(dec.decode_i64().is_ok());
    assert!(dec.decode_i128().is_ok());
}

#[test]
fn test_decoder_byte_string_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_bstr().is_ok());
    assert!(dec.decode_bstr_header().is_ok());
}

#[test]
fn test_decoder_text_string_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_tstr().is_ok());
    assert!(dec.decode_tstr_header().is_ok());
}

#[test]
fn test_decoder_array_method() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_array_len().is_ok());
}

#[test]
fn test_decoder_map_method() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_map_len().is_ok());
}

#[test]
fn test_decoder_tag_method() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_tag().is_ok());
}

#[test]
fn test_decoder_simple_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_bool().is_ok());
    assert!(dec.decode_null().is_ok());
    assert!(dec.decode_undefined().is_ok());
    assert!(dec.decode_simple().is_ok());
}

#[test]
fn test_decoder_float_methods() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_f16().is_ok());
    assert!(dec.decode_f32().is_ok());
    assert!(dec.decode_f64().is_ok());
}

#[test]
fn test_decoder_break_method() {
    let data = &[];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_break().is_ok());
}

#[test]
fn test_decoder_navigation_methods() {
    let data = &[1, 2, 3, 4, 5];
    let mut dec = MockDecoder { data, position: 2 };

    assert!(dec.skip().is_ok());

    let remaining = dec.remaining();
    assert_eq!(remaining, &[3, 4, 5]);

    let pos = dec.position();
    assert_eq!(pos, 2);
}

#[test]
fn test_decoder_raw_method() {
    let data = &[1, 2, 3];
    let mut dec = MockDecoder { data, position: 0 };

    assert!(dec.decode_raw().is_ok());
}

#[test]
fn test_decoder_error_bounds() {
    fn assert_error_bounds<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error_bounds::<<MockDecoder<'_> as CborDecoder<'_>>::Error>();
}

#[test]
fn test_decoder_lifetime_correctness() {
    let data = vec![1, 2, 3];
    let dec = MockDecoder {
        data: &data,
        position: 0,
    };

    // Decoder should be tied to the lifetime of the data
    let _remaining = dec.remaining();
    // Data must outlive decoder
    drop(dec);
    drop(data);
}

// ============================================================================
// CborProvider Trait Signature Tests
// ============================================================================

#[test]
fn test_provider_encoder_creation() {
    let provider = MockProvider;

    let _enc1 = provider.encoder();
    let _enc2 = provider.encoder_with_capacity(1024);
}

#[test]
fn test_provider_decoder_creation() {
    let provider = MockProvider;
    let data = &[1, 2, 3];

    let _dec = provider.decoder(data);
}

#[test]
fn test_provider_trait_bounds() {
    fn assert_bounds<P: Send + Sync + Clone + 'static>() {}
    assert_bounds::<MockProvider>();
}

#[test]
fn test_provider_encoder_type_bounds() {
    fn assert_encoder<E: CborEncoder>() {}
    assert_encoder::<MockEncoder>();
}

#[test]
fn test_provider_decoder_type_bounds() {
    fn assert_decoder<'a, D: CborDecoder<'a>>() {}
    assert_decoder::<MockDecoder<'_>>();
}

#[test]
fn test_provider_error_type_bounds() {
    fn assert_error<E: std::error::Error + Send + Sync + 'static>() {}
    assert_error::<<MockProvider as CborProvider>::Error>();
}

#[test]
fn test_provider_clone() {
    let provider = MockProvider;
    let cloned = provider.clone();

    let _enc1 = provider.encoder();
    let _enc2 = cloned.encoder();
}

// ============================================================================
// Integration Tests with Mock Types
// ============================================================================

#[test]
fn test_encoder_decoder_integration() {
    let provider = MockProvider;

    let mut encoder = provider.encoder();
    encoder.encode_u8(42).unwrap();
    encoder.encode_tstr("test").unwrap();

    let bytes = encoder.into_bytes();

    let mut decoder = provider.decoder(&bytes);
    let _ = decoder.peek_type().unwrap();
}

#[test]
fn test_trait_generic_function() {
    fn encode_value<E: CborEncoder>(enc: &mut E, val: u32) -> Result<(), E::Error> {
        enc.encode_u32(val)
    }

    let mut encoder = MockEncoder { data: Vec::new() };
    assert!(encode_value(&mut encoder, 123).is_ok());
}

#[test]
fn test_trait_generic_decode() {
    fn decode_value<'a, D: CborDecoder<'a>>(dec: &mut D) -> Result<u32, D::Error> {
        dec.decode_u32()
    }

    let data = &[];
    let mut decoder = MockDecoder { data, position: 0 };
    assert!(decode_value(&mut decoder).is_ok());
}

#[test]
fn test_trait_provider_generic() {
    fn create_and_use<P: CborProvider>(provider: &P) {
        let _enc = provider.encoder();
        let _dec = provider.decoder(&[]);
    }

    let provider = MockProvider;
    create_and_use(&provider);
}
