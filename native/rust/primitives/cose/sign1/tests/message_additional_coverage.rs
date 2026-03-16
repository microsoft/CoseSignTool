// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for CoseSign1Message to reach all uncovered code paths.

use std::io::Cursor;
use std::sync::Arc;

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;
use cose_sign1_primitives::sig_structure::{SizedRead, SizedReader};
use cose_sign1_primitives::payload::StreamingPayload;
use cose_sign1_primitives::error::PayloadError;

/// Mock streaming payload for testing
struct MockStreamingPayload {
    data: Vec<u8>,
}

impl MockStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl StreamingPayload for MockStreamingPayload {
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(SizedReader::new(Cursor::new(self.data.clone()), self.data.len() as u64)))
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Mock crypto verifier for testing
struct MockCryptoVerifier {
    verify_result: bool,
}

impl MockCryptoVerifier {
    fn new(verify_result: bool) -> Self {
        Self { verify_result }
    }
}

impl crypto_primitives::CryptoVerifier for MockCryptoVerifier {
    fn verify(&self, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, crypto_primitives::CryptoError> {
        Ok(self.verify_result)
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
}

#[test]
fn test_parse_tagged_message() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Tag 18 for COSE_Sign1
    encoder.encode_tag(COSE_SIGN1_TAG).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // empty protected
    encoder.encode_map(0).unwrap(); // empty unprotected
    encoder.encode_null().unwrap(); // detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse tagged");
    assert!(msg.is_detached());
}

#[test]
fn test_parse_wrong_tag() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Wrong tag (not 18)
    encoder.encode_tag(999).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("tag"));
}

#[test]
fn test_parse_indefinite_array() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    encoder.encode_break().unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("definite-length"));
}

#[test]
fn test_parse_wrong_array_length() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Array with 3 elements instead of 4
    encoder.encode_array(3).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("4 elements"));
}

#[test]
fn test_decode_all_header_value_types() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    // Comprehensive unprotected header with all types
    encoder.encode_map(8).unwrap();
    
    // ByteString
    encoder.encode_i64(10).unwrap();
    encoder.encode_bstr(b"binary_data").unwrap();
    
    // Null
    encoder.encode_i64(11).unwrap();
    encoder.encode_null().unwrap();
    
    // Map value
    encoder.encode_i64(12).unwrap();
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    
    // Definite array with nested values
    encoder.encode_i64(13).unwrap();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(42).unwrap();
    encoder.encode_tstr("nested").unwrap();
    
    // Text string label (not int)
    encoder.encode_tstr("text_label").unwrap();
    encoder.encode_i64(555).unwrap();
    
    // Nested indefinite map
    encoder.encode_i64(14).unwrap();
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_tstr("key1").unwrap();
    encoder.encode_i64(100).unwrap();
    encoder.encode_break().unwrap();
    
    // Negative integer header value
    encoder.encode_i64(15).unwrap();
    encoder.encode_i64(-999).unwrap();
    
    // Bool false
    encoder.encode_i64(16).unwrap();
    encoder.encode_bool(false).unwrap();
    
    encoder.encode_null().unwrap(); // payload
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse all types");
    
    // Verify all parsed values
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(10)), Some(&CoseHeaderValue::Bytes(b"binary_data".to_vec())));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(11)), Some(&CoseHeaderValue::Null));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(15)), Some(&CoseHeaderValue::Int(-999)));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(16)), Some(&CoseHeaderValue::Bool(false)));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Text("text_label".to_string())), Some(&CoseHeaderValue::Int(555)));
    
    // Check map value
    match msg.unprotected.get(&CoseHeaderLabel::Int(12)) {
        Some(CoseHeaderValue::Map(pairs)) => {
            assert_eq!(pairs.len(), 1);
            assert_eq!(pairs[0].0, CoseHeaderLabel::Int(1));
            assert_eq!(pairs[0].1, CoseHeaderValue::Int(2));
        }
        _ => panic!("Expected map value"),
    }
    
    // Check array value
    match msg.unprotected.get(&CoseHeaderLabel::Int(13)) {
        Some(CoseHeaderValue::Array(arr)) => {
            assert_eq!(arr.len(), 2);
            assert_eq!(arr[0], CoseHeaderValue::Int(42));
            assert_eq!(arr[1], CoseHeaderValue::Text("nested".to_string()));
        }
        _ => panic!("Expected array value"),
    }
}

#[test] 
fn test_verify_with_embedded_payload() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_bstr(b"test_payload").unwrap(); // embedded payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let verifier = MockCryptoVerifier::new(true);
    let result = msg.verify(&verifier, Some(b"external")).expect("should verify");
    assert!(result);
}

#[test]
fn test_verify_detached_payload_missing() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap(); // detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let verifier = MockCryptoVerifier::new(true);
    let result = msg.verify(&verifier, None);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("payload") && err_msg.contains("detached"));
}

#[test]
fn test_verify_detached() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let verifier = MockCryptoVerifier::new(false);
    let result = msg.verify_detached(&verifier, b"external_payload", Some(b"aad"))
        .expect("should call verify_detached");
    assert!(!result);
}

#[test]
fn test_verify_detached_streaming() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let payload_data = b"streaming_payload_data";
    let mut reader = SizedReader::new(Cursor::new(payload_data.to_vec()), payload_data.len() as u64);
    
    let verifier = MockCryptoVerifier::new(true);
    let result = msg.verify_detached_streaming(&verifier, &mut reader, None)
        .expect("should verify streaming");
    assert!(result);
}

#[test]
fn test_verify_detached_read() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let payload_data = b"read_payload_data";
    let mut reader = Cursor::new(payload_data);
    
    let verifier = MockCryptoVerifier::new(true);
    let result = msg.verify_detached_read(&verifier, &mut reader, Some(b"external"))
        .expect("should verify read");
    assert!(result);
}

#[test]
fn test_verify_streaming_payload() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let payload = Arc::new(MockStreamingPayload::new(b"streaming_data".to_vec()));
    let verifier = MockCryptoVerifier::new(false);
    let result = msg.verify_streaming(&verifier, payload, None)
        .expect("should verify streaming payload");
    assert!(!result);
}

#[test]
fn test_encode_with_embedded_payload() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_bstr(b"embedded_payload").unwrap(); // embedded
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let encoded = msg.encode(false).expect("should encode");
    let reparsed = CoseSign1Message::parse(&encoded).expect("should reparse");
    assert_eq!(reparsed.payload, Some(b"embedded_payload".to_vec()));
}

#[test]
fn test_unknown_cbor_type_skip() {
    // Test the "skip unknown types" path in decode_header_value
    // This is challenging to test directly since we need an unknown CborType
    // We'll create a scenario where the decoder might encounter unexpected data
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(99).unwrap();
    // This will be treated as Int type, but tests the value parsing path
    encoder.encode_i64(i64::MAX).unwrap(); // Large positive int
    
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse with large int");
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(99)), Some(&CoseHeaderValue::Int(i64::MAX)));
}

#[test]
fn test_uint_header_value_conversion() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    encoder.encode_map(2).unwrap();
    
    // Small uint that fits in i64
    encoder.encode_i64(1).unwrap();
    encoder.encode_u64(100).unwrap();
    
    // Large uint that doesn't fit in i64 (> i64::MAX)
    encoder.encode_i64(2).unwrap();
    encoder.encode_u64((i64::MAX as u64) + 1).unwrap();
    
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse uints");
    
    // Small uint becomes Int
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(100)));
    
    // Large uint stays as Uint
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(2)), Some(&CoseHeaderValue::Uint((i64::MAX as u64) + 1)));
}
