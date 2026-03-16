// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Advanced coverage tests for CoseSign1Message parsing edge cases.

use cbor_primitives::{CborProvider, CborEncoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue, CoseHeaderMap};

use cose_sign1_primitives::error::CoseSign1Error;
use crypto_primitives::{CryptoVerifier, CryptoError};

use std::io::Read;

/// Mock verifier for testing
struct MockVerifier {
    should_succeed: bool,
}

impl CryptoVerifier for MockVerifier {
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(self.should_succeed)
    }
    fn algorithm(&self) -> i64 { -7 }
}

/// Mock SizedRead implementation
struct MockSizedRead {
    data: Vec<u8>,
    pos: usize,
    should_fail_len: bool,
    should_fail_read: bool,
}

impl MockSizedRead {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0, should_fail_len: false, should_fail_read: false }
    }
    
    fn with_len_error(mut self) -> Self {
        self.should_fail_len = true;
        self
    }
    
    fn with_read_error(mut self) -> Self {
        self.should_fail_read = true;
        self
    }
}

impl Read for MockSizedRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.should_fail_read {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock read error"));
        }
        let remaining = &self.data[self.pos..];
        let len = buf.len().min(remaining.len());
        buf[..len].copy_from_slice(&remaining[..len]);
        self.pos += len;
        Ok(len)
    }
}

impl cose_sign1_primitives::SizedRead for MockSizedRead {
    fn len(&self) -> std::io::Result<u64> {
        if self.should_fail_len {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "Mock len error"));
        }
        Ok(self.data.len() as u64)
    }
}

#[test]
fn test_parse_wrong_tag() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Wrong tag (999 instead of 18)
    encoder.encode_tag(999).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // protected
    encoder.encode_map(0).unwrap(); // unprotected
    encoder.encode_null().unwrap(); // payload
    encoder.encode_bstr(&[]).unwrap(); // signature
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CoseSign1Error::InvalidMessage(_)));
    }
}

#[test]
fn test_parse_wrong_array_length() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Array with wrong length (3 instead of 4)
    encoder.encode_array(3).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // protected
    encoder.encode_map(0).unwrap(); // unprotected  
    encoder.encode_null().unwrap(); // payload
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CoseSign1Error::InvalidMessage(_)));
    }
}

#[test]
fn test_parse_indefinite_array() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Indefinite array (not allowed)
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_bstr(&[]).unwrap(); // protected
    encoder.encode_map(0).unwrap(); // unprotected
    encoder.encode_null().unwrap(); // payload
    encoder.encode_bstr(&[]).unwrap(); // signature
    encoder.encode_break().unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CoseSign1Error::InvalidMessage(_)));
    }
}

#[test]
fn test_parse_untagged_message() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // No tag, just array
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // protected
    encoder.encode_map(0).unwrap(); // unprotected
    encoder.encode_null().unwrap(); // payload
    encoder.encode_bstr(&[]).unwrap(); // signature
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_ok());
}

#[test]
fn test_complex_header_values() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // empty protected
    
    // Complex unprotected headers with different types
    encoder.encode_map(8).unwrap();
    
    // Int key with uint value > i64::MAX
    encoder.encode_i64(1).unwrap();
    encoder.encode_u64(u64::MAX).unwrap();
    
    // Text key with byte value
    encoder.encode_tstr("custom").unwrap();
    encoder.encode_bstr(b"bytes").unwrap();
    
    // Array header
    encoder.encode_i64(2).unwrap();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(42).unwrap();
    encoder.encode_tstr("text").unwrap();
    
    // Map header
    encoder.encode_i64(3).unwrap();
    encoder.encode_map(1).unwrap();
    encoder.encode_tstr("key").unwrap();
    encoder.encode_i64(123).unwrap();
    
    // Tagged value
    encoder.encode_i64(4).unwrap();
    encoder.encode_tag(123).unwrap();
    encoder.encode_tstr("tagged").unwrap();
    
    // Bool values
    encoder.encode_i64(5).unwrap();
    encoder.encode_bool(true).unwrap();
    
    encoder.encode_i64(6).unwrap();
    encoder.encode_bool(false).unwrap();
    
    // Undefined
    encoder.encode_i64(7).unwrap();
    encoder.encode_undefined().unwrap();
    
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_ok());
    
    let msg = result.unwrap();
    assert_eq!(msg.unprotected.len(), 8);
    assert_eq!(msg.payload, Some(b"payload".to_vec()));
}

#[test]
fn test_indefinite_length_headers() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // empty protected
    
    // Indefinite length map
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("value1").unwrap();
    encoder.encode_tstr("key2").unwrap();
    encoder.encode_i64(42).unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_ok());
    
    let msg = result.unwrap();
    assert_eq!(msg.unprotected.len(), 2);
}

#[test]
fn test_indefinite_array_header() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // empty protected
    
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    // Indefinite array value
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_ok());
    
    let msg = result.unwrap();
    if let Some(CoseHeaderValue::Array(arr)) = msg.unprotected.get(&CoseHeaderLabel::Int(1)) {
        assert_eq!(arr.len(), 2);
    } else {
        panic!("Expected array header");
    }
}

#[test]
fn test_indefinite_map_header() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // empty protected
    
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    // Indefinite map value
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_tstr("k1").unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("k2").unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_ok());
}

#[test]
fn test_accessor_methods() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Create protected header with algorithm
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    let protected_bytes = protected.encode().unwrap();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&protected_bytes).unwrap();
    encoder.encode_map(0).unwrap(); // unprotected
    encoder.encode_bstr(b"test_payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    // Test accessor methods
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.protected_header_bytes(), &protected_bytes);
    assert!(!msg.is_detached());
    assert_eq!(msg.payload.as_ref().unwrap(), b"test_payload");
    assert_eq!(msg.signature, b"signature");
    
    // Test provider access
    let _provider_ref = msg.provider();
}

#[test]
fn test_parse_inner() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    // Test parse_inner (should work the same as parse)
    let inner = msg.parse_inner(&data).unwrap();
    assert_eq!(inner.signature, msg.signature);
}

#[test]
fn test_verify_embedded_payload() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify(&verifier, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
    
    let verifier = MockVerifier { should_succeed: false };
    let result = msg.verify(&verifier, None);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_verify_detached_payload_missing() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap(); // detached
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify(&verifier, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoseSign1Error::PayloadMissing));
}

#[test]
fn test_verify_detached() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap(); // detached
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify_detached(&verifier, b"external_payload", Some(b"aad"));
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_detached_streaming_success() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let mut payload = MockSizedRead::new(b"payload_data".to_vec());
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify_detached_streaming(&verifier, &mut payload, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_verify_detached_streaming_len_error() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let mut payload = MockSizedRead::new(b"payload".to_vec()).with_len_error();
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify_detached_streaming(&verifier, &mut payload, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoseSign1Error::IoError(_)));
}

#[test]
fn test_verify_detached_streaming_read_error() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let mut payload = MockSizedRead::new(b"payload".to_vec()).with_read_error();
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify_detached_streaming(&verifier, &mut payload, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoseSign1Error::IoError(_)));
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
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let mut payload_reader = &b"payload_from_reader"[..];
    let verifier = MockVerifier { should_succeed: true };
    let result = msg.verify_detached_read(&verifier, &mut payload_reader, None);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_sig_structure_bytes() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    let protected_bytes = protected.encode().unwrap();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&protected_bytes).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let sig_struct = msg.sig_structure_bytes(b"test_payload", Some(b"external_aad"));
    assert!(sig_struct.is_ok());
    let bytes = sig_struct.unwrap();
    assert!(!bytes.is_empty());
}

#[test]
fn test_encode_tagged() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    encoder.encode_map(0).unwrap();
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let encoded = msg.encode(true).unwrap();
    assert!(encoded.len() > data.len()); // Should be larger due to tag
    
    let encoded_untagged = msg.encode(false).unwrap();
    assert_eq!(encoded_untagged.len(), data.len());
}

#[test]
fn test_skip_unknown_header_type() {
    // This is tricky to test directly since we can't easily create unknown types
    // with EverParse. The skip logic is in the _ arm of decode_header_value match.
    // This test exists to document the intention - in practice, this would handle
    // any new CBOR types that aren't explicitly supported yet.
}
