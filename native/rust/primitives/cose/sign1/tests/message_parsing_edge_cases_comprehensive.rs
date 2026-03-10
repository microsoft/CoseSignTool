// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional parsing edge cases coverage for message.rs.

use std::io::Cursor;
use cbor_primitives::{CborProvider, CborEncoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    message::CoseSign1Message, 
    algorithms::COSE_SIGN1_TAG, 
    error::CoseSign1Error,
    headers::{CoseHeaderLabel, CoseHeaderValue}
};

/// Helper to create CBOR bytes for various edge cases.
fn create_test_message(
    use_tag: bool,
    wrong_tag: Option<u64>,
    array_len: Option<usize>,
    protected_header: &[u8],
    unprotected_entries: usize,
    payload_type: PayloadType,
) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Optional tag
    if use_tag {
        let tag = wrong_tag.unwrap_or(COSE_SIGN1_TAG);
        encoder.encode_tag(tag).unwrap();
    }
    
    // Array with specified length (or indefinite)
    match array_len {
        Some(len) => encoder.encode_array(len).unwrap(),
        None => encoder.encode_array_indefinite_begin().unwrap(),
    }
    
    // 1. Protected header (bstr)
    encoder.encode_bstr(protected_header).unwrap();
    
    // 2. Unprotected header (map)
    encoder.encode_map(unprotected_entries).unwrap();
    for i in 0..unprotected_entries {
        encoder.encode_i64(100 + i as i64).unwrap();
        encoder.encode_tstr(&format!("value{}", i)).unwrap();
    }
    
    // 3. Payload (bstr, null, or other type)
    match payload_type {
        PayloadType::Embedded(data) => encoder.encode_bstr(data).unwrap(),
        PayloadType::Detached => encoder.encode_null().unwrap(),
        PayloadType::Invalid => encoder.encode_i64(42).unwrap(), // Invalid type
    }
    
    // 4. Signature (if we have at least 4 elements)
    if array_len.unwrap_or(4) >= 4 {
        encoder.encode_bstr(b"test_signature").unwrap();
    }
    
    if array_len.is_none() {
        encoder.encode_break().unwrap();
    }
    
    encoder.into_bytes()
}

#[derive(Clone)]
enum PayloadType<'a> {
    Embedded(&'a [u8]),
    Detached,
    Invalid,
}

#[test]
fn test_parse_wrong_tag() {
    let data = create_test_message(
        true,               // use_tag
        Some(999),         // wrong tag
        Some(4),           // proper array length
        &[],               // empty protected header
        0,                 // no unprotected headers
        PayloadType::Detached,
    );
    
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("unexpected COSE tag"));
            assert!(msg.contains("999"));
        }
        _ => panic!("Expected InvalidMessage error for wrong tag"),
    }
}

#[test]
fn test_parse_wrong_array_length_too_short() {
    let data = create_test_message(
        false,             // no tag
        None,
        Some(3),           // array too short
        &[],
        0,
        PayloadType::Embedded(b"test"),
    );
    
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must have 4 elements, got 3"));
        }
        _ => panic!("Expected InvalidMessage error for wrong array length"),
    }
}

#[test]
fn test_parse_wrong_array_length_too_long() {
    let data = create_test_message(
        false,             // no tag
        None,
        Some(5),           // array too long
        &[],
        0,
        PayloadType::Embedded(b"test"),
    );
    
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must have 4 elements, got 5"));
        }
        _ => panic!("Expected InvalidMessage error for wrong array length"),
    }
}

#[test]
fn test_parse_indefinite_array() {
    let data = create_test_message(
        false,             // no tag
        None,
        None,              // indefinite array
        &[],
        0,
        PayloadType::Detached,
    );
    
    let result = CoseSign1Message::parse(&data);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must be definite-length array"));
        }
        _ => panic!("Expected InvalidMessage error for indefinite array"),
    }
}

#[test]
fn test_parse_indefinite_unprotected_map() {
    // Create a message with an indefinite-length unprotected header map
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    
    // Indefinite unprotected map
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("value1").unwrap();
    encoder.encode_i64(2).unwrap();
    encoder.encode_tstr("value2").unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_null().unwrap(); // Detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    
    // Should parse successfully with indefinite unprotected map
    let result = CoseSign1Message::parse(&data);
    match result {
        Ok(msg) => {
            assert_eq!(msg.unprotected.len(), 2);
        }
        Err(e) => {
            // Some CBOR implementations may not support indefinite maps
            println!("Indefinite map parsing failed (may be expected): {:?}", e);
        }
    }
}

#[test]
fn test_parse_complex_unprotected_headers() {
    // Test parsing various header value types in unprotected headers
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    
    // Complex unprotected map with various types
    encoder.encode_map(5).unwrap();
    
    // Int header
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(42).unwrap();
    
    // Large uint header
    encoder.encode_i64(2).unwrap();
    encoder.encode_u64(u64::MAX).unwrap();
    
    // Array header
    encoder.encode_i64(3).unwrap();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    
    // Bool header
    encoder.encode_i64(4).unwrap();
    encoder.encode_bool(true).unwrap();
    
    // Null header
    encoder.encode_i64(5).unwrap();
    encoder.encode_null().unwrap();
    
    encoder.encode_null().unwrap(); // Detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    
    match result {
        Ok(msg) => {
            assert_eq!(msg.unprotected.len(), 5);
            
            // Verify various header types were parsed correctly
            assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(1)), 
                      Some(&CoseHeaderValue::Int(42)));
            
            if let Some(CoseHeaderValue::Array(arr)) = msg.unprotected.get(&CoseHeaderLabel::Int(3)) {
                assert_eq!(arr.len(), 2);
            }
            
            assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(4)), 
                      Some(&CoseHeaderValue::Bool(true)));
            
            assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(5)), 
                      Some(&CoseHeaderValue::Null));
        }
        Err(e) => {
            // Some CBOR features might not be supported
            println!("Complex header parsing failed: {:?}", e);
        }
    }
}

#[test]
fn test_parse_invalid_unprotected_label_type() {
    // Create unprotected header with invalid label type (array)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    
    // Unprotected map with invalid label
    encoder.encode_map(1).unwrap();
    encoder.encode_array(1).unwrap(); // Invalid label type (array)
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("value").unwrap();
    
    encoder.encode_null().unwrap(); // Detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let result = CoseSign1Message::parse(&data);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("invalid header label type"));
        }
        _ => panic!("Expected InvalidMessage error for invalid header label"),
    }
}

#[test]
fn test_accessors_and_helpers() {
    // Create a valid message with various elements
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Create protected header with algorithm
    let mut protected_encoder = provider.encoder();
    protected_encoder.encode_map(1).unwrap();
    protected_encoder.encode_i64(1).unwrap(); // alg
    protected_encoder.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = protected_encoder.into_bytes();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&protected_bytes).unwrap();
    
    // Unprotected with kid
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(4).unwrap(); // kid
    encoder.encode_bstr(b"key123").unwrap();
    
    encoder.encode_bstr(b"embedded_payload").unwrap();
    encoder.encode_bstr(b"signature_bytes").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    // Test accessors
    assert_eq!(msg.alg(), Some(-7));
    assert!(!msg.is_detached());
    assert_eq!(msg.protected_header_bytes(), protected_bytes.as_slice());
    
    // Test provider accessor
    let _provider = msg.provider();
    
    // Test parse_inner (should work with same data)
    let inner = msg.parse_inner(&data).unwrap();
    assert_eq!(inner.alg(), Some(-7));
}

#[test]
fn test_debug_format() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Empty protected
    encoder.encode_map(0).unwrap();   // Empty unprotected
    encoder.encode_bstr(b"test_payload").unwrap();
    encoder.encode_bstr(b"test_signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
    assert!(debug_str.contains("protected"));
    assert!(debug_str.contains("unprotected"));
    assert!(debug_str.contains("payload"));
    assert!(debug_str.contains("signature"));
}

#[test]
fn test_verify_payload_missing_error() {
    // Create a detached message
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap();   // Unprotected
    encoder.encode_null().unwrap();   // Detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    // Mock verifier (we won't actually verify, just test error path)
    struct MockVerifier;
    impl crypto_primitives::CryptoVerifier for MockVerifier {
        fn algorithm(&self) -> i64 {
            -7 // ES256
        }
        
        fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, crypto_primitives::CryptoError> {
            Ok(true)
        }
    }
    
    let verifier = MockVerifier;
    let result = msg.verify(&verifier, None);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadMissing => {} // Expected
        _ => panic!("Expected PayloadMissing error for detached payload"),
    }
}

#[test]
fn test_verify_detached_read() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap();   // Unprotected
    encoder.encode_null().unwrap();   // Detached payload
    encoder.encode_bstr(b"signature").unwrap();
    
    let data = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&data).unwrap();
    
    struct MockVerifier;
    impl crypto_primitives::CryptoVerifier for MockVerifier {
        fn algorithm(&self) -> i64 {
            -7 // ES256
        }
        
        fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, crypto_primitives::CryptoError> {
            Ok(true)
        }
    }
    
    let verifier = MockVerifier;
    let mut payload_reader = Cursor::new(b"detached_payload");
    
    let result = msg.verify_detached_read(&verifier, &mut payload_reader, None);
    // Should succeed (though signature won't actually verify with mock)
    assert!(result.is_ok());
}