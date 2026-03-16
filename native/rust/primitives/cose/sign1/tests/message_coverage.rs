// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for CoseSign1Message.

use cbor_primitives::{CborProvider, CborEncoder, CborDecoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;

/// Helper to create CBOR bytes for testing.
fn create_cbor(tagged: bool, array_len: Option<u32>, wrong_tag: bool) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    if tagged {
        let tag = if wrong_tag { 999u64 } else { COSE_SIGN1_TAG };
        encoder.encode_tag(tag).unwrap();
    }
    
    if let Some(len) = array_len {
        encoder.encode_array(len as usize).unwrap();
    } else {
        encoder.encode_array_indefinite_begin().unwrap();
    }
    
    // Protected header (empty)
    encoder.encode_bstr(&[]).unwrap();
    
    // Unprotected header (empty map)
    encoder.encode_map(0).unwrap();
    
    if array_len.unwrap_or(4) >= 3 {
        // Payload (null - detached)
        encoder.encode_null().unwrap();
    }
    
    if array_len.unwrap_or(4) >= 4 {
        // Signature
        encoder.encode_bstr(b"dummy_signature").unwrap();
    }
    
    if array_len.is_none() {
        encoder.encode_break().unwrap();
    }
    
    encoder.into_bytes()
}

#[test]
fn test_parse_tagged_message() {
    let bytes = create_cbor(true, Some(4), false);
    let msg = CoseSign1Message::parse(&bytes).expect("should parse tagged");
    assert!(msg.is_detached());
    assert_eq!(msg.signature, b"dummy_signature");
}

#[test] 
fn test_parse_untagged_message() {
    let bytes = create_cbor(false, Some(4), false);
    let msg = CoseSign1Message::parse(&bytes).expect("should parse untagged");
    assert!(msg.is_detached());
}

#[test]
fn test_parse_wrong_tag() {
    let bytes = create_cbor(true, Some(4), true);
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unexpected COSE tag"));
}

#[test]
fn test_parse_wrong_array_length() {
    let bytes = create_cbor(false, Some(3), false);
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("must have 4 elements"));
}

#[test]
fn test_parse_indefinite_array() {
    let bytes = create_cbor(false, None, false);
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("definite-length array"));
}

#[test]
fn test_parse_non_array() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_tstr("not an array").unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_parse_with_protected_headers() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    
    // Protected header with algorithm
    let mut protected_encoder = provider.encoder();
    protected_encoder.encode_map(1).unwrap();
    protected_encoder.encode_i64(1).unwrap(); // alg label
    protected_encoder.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = protected_encoder.into_bytes();
    encoder.encode_bstr(&protected_bytes).unwrap();
    
    encoder.encode_map(0).unwrap();
    encoder.encode_bstr(b"test payload").unwrap(); // Embedded payload
    encoder.encode_bstr(b"dummy_signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse with protected");
    assert_eq!(msg.alg(), Some(-7));
    assert!(!msg.is_detached());
    assert_eq!(msg.payload, Some(b"test payload".to_vec()));
}

#[test]
fn test_accessor_methods() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    
    // Protected header with multiple fields
    let mut protected_encoder = provider.encoder();
    protected_encoder.encode_map(2).unwrap();
    protected_encoder.encode_i64(1).unwrap(); // alg
    protected_encoder.encode_i64(-7).unwrap();
    protected_encoder.encode_i64(4).unwrap(); // kid
    protected_encoder.encode_bstr(b"test-key-id").unwrap();
    let protected_bytes = protected_encoder.into_bytes();
    encoder.encode_bstr(&protected_bytes).unwrap();
    
    // Unprotected header
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(3).unwrap(); // content-type
    encoder.encode_i64(42).unwrap();
    
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"signature").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    // Test accessors
    assert_eq!(msg.alg(), Some(-7));
    assert!(!msg.is_detached());
    assert_eq!(msg.protected_header_bytes(), &protected_bytes);
    assert_eq!(msg.protected_headers().alg(), Some(-7));
    
    // Test provider access
    let _provider = msg.provider();
    
    // Test parse_inner
    let _inner = msg.parse_inner(&bytes).expect("should parse inner");
}

#[test]
fn test_encode_roundtrip() {
    let bytes = create_cbor(true, Some(4), false);
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    // Test tagged encoding
    let encoded_tagged = msg.encode(true).expect("should encode tagged");
    let reparsed = CoseSign1Message::parse(&encoded_tagged).expect("should reparse");
    assert_eq!(msg.is_detached(), reparsed.is_detached());
    
    // Test untagged encoding
    let encoded_untagged = msg.encode(false).expect("should encode untagged");
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&encoded_untagged);
    let len = decoder.decode_array_len().expect("should be array");
    assert_eq!(len, Some(4)); // Direct array, no tag
}

#[test]
fn test_decode_header_value_types() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    // Unprotected header with various value types
    encoder.encode_map(6).unwrap();
    
    // Large uint (> i64::MAX)
    encoder.encode_i64(100).unwrap();
    encoder.encode_u64(u64::MAX).unwrap();
    
    // Text string  
    encoder.encode_i64(101).unwrap();
    encoder.encode_tstr("test").unwrap();
    
    // Boolean
    encoder.encode_i64(102).unwrap();
    encoder.encode_bool(true).unwrap();
    
    // Undefined (skipping float since EverParse doesn't support f64)
    encoder.encode_i64(103).unwrap();
    encoder.encode_undefined().unwrap();
    
    // Tagged value
    encoder.encode_i64(105).unwrap();
    encoder.encode_tag(42).unwrap();
    encoder.encode_tstr("tagged").unwrap();
    
    // Array
    encoder.encode_i64(106).unwrap();
    encoder.encode_array(1).unwrap();
    encoder.encode_i64(123).unwrap();
    
    encoder.encode_bstr(b"payload").unwrap(); // payload position
    encoder.encode_bstr(b"sig").unwrap(); // signature position
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse types");
    
    // Verify parsed values
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(100)), Some(&CoseHeaderValue::Uint(u64::MAX)));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(101)), Some(&CoseHeaderValue::Text("test".to_string())));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(102)), Some(&CoseHeaderValue::Bool(true)));
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(103)), Some(&CoseHeaderValue::Undefined));
    
    match msg.unprotected.get(&CoseHeaderLabel::Int(105)) {
        Some(CoseHeaderValue::Tagged(42, inner)) => {
            assert_eq!(**inner, CoseHeaderValue::Text("tagged".to_string()));
        }
        _ => panic!("Expected tagged value"),
    }
    
    match msg.unprotected.get(&CoseHeaderLabel::Int(106)) {
        Some(CoseHeaderValue::Array(arr)) => assert_eq!(arr.len(), 1),
        _ => panic!("Expected array"),
    }
}

#[test]
fn test_decode_indefinite_structures() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    // Indefinite unprotected header
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(-7).unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse indefinite map");
    assert_eq!(msg.unprotected.get(&CoseHeaderLabel::Int(1)), Some(&CoseHeaderValue::Int(-7)));
}

#[test]
fn test_decode_nested_indefinite() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(200).unwrap();
    
    // Indefinite array
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap(); 
    encoder.encode_break().unwrap();
    
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    match msg.unprotected.get(&CoseHeaderLabel::Int(200)) {
        Some(CoseHeaderValue::Array(arr)) => assert_eq!(arr.len(), 2),
        _ => panic!("Expected array"),
    }
}

#[test]
fn test_invalid_header_label() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_bstr(b"invalid").unwrap(); // Invalid label type
    encoder.encode_i64(42).unwrap();
    
    encoder.encode_null().unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid header label"));
}

#[test]
fn test_sig_structure_bytes() {
    let bytes = create_cbor(true, Some(4), false);
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    
    let payload = b"test payload";
    let external_aad = Some(b"external".as_slice());
    
    let sig_struct = msg.sig_structure_bytes(payload, external_aad)
        .expect("should create sig structure");
    
    // Should be valid CBOR array
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&sig_struct);
    let len = decoder.decode_array_len().expect("should be array");
    assert_eq!(len, Some(4)); // ["Signature1", protected, external_aad, payload]
}
