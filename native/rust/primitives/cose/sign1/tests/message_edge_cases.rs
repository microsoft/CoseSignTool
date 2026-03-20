// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for CoseSign1Message parsing and accessor methods.
//!
//! Tests uncovered paths in message.rs including:
//! - Tagged vs untagged parsing  
//! - Empty payload handling
//! - Wrong-length arrays
//! - Accessor methods (alg, kid, is_detached, etc)
//! - Provider access

use cbor_primitives::{CborDecoder, CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    algorithms::{COSE_SIGN1_TAG, ES256},
    error::CoseSign1Error,
    CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, CoseSign1Message,
};
use std::sync::Arc;

/// Helper to create valid COSE_Sign1 CBOR bytes.
fn create_valid_cose_sign1(
    tagged: bool,
    empty_payload: bool,
    protected_headers: Option<CoseHeaderMap>,
) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    if tagged {
        encoder.encode_tag(COSE_SIGN1_TAG).unwrap();
    }

    encoder.encode_array(4).unwrap();

    // 1. Protected header
    let protected_bytes = if let Some(headers) = protected_headers {
        headers.encode().unwrap()
    } else {
        Vec::new()
    };
    encoder.encode_bstr(&protected_bytes).unwrap();

    // 2. Unprotected header (empty map)
    encoder.encode_map(0).unwrap();

    // 3. Payload
    if empty_payload {
        encoder.encode_null().unwrap();
    } else {
        encoder.encode_bstr(b"test payload").unwrap();
    }

    // 4. Signature
    encoder.encode_bstr(b"dummy_signature").unwrap();

    encoder.into_bytes()
}

/// Helper to create CBOR with wrong tag.
fn create_wrong_tag_cose_sign1() -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    encoder.encode_tag(999u64).unwrap(); // Wrong tag
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap(); // Unprotected
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature

    encoder.into_bytes()
}

/// Helper to create CBOR with wrong array length.
fn create_wrong_length_array(len: usize) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    encoder.encode_array(len).unwrap();

    if len >= 1 {
        encoder.encode_bstr(&[]).unwrap(); // Protected
    }
    if len >= 2 {
        encoder.encode_map(0).unwrap(); // Unprotected
    }
    if len >= 3 {
        encoder.encode_null().unwrap(); // Payload
    }
    if len >= 4 {
        encoder.encode_bstr(b"sig").unwrap(); // Signature
    }
    // Add extra elements
    for _ in 4..len {
        encoder.encode_null().unwrap();
    }

    encoder.into_bytes()
}

/// Helper to create indefinite-length array (not allowed).
fn create_indefinite_array() -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();

    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap(); // Unprotected
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    encoder.encode_break().unwrap();

    encoder.into_bytes()
}

#[test]
fn test_parse_tagged_message() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(msg.payload().is_some());
    assert_eq!(msg.payload().unwrap(), b"test payload");
}

#[test]
fn test_parse_untagged_message() {
    let bytes = create_valid_cose_sign1(false, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(msg.payload().is_some());
    assert_eq!(msg.payload().unwrap(), b"test payload");
}

#[test]
fn test_parse_empty_payload_detached() {
    let bytes = create_valid_cose_sign1(true, true, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(msg.payload().is_none());
    assert!(msg.is_detached());
}

#[test]
fn test_parse_embedded_payload() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(msg.payload().is_some());
    assert!(!msg.is_detached());
}

#[test]
fn test_parse_wrong_tag_error() {
    let bytes = create_wrong_tag_cose_sign1();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("unexpected COSE tag"));
            assert!(msg.contains("expected 18"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_parse_wrong_array_length_3() {
    let bytes = create_wrong_length_array(3);
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must have 4 elements"));
            assert!(msg.contains("got 3"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_parse_wrong_array_length_5() {
    let bytes = create_wrong_length_array(5);
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must have 4 elements"));
            assert!(msg.contains("got 5"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_parse_indefinite_array_error() {
    let bytes = create_indefinite_array();
    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("COSE_Sign1 must be definite-length array"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_alg_accessor_with_protected_header() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let bytes = create_valid_cose_sign1(true, false, Some(protected));
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    assert_eq!(msg.alg(), Some(ES256));
}

#[test]
fn test_alg_accessor_no_alg() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    assert_eq!(msg.alg(), None);
}

#[test]
fn test_protected_headers_accessor() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);
    protected.set_kid(b"test_kid");

    let bytes = create_valid_cose_sign1(true, false, Some(protected));
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let headers = msg.protected_headers();
    assert_eq!(headers.alg(), Some(ES256));
    assert_eq!(headers.kid(), Some(b"test_kid".as_slice()));
}

#[test]
fn test_protected_header_bytes() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let bytes = create_valid_cose_sign1(true, false, Some(protected.clone()));
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let raw_bytes = msg.protected_header_bytes();
    let expected_bytes = protected.encode().unwrap();
    assert_eq!(raw_bytes, expected_bytes);
}

#[test]
fn test_provider_accessor() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    // Just ensure the provider accessor works and returns the expected type
    let _provider = msg.provider();
    // Provider exists and can be accessed
}

#[test]
fn test_parse_inner_message() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    // Parse same bytes as "inner" message
    let inner = msg.parse_inner(&bytes).unwrap();
    assert_eq!(msg.payload(), inner.payload());
    assert_eq!(msg.signature(), inner.signature());
}

#[test]
fn test_debug_formatting() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
    assert!(debug_str.contains("protected"));
    assert!(debug_str.contains("unprotected"));
    assert!(debug_str.contains("payload"));
    assert!(debug_str.contains("signature"));
}

#[test]
fn test_verify_with_missing_payload() {
    // Create detached message (null payload)
    let bytes = create_valid_cose_sign1(true, true, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    // Mock verifier (will never be called due to early error)
    struct MockVerifier;
    impl crypto_primitives::CryptoVerifier for MockVerifier {
        fn verify(
            &self,
            _data: &[u8],
            _signature: &[u8],
        ) -> Result<bool, crypto_primitives::CryptoError> {
            Ok(true)
        }
        fn algorithm(&self) -> i64 {
            -7 // ES256
        }
    }

    let verifier = MockVerifier;
    let result = msg.verify(&verifier, None);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadMissing => {}
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_encode_tagged() {
    let bytes = create_valid_cose_sign1(false, false, None); // Untagged input
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let encoded = msg.encode(true).unwrap(); // Encode with tag

    // Verify it parses back correctly
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert_eq!(msg.payload(), reparsed.payload());
    assert_eq!(msg.signature(), reparsed.signature());
}

#[test]
fn test_encode_untagged() {
    let bytes = create_valid_cose_sign1(true, false, None); // Tagged input
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let encoded = msg.encode(false).unwrap(); // Encode without tag

    // Verify it parses back correctly
    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert_eq!(msg.payload(), reparsed.payload());
    assert_eq!(msg.signature(), reparsed.signature());
}

#[test]
fn test_encode_with_detached_payload() {
    let bytes = create_valid_cose_sign1(true, true, None); // Detached
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let encoded = msg.encode(true).unwrap();

    let reparsed = CoseSign1Message::parse(&encoded).unwrap();
    assert!(reparsed.is_detached());
    assert_eq!(msg.signature(), reparsed.signature());
}

#[test]
fn test_sig_structure_bytes() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let payload = b"test payload for sig structure";
    let external_aad = Some(b"additional auth data".as_slice());

    let sig_structure = msg.sig_structure_bytes(payload, external_aad).unwrap();

    // Verify it's valid CBOR
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&sig_structure);
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4)); // [context, protected, external_aad, payload]
}

#[test]
fn test_clone_message() {
    let bytes = create_valid_cose_sign1(true, false, None);
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    let cloned = msg.clone();
    assert_eq!(msg.payload(), cloned.payload());
    assert_eq!(msg.signature(), cloned.signature());
    assert_eq!(
        msg.protected_header_bytes(),
        cloned.protected_header_bytes()
    );
}
