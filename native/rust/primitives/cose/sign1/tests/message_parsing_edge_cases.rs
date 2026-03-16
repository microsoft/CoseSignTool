// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive message parsing edge cases and accessor tests.

use cbor_primitives::{CborProvider, CborEncoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderValue, CoseHeaderMap, ProtectedHeader, ContentType};
use cose_sign1_primitives::algorithms::COSE_SIGN1_TAG;
use cose_sign1_primitives::error::CoseSign1Error;

#[test]
fn test_parse_malformed_cbor() {
    // Invalid CBOR bytes
    let invalid_cbor = vec![0xFF, 0xFE, 0xFD]; // Invalid CBOR
    let result = CoseSign1Message::parse(&invalid_cbor);
    match result {
        Err(CoseSign1Error::CborError(_)) => {}
        _ => panic!("Expected CborError for malformed CBOR"),
    }
}

#[test]
fn test_parse_wrong_cbor_tag() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Wrong tag (not 18)
    encoder.encode_tag(999).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap(); // Unprotected
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    
    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert!(msg.contains("unexpected COSE tag"));
            assert!(msg.contains("expected 18"));
            assert!(msg.contains("got 999"));
        }
        _ => panic!("Expected InvalidMessage for wrong tag"),
    }
}

#[test]
fn test_parse_incorrect_array_length() {
    let provider = EverParseCborProvider;
    
    // Test various incorrect array lengths
    for bad_len in [0, 1, 2, 3, 5, 10] {
        let mut encoder = provider.encoder();
        encoder.encode_array(bad_len).unwrap();
        
        // Add elements up to the bad length
        for i in 0..bad_len {
            match i {
                0 => encoder.encode_bstr(&[]).unwrap(),
                1 => encoder.encode_map(0).unwrap(),
                2 => encoder.encode_null().unwrap(),
                3 => encoder.encode_bstr(b"sig").unwrap(),
                _ => encoder.encode_null().unwrap(),
            }
        }
        
        let bytes = encoder.into_bytes();
        let result = CoseSign1Message::parse(&bytes);
        
        match result {
            Err(CoseSign1Error::InvalidMessage(msg)) => {
                assert!(msg.contains("COSE_Sign1 must have 4 elements"));
                assert!(msg.contains(&format!("got {}", bad_len)));
            }
            _ => panic!("Expected InvalidMessage for wrong array length {}", bad_len),
        }
    }
}

#[test]
fn test_parse_indefinite_length_array() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array_indefinite_begin().unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap(); // Unprotected
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    encoder.encode_break().unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CoseSign1Message::parse(&bytes);
    
    match result {
        Err(CoseSign1Error::InvalidMessage(msg)) => {
            assert_eq!(msg, "COSE_Sign1 must be definite-length array");
        }
        _ => panic!("Expected InvalidMessage for indefinite-length array"),
    }
}

#[test]
fn test_parse_both_tagged_and_untagged() {
    let provider = EverParseCborProvider;
    
    // Create valid COSE_Sign1 message data
    let mut encoder = provider.encoder();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected (empty)
    encoder.encode_map(0).unwrap(); // Unprotected (empty)
    encoder.encode_bstr(b"test payload").unwrap(); // Payload
    encoder.encode_bstr(b"test signature").unwrap(); // Signature
    let untagged_bytes = encoder.into_bytes();
    
    // Test untagged parsing
    let untagged_msg = CoseSign1Message::parse(&untagged_bytes).expect("should parse untagged");
    assert_eq!(untagged_msg.payload, Some(b"test payload".to_vec()));
    assert_eq!(untagged_msg.signature, b"test signature".to_vec());
    
    // Create tagged version
    let mut encoder = provider.encoder();
    encoder.encode_tag(COSE_SIGN1_TAG).unwrap();
    encoder.encode_raw(&untagged_bytes).unwrap();
    let tagged_bytes = encoder.into_bytes();
    
    // Test tagged parsing
    let tagged_msg = CoseSign1Message::parse(&tagged_bytes).expect("should parse tagged");
    assert_eq!(tagged_msg.payload, Some(b"test payload".to_vec()));
    assert_eq!(tagged_msg.signature, b"test signature".to_vec());
}

#[test]
fn test_accessor_methods_comprehensive() {
    let provider = EverParseCborProvider;
    
    // Create protected headers with specific values
    let mut protected_headers = CoseHeaderMap::new();
    protected_headers.set_alg(-7); // ES256
    protected_headers.set_kid(b"test-key-123");
    protected_headers.set_content_type(ContentType::Text("application/json".to_string()));
    protected_headers.insert(CoseHeaderLabel::Int(999), CoseHeaderValue::Text("custom".to_string()));
    
    let protected = ProtectedHeader::encode(protected_headers).expect("should encode protected");
    
    // Create unprotected headers
    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(CoseHeaderLabel::Int(100), CoseHeaderValue::Int(42));
    unprotected.insert(CoseHeaderLabel::Text("unprotected".to_string()), CoseHeaderValue::Bool(true));
    
    // Create message
    let msg = CoseSign1Message {
        protected,
        unprotected,
        payload: Some(b"test payload data".to_vec()),
        signature: b"signature_bytes".to_vec(),
    };
    
    // Test accessor methods
    assert_eq!(msg.alg(), Some(-7));
    assert!(!msg.is_detached());
    
    let protected_headers = msg.protected_headers();
    assert_eq!(protected_headers.alg(), Some(-7));
    assert_eq!(protected_headers.kid(), Some(b"test-key-123" as &[u8]));
    assert_eq!(protected_headers.content_type(), Some(ContentType::Text("application/json".to_string())));
    assert_eq!(
        protected_headers.get(&CoseHeaderLabel::Int(999)),
        Some(&CoseHeaderValue::Text("custom".to_string()))
    );
    
    let protected_bytes = msg.protected_header_bytes();
    assert!(!protected_bytes.is_empty());
    
    // Test provider access
    let provider_ref = msg.provider();
    assert_eq!(std::ptr::eq(provider_ref, &EverParseCborProvider), false); // Different instances but same type
}

#[test]
fn test_detached_payload_message() {
    let provider = EverParseCborProvider;
    
    // Create message with detached payload (null)
    let mut encoder = provider.encoder();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected (empty)
    encoder.encode_map(0).unwrap(); // Unprotected (empty)
    encoder.encode_null().unwrap(); // Payload (detached)
    encoder.encode_bstr(b"detached_signature").unwrap(); // Signature
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse detached message");
    
    assert!(msg.is_detached());
    assert_eq!(msg.payload, None);
    assert_eq!(msg.signature, b"detached_signature".to_vec());
}

#[test]
fn test_complex_unprotected_headers() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected (empty)
    
    // Complex unprotected headers map
    encoder.encode_map(5).unwrap();
    
    // Integer label with array value
    encoder.encode_i64(100).unwrap();
    encoder.encode_array(3).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("nested").unwrap();
    encoder.encode_bool(true).unwrap();
    
    // Text label with map value
    encoder.encode_tstr("nested_map").unwrap();
    encoder.encode_map(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("inner1").unwrap();
    encoder.encode_tstr("key2").unwrap();
    encoder.encode_i64(999).unwrap();
    
    // Tagged value
    encoder.encode_i64(101).unwrap();
    encoder.encode_tag(999).unwrap();
    encoder.encode_bstr(b"tagged_content").unwrap();
    
    // Bytes value
    encoder.encode_i64(102).unwrap();
    encoder.encode_bstr(b"\x00\x01\x02\xFF").unwrap();
    
    // Undefined value
    encoder.encode_i64(103).unwrap();
    encoder.encode_undefined().unwrap();
    
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse complex headers");
    
    // Verify complex header parsing
    let headers = &msg.unprotected;
    
    // Check array header
    if let Some(CoseHeaderValue::Array(arr)) = headers.get(&CoseHeaderLabel::Int(100)) {
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], CoseHeaderValue::Int(1));
        assert_eq!(arr[1], CoseHeaderValue::Text("nested".to_string()));
        assert_eq!(arr[2], CoseHeaderValue::Bool(true));
    } else {
        panic!("Expected array header");
    }
    
    // Check map header
    if let Some(CoseHeaderValue::Map(map_pairs)) = headers.get(&CoseHeaderLabel::Text("nested_map".to_string())) {
        assert_eq!(map_pairs.len(), 2);
        assert!(map_pairs.contains(&(CoseHeaderLabel::Int(1), CoseHeaderValue::Text("inner1".to_string()))));
        assert!(map_pairs.contains(&(CoseHeaderLabel::Text("key2".to_string()), CoseHeaderValue::Int(999))));
    } else {
        panic!("Expected map header");
    }
    
    // Check tagged header
    if let Some(CoseHeaderValue::Tagged(tag, inner)) = headers.get(&CoseHeaderLabel::Int(101)) {
        assert_eq!(*tag, 999);
        assert_eq!(**inner, CoseHeaderValue::Bytes(b"tagged_content".to_vec()));
    } else {
        panic!("Expected tagged header");
    }
    
    // Check bytes header
    assert_eq!(
        headers.get(&CoseHeaderLabel::Int(102)),
        Some(&CoseHeaderValue::Bytes(vec![0x00, 0x01, 0x02, 0xFF]))
    );
    
    // Check undefined header
    assert_eq!(
        headers.get(&CoseHeaderLabel::Int(103)),
        Some(&CoseHeaderValue::Undefined)
    );
}

#[test]
fn test_indefinite_length_unprotected_headers() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected (empty)
    
    // Indefinite length unprotected headers map
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("first").unwrap();
    encoder.encode_tstr("key2").unwrap();
    encoder.encode_i64(42).unwrap();
    encoder.encode_break().unwrap();
    
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse indefinite headers");
    
    assert_eq!(msg.unprotected.len(), 2);
    assert_eq!(
        msg.unprotected.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Text("first".to_string()))
    );
    assert_eq!(
        msg.unprotected.get(&CoseHeaderLabel::Text("key2".to_string())),
        Some(&CoseHeaderValue::Int(42))
    );
}

#[test]
fn test_message_debug_formatting() {
    let msg = CoseSign1Message {
        protected: ProtectedHeader::default(),
        unprotected: CoseHeaderMap::new(),
        payload: Some(b"debug test".to_vec()),
        signature: b"debug_sig".to_vec(),
    };
    
    let debug_str = format!("{:?}", msg);
    assert!(debug_str.contains("CoseSign1Message"));
    assert!(debug_str.contains("protected"));
    assert!(debug_str.contains("unprotected"));
    assert!(debug_str.contains("payload"));
    assert!(debug_str.contains("signature"));
}

#[test]
fn test_parse_inner_method() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    encoder.encode_map(0).unwrap(); // Unprotected
    encoder.encode_bstr(b"inner payload").unwrap(); // Payload
    encoder.encode_bstr(b"inner_sig").unwrap(); // Signature
    
    let inner_bytes = encoder.into_bytes();
    
    // Create outer message
    let outer_msg = CoseSign1Message {
        protected: ProtectedHeader::default(),
        unprotected: CoseHeaderMap::new(),
        payload: Some(b"outer payload".to_vec()),
        signature: b"outer_sig".to_vec(),
    };
    
    // Parse inner message
    let inner_msg = outer_msg.parse_inner(&inner_bytes).expect("should parse inner");
    assert_eq!(inner_msg.payload, Some(b"inner payload".to_vec()));
    assert_eq!(inner_msg.signature, b"inner_sig".to_vec());
}

#[test]
fn test_encode_with_and_without_tag() {
    let msg = CoseSign1Message {
        protected: ProtectedHeader::default(),
        unprotected: CoseHeaderMap::new(),
        payload: Some(b"encode test".to_vec()),
        signature: b"encode_sig".to_vec(),
    };
    
    // Test encoding without tag
    let untagged = msg.encode(false).expect("should encode untagged");
    let decoded_untagged = CoseSign1Message::parse(&untagged).expect("should parse untagged");
    assert_eq!(decoded_untagged.payload, msg.payload);
    assert_eq!(decoded_untagged.signature, msg.signature);
    
    // Test encoding with tag
    let tagged = msg.encode(true).expect("should encode tagged");
    let decoded_tagged = CoseSign1Message::parse(&tagged).expect("should parse tagged");
    assert_eq!(decoded_tagged.payload, msg.payload);
    assert_eq!(decoded_tagged.signature, msg.signature);
    
    // Tagged version should be longer due to tag
    assert!(tagged.len() > untagged.len());
}

#[test]
fn test_sig_structure_bytes_method() {
    let mut protected_headers = CoseHeaderMap::new();
    protected_headers.set_alg(-7);
    let protected = ProtectedHeader::encode(protected_headers).expect("should encode");
    
    let msg = CoseSign1Message {
        protected,
        unprotected: CoseHeaderMap::new(),
        payload: Some(b"test payload".to_vec()),
        signature: b"test_sig".to_vec(),
    };
    
    // Test sig structure generation
    let sig_struct = msg.sig_structure_bytes(b"custom payload", Some(b"external aad")).expect("should build sig structure");
    assert!(!sig_struct.is_empty());
    
    // Test with no external AAD
    let sig_struct_no_aad = msg.sig_structure_bytes(b"custom payload", None).expect("should build sig structure");
    assert!(!sig_struct_no_aad.is_empty());
    assert_ne!(sig_struct, sig_struct_no_aad); // Should be different
}

#[test]
fn test_unknown_cbor_types_in_headers() {
    // This tests the skip functionality for unknown CBOR types
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap(); // Protected
    
    // Unprotected with unknown type (simple value that might not be recognized)
    encoder.encode_map(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_tstr("known").unwrap(); // Known type
    encoder.encode_i64(2).unwrap();
    // Encode a simple value that should be handled as unknown
    encoder.encode_raw(&[0xF7]).unwrap(); // CBOR simple value 23 (undefined)
    
    encoder.encode_null().unwrap(); // Payload
    encoder.encode_bstr(b"sig").unwrap(); // Signature
    
    let bytes = encoder.into_bytes();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse with unknown types");
    
    // Should have parsed the known header and handled unknown gracefully
    assert_eq!(
        msg.unprotected.get(&CoseHeaderLabel::Int(1)),
        Some(&CoseHeaderValue::Text("known".to_string()))
    );
    // The unknown type should have been converted to Null or handled gracefully
    assert!(msg.unprotected.get(&CoseHeaderLabel::Int(2)).is_some());
}
