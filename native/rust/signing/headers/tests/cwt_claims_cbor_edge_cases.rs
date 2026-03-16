// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional CWT claims CBOR decoding edge cases and error handling tests.

use cose_sign1_headers::{CwtClaims, CwtClaimValue, CWTClaimsHeaderLabels, HeaderError};
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;

#[test]
fn test_cbor_decode_invalid_map_structure() {
    // Test indefinite-length map (not supported)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Create an indefinite-length map (not allowed by our implementation)
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_i64(1).unwrap(); // issuer label
    encoder.encode_tstr("test").unwrap();
    encoder.encode_break().unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes);
    
    match result {
        Err(HeaderError::CborDecodingError(msg)) => {
            assert!(msg.contains("Indefinite-length maps not supported"));
        }
        _ => panic!("Expected error for indefinite-length map"),
    }
}

#[test]
fn test_cbor_decode_invalid_claim_labels() {
    // Test with text string labels (not allowed)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(1).unwrap();
    encoder.encode_tstr("invalid-label").unwrap(); // Should be integer
    encoder.encode_tstr("value").unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes);
    
    match result {
        Err(HeaderError::CborDecodingError(msg)) => {
            assert!(msg.contains("CWT claim label must be integer"));
        }
        _ => panic!("Expected error for text string label"),
    }
}

#[test]
fn test_cbor_decode_complex_custom_claims() {
    // Test that complex types in custom claims are skipped
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(3).unwrap();
    
    // Valid claim
    encoder.encode_i64(1000).unwrap();
    encoder.encode_tstr("valid").unwrap();
    
    // Complex claim (array) - should be skipped
    encoder.encode_i64(1001).unwrap();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();
    
    // Another valid claim
    encoder.encode_i64(1002).unwrap();
    encoder.encode_i64(42).unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    
    // Should only have the 2 valid claims (complex one skipped)
    assert_eq!(result.custom_claims.len(), 2);
    assert_eq!(result.custom_claims.get(&1000), Some(&CwtClaimValue::Text("valid".to_string())));
    assert_eq!(result.custom_claims.get(&1002), Some(&CwtClaimValue::Integer(42)));
    assert_eq!(result.custom_claims.get(&1001), None); // Skipped
}

#[test]
fn test_cbor_decode_all_standard_claims() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(7).unwrap();
    
    // All standard claims
    encoder.encode_i64(CWTClaimsHeaderLabels::ISSUER).unwrap();
    encoder.encode_tstr("test-issuer").unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::SUBJECT).unwrap();
    encoder.encode_tstr("test-subject").unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::AUDIENCE).unwrap();
    encoder.encode_tstr("test-audience").unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::EXPIRATION_TIME).unwrap();
    encoder.encode_i64(1700000000).unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::NOT_BEFORE).unwrap();
    encoder.encode_i64(1600000000).unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::ISSUED_AT).unwrap();
    encoder.encode_i64(1650000000).unwrap();
    
    encoder.encode_i64(CWTClaimsHeaderLabels::CWT_ID).unwrap();
    encoder.encode_bstr(&[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    
    assert_eq!(result.issuer, Some("test-issuer".to_string()));
    assert_eq!(result.subject, Some("test-subject".to_string()));
    assert_eq!(result.audience, Some("test-audience".to_string()));
    assert_eq!(result.expiration_time, Some(1700000000));
    assert_eq!(result.not_before, Some(1600000000));
    assert_eq!(result.issued_at, Some(1650000000));
    assert_eq!(result.cwt_id, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[test]
fn test_cbor_decode_mixed_custom_claim_types() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(5).unwrap();
    
    // Text claim
    encoder.encode_i64(100).unwrap();
    encoder.encode_tstr("text-value").unwrap();
    
    // Integer claim (positive)
    encoder.encode_i64(101).unwrap();
    encoder.encode_u64(999).unwrap();
    
    // Integer claim (negative)  
    encoder.encode_i64(102).unwrap();
    encoder.encode_i64(-123).unwrap();
    
    // Bytes claim
    encoder.encode_i64(103).unwrap();
    encoder.encode_bstr(&[1, 2, 3, 4]).unwrap();
    
    // Bool claim
    encoder.encode_i64(104).unwrap();
    encoder.encode_bool(false).unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    
    assert_eq!(result.custom_claims.len(), 5);
    assert_eq!(result.custom_claims.get(&100), Some(&CwtClaimValue::Text("text-value".to_string())));
    assert_eq!(result.custom_claims.get(&101), Some(&CwtClaimValue::Integer(999)));
    assert_eq!(result.custom_claims.get(&102), Some(&CwtClaimValue::Integer(-123)));
    assert_eq!(result.custom_claims.get(&103), Some(&CwtClaimValue::Bytes(vec![1, 2, 3, 4])));
    assert_eq!(result.custom_claims.get(&104), Some(&CwtClaimValue::Bool(false)));
}

#[test]
fn test_cbor_decode_duplicate_labels() {
    // Test what happens with duplicate labels (last one should win per CBOR spec)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    encoder.encode_map(2).unwrap();
    
    // Same label twice with different values
    encoder.encode_i64(100).unwrap();
    encoder.encode_tstr("first-value").unwrap();
    encoder.encode_i64(100).unwrap();
    encoder.encode_tstr("second-value").unwrap();
    
    let bytes = encoder.into_bytes();
    let result = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    
    assert_eq!(result.custom_claims.len(), 1);
    assert_eq!(result.custom_claims.get(&100), Some(&CwtClaimValue::Text("second-value".to_string())));
}

#[test]
fn test_cbor_encode_deterministic_ordering() {
    // Verify that encoding is deterministic (custom claims sorted by label)
    let claims1 = CwtClaims::new()
        .with_custom_claim(1003, CwtClaimValue::Text("z".to_string()))
        .with_custom_claim(1001, CwtClaimValue::Text("a".to_string()))
        .with_custom_claim(1002, CwtClaimValue::Text("m".to_string()));
        
    let claims2 = CwtClaims::new()
        .with_custom_claim(1001, CwtClaimValue::Text("a".to_string()))
        .with_custom_claim(1002, CwtClaimValue::Text("m".to_string()))
        .with_custom_claim(1003, CwtClaimValue::Text("z".to_string()));
    
    let bytes1 = claims1.to_cbor_bytes().unwrap();
    let bytes2 = claims2.to_cbor_bytes().unwrap();
    
    // Encoding should be identical regardless of insertion order
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_cbor_encode_empty_claims() {
    let claims = CwtClaims::new();
    let bytes = claims.to_cbor_bytes().unwrap();
    
    // Should be an empty map
    assert_eq!(bytes.len(), 1);
    assert_eq!(bytes[0], 0xa0); // CBOR empty map
}

#[test]
fn test_cbor_roundtrip_edge_case_values() {
    let claims = CwtClaims::new()
        .with_issuer("\0null byte in string\0")
        .with_custom_claim(i64::MIN, CwtClaimValue::Integer(i64::MAX))
        .with_custom_claim(i64::MAX, CwtClaimValue::Integer(i64::MIN))
        .with_custom_claim(0, CwtClaimValue::Bytes(vec![0x00, 0xFF, 0x7F, 0x80]))
        .with_expiration_time(0)
        .with_not_before(-1)
        .with_cwt_id(vec![]);
        
    let bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&bytes).unwrap();
    
    assert_eq!(decoded.issuer, Some("\0null byte in string\0".to_string()));
    assert_eq!(decoded.custom_claims.get(&i64::MIN), Some(&CwtClaimValue::Integer(i64::MAX)));
    assert_eq!(decoded.custom_claims.get(&i64::MAX), Some(&CwtClaimValue::Integer(i64::MIN)));
    assert_eq!(decoded.custom_claims.get(&0), Some(&CwtClaimValue::Bytes(vec![0x00, 0xFF, 0x7F, 0x80])));
    assert_eq!(decoded.expiration_time, Some(0));
    assert_eq!(decoded.not_before, Some(-1));
    assert_eq!(decoded.cwt_id, Some(vec![]));
}
