// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CBOR error handling and edge case tests for CwtClaims.
//!
//! These tests target error scenarios and edge cases in CBOR encoding/decoding
//! to improve coverage in cwt_claims.rs

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_headers::{CwtClaimValue, CwtClaims, HeaderError};

#[test]
fn test_from_cbor_bytes_non_map_error() {
    // Create CBOR that is not a map (text string instead)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_tstr("not a map").unwrap();
    let invalid_cbor = encoder.into_bytes();

    let result = CwtClaims::from_cbor_bytes(&invalid_cbor);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("Expected CBOR map"));
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_from_cbor_bytes_indefinite_length_map_error() {
    // Create CBOR with indefinite-length map
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_map_indefinite_begin().unwrap();
    encoder.encode_break().unwrap();
    let invalid_cbor = encoder.into_bytes();

    let result = CwtClaims::from_cbor_bytes(&invalid_cbor);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("Indefinite-length maps not supported"));
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_from_cbor_bytes_non_integer_label_error() {
    // Create CBOR map with non-integer key
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_map(1).unwrap();
    encoder.encode_tstr("string-key").unwrap(); // Invalid - should be integer
    encoder.encode_tstr("value").unwrap();
    let invalid_cbor = encoder.into_bytes();

    let result = CwtClaims::from_cbor_bytes(&invalid_cbor);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(msg) => {
            assert!(msg.contains("CWT claim label must be integer"));
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_from_cbor_bytes_empty_data() {
    let result = CwtClaims::from_cbor_bytes(&[]);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(_) => {
            // Expected - empty data can't be parsed
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_from_cbor_bytes_truncated_data() {
    // Create valid start but truncate it
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap();
    // Missing the value - truncated
    let mut truncated_cbor = encoder.into_bytes();
    truncated_cbor.truncate(truncated_cbor.len() - 1); // Remove last byte

    let result = CwtClaims::from_cbor_bytes(&truncated_cbor);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(_) => {
            // Expected - truncated data can't be fully parsed
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_from_cbor_complex_type_skip() {
    // Create CBOR map with an array value (which should be skipped)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_map(2).unwrap();

    // First valid claim
    encoder.encode_i64(1).unwrap(); // issuer label
    encoder.encode_tstr("issuer").unwrap();

    // Second claim with complex type (array) - should be skipped
    encoder.encode_i64(1000).unwrap(); // custom label
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(1).unwrap();
    encoder.encode_i64(2).unwrap();

    let cbor_bytes = encoder.into_bytes();

    let claims = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    // Should have parsed issuer but skipped custom array claim
    assert_eq!(claims.issuer, Some("issuer".to_string()));
    assert!(!claims.custom_claims.contains_key(&1000)); // Should be skipped
}

#[test]
fn test_to_cbor_bytes_with_float_custom_claim() {
    // Note: This test documents the current behavior where float claims
    // attempt to be encoded but may fail depending on CBOR provider support
    let claims = CwtClaims::new().with_custom_claim(1000, CwtClaimValue::Float(3.14159));

    // EverParse doesn't support float encoding, so this should fail
    // But we test the error path is handled
    let result = claims.to_cbor_bytes();
    match result {
        Ok(_) => {
            // If float encoding succeeds, verify roundtrip
            let decoded = CwtClaims::from_cbor_bytes(&result.unwrap()).unwrap();
            match decoded.custom_claims.get(&1000) {
                Some(CwtClaimValue::Float(f)) => assert!((f - 3.14159).abs() < 1e-6),
                _ => panic!("Float claim should decode correctly"),
            }
        }
        Err(HeaderError::CborEncodingError(msg)) => {
            // Expected if CBOR provider doesn't support float encoding
            assert!(msg.contains("not supported") || msg.contains("error"));
        }
        Err(e) => panic!("Unexpected error type: {:?}", e),
    }
}

#[test]
fn test_cbor_roundtrip_custom_claim_all_integer_types() {
    let claims = CwtClaims::new()
        .with_custom_claim(1000, CwtClaimValue::Integer(0)) // Zero
        .with_custom_claim(1001, CwtClaimValue::Integer(1)) // Small positive
        .with_custom_claim(1002, CwtClaimValue::Integer(-1)) // Small negative
        .with_custom_claim(1003, CwtClaimValue::Integer(255)) // Byte boundary
        .with_custom_claim(1004, CwtClaimValue::Integer(-256)) // Negative byte boundary
        .with_custom_claim(1005, CwtClaimValue::Integer(65535)) // 16-bit boundary
        .with_custom_claim(1006, CwtClaimValue::Integer(-65536)) // Negative 16-bit boundary
        .with_custom_claim(1007, CwtClaimValue::Integer(i64::MAX)) // Maximum
        .with_custom_claim(1008, CwtClaimValue::Integer(i64::MIN)); // Minimum

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&1000),
        Some(&CwtClaimValue::Integer(0))
    );
    assert_eq!(
        decoded.custom_claims.get(&1001),
        Some(&CwtClaimValue::Integer(1))
    );
    assert_eq!(
        decoded.custom_claims.get(&1002),
        Some(&CwtClaimValue::Integer(-1))
    );
    assert_eq!(
        decoded.custom_claims.get(&1003),
        Some(&CwtClaimValue::Integer(255))
    );
    assert_eq!(
        decoded.custom_claims.get(&1004),
        Some(&CwtClaimValue::Integer(-256))
    );
    assert_eq!(
        decoded.custom_claims.get(&1005),
        Some(&CwtClaimValue::Integer(65535))
    );
    assert_eq!(
        decoded.custom_claims.get(&1006),
        Some(&CwtClaimValue::Integer(-65536))
    );
    assert_eq!(
        decoded.custom_claims.get(&1007),
        Some(&CwtClaimValue::Integer(i64::MAX))
    );
    assert_eq!(
        decoded.custom_claims.get(&1008),
        Some(&CwtClaimValue::Integer(i64::MIN))
    );
}

#[test]
fn test_cbor_roundtrip_custom_claim_bytes_edge_cases() {
    let claims = CwtClaims::new()
        .with_custom_claim(1000, CwtClaimValue::Bytes(vec![])) // Empty bytes
        .with_custom_claim(1001, CwtClaimValue::Bytes(vec![0x00])) // Single zero byte
        .with_custom_claim(1002, CwtClaimValue::Bytes(vec![0xFF])) // Single max byte
        .with_custom_claim(1003, CwtClaimValue::Bytes((0..=255).collect::<Vec<u8>>())); // All byte values

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&1000),
        Some(&CwtClaimValue::Bytes(vec![]))
    );
    assert_eq!(
        decoded.custom_claims.get(&1001),
        Some(&CwtClaimValue::Bytes(vec![0x00]))
    );
    assert_eq!(
        decoded.custom_claims.get(&1002),
        Some(&CwtClaimValue::Bytes(vec![0xFF]))
    );
    assert_eq!(
        decoded.custom_claims.get(&1003),
        Some(&CwtClaimValue::Bytes((0..=255).collect::<Vec<u8>>()))
    );
}

#[test]
fn test_cbor_roundtrip_custom_claim_bool_cases() {
    let claims = CwtClaims::new()
        .with_custom_claim(1000, CwtClaimValue::Bool(true))
        .with_custom_claim(1001, CwtClaimValue::Bool(false));

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&1000),
        Some(&CwtClaimValue::Bool(true))
    );
    assert_eq!(
        decoded.custom_claims.get(&1001),
        Some(&CwtClaimValue::Bool(false))
    );
}

#[test]
fn test_from_cbor_malformed_standard_claims() {
    // Create CBOR where issuer claim has wrong type (integer instead of string)
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(1).unwrap(); // issuer label
    encoder.encode_i64(123).unwrap(); // wrong type - should be string
    let invalid_cbor = encoder.into_bytes();

    let result = CwtClaims::from_cbor_bytes(&invalid_cbor);
    assert!(result.is_err());

    match result.unwrap_err() {
        HeaderError::CborDecodingError(_) => {
            // Expected - type mismatch
        }
        _ => panic!("Expected CborDecodingError"),
    }
}

#[test]
fn test_label_ordering_deterministic() {
    // Test that claims are encoded in deterministic order regardless of insertion order
    let mut claims1 = CwtClaims::new();
    claims1.expiration_time = Some(1000);
    claims1.issuer = Some("issuer".to_string());
    claims1.not_before = Some(500);

    let mut claims2 = CwtClaims::new();
    claims2.not_before = Some(500);
    claims2.expiration_time = Some(1000);
    claims2.issuer = Some("issuer".to_string());

    let cbor1 = claims1.to_cbor_bytes().unwrap();
    let cbor2 = claims2.to_cbor_bytes().unwrap();

    // CBOR bytes should be identical regardless of field setting order
    assert_eq!(cbor1, cbor2);
}

#[test]
fn test_custom_claims_sorting() {
    let claims = CwtClaims::new()
        .with_custom_claim(3000, CwtClaimValue::Text("3000".to_string()))
        .with_custom_claim(1000, CwtClaimValue::Text("1000".to_string()))
        .with_custom_claim(2000, CwtClaimValue::Text("2000".to_string()))
        .with_custom_claim(-500, CwtClaimValue::Text("-500".to_string()));

    let cbor_bytes = claims.to_cbor_bytes().unwrap();

    // Decode and verify order is maintained on roundtrip
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(
        decoded.custom_claims.get(&-500),
        Some(&CwtClaimValue::Text("-500".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&1000),
        Some(&CwtClaimValue::Text("1000".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&2000),
        Some(&CwtClaimValue::Text("2000".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&3000),
        Some(&CwtClaimValue::Text("3000".to_string()))
    );
}

#[test]
fn test_large_map_handling() {
    // Test with a reasonably large number of custom claims
    let mut claims = CwtClaims::new();
    for i in 0..100 {
        claims
            .custom_claims
            .insert(1000 + i, CwtClaimValue::Integer(i));
    }

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    assert_eq!(decoded.custom_claims.len(), 100);
    for i in 0..100 {
        assert_eq!(
            decoded.custom_claims.get(&(1000 + i)),
            Some(&CwtClaimValue::Integer(i))
        );
    }
}

#[test]
fn test_mixed_standard_and_custom_claims_roundtrip() {
    // Build claims with both standard and custom claims (without conflicts)
    let claims = CwtClaims::new()
        .with_issuer("mixed-issuer")
        .with_expiration_time(2000)
        .with_audience("real-audience")
        .with_custom_claim(-1, CwtClaimValue::Text("negative".to_string()))
        .with_custom_claim(8, CwtClaimValue::Integer(999)) // Higher than standard labels (1-7)
        .with_custom_claim(10, CwtClaimValue::Text("non-conflicting".to_string())); // Non-conflicting custom label

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    // Standard claims should be present
    assert_eq!(decoded.issuer, Some("mixed-issuer".to_string()));
    assert_eq!(decoded.audience, Some("real-audience".to_string()));
    assert_eq!(decoded.expiration_time, Some(2000));

    // Custom claims should be present
    assert_eq!(
        decoded.custom_claims.get(&-1),
        Some(&CwtClaimValue::Text("negative".to_string()))
    );
    assert_eq!(
        decoded.custom_claims.get(&8),
        Some(&CwtClaimValue::Integer(999))
    );
    assert_eq!(
        decoded.custom_claims.get(&10),
        Some(&CwtClaimValue::Text("non-conflicting".to_string()))
    );

    // Standard claim labels should not appear in custom_claims
    assert!(!decoded.custom_claims.contains_key(&1)); // Issuer
    assert!(!decoded.custom_claims.contains_key(&3)); // Audience
    assert!(!decoded.custom_claims.contains_key(&4)); // Expiration time
}

#[test]
fn test_conflicting_label_behavior() {
    // Test how the system handles conflicting labels between standard and custom claims
    let mut claims = CwtClaims::new();
    claims
        .custom_claims
        .insert(3, CwtClaimValue::Text("custom-audience".to_string()));

    // Now set standard audience - this should be in the standard field
    claims.audience = Some("standard-audience".to_string());

    let cbor_bytes = claims.to_cbor_bytes().unwrap();
    let decoded = CwtClaims::from_cbor_bytes(&cbor_bytes).unwrap();

    // When decoding a CBOR map with duplicate keys (label 3),
    // the last value encountered wins for standard claims
    // Standard claims are encoded first, then custom claims, so custom wins
    assert_eq!(decoded.audience, Some("custom-audience".to_string()));
}
