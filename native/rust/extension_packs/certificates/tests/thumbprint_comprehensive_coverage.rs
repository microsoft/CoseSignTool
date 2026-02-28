// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive test coverage for certificates thumbprint.rs.
//! 
//! Targets remaining uncovered lines (24 uncov) with focus on:
//! - ThumbprintAlgorithm methods
//! - CoseX509Thumbprint creation and serialization
//! - CBOR encoding/decoding paths
//! - Thumbprint matching functionality
//! - Error conditions

use cose_sign1_certificates::thumbprint::{
    CoseX509Thumbprint, ThumbprintAlgorithm, compute_thumbprint
};

// Create mock certificate DER for testing
fn create_mock_cert_der() -> Vec<u8> {
    // Mock DER certificate bytes for testing
    vec![
        0x30, 0x82, 0x02, 0x76, // SEQUENCE, length 0x276
        0x30, 0x82, 0x01, 0x5E, // tbsCertificate SEQUENCE
        // Mock ASN.1 structure - not a real cert, but valid for hashing
        0x02, 0x01, 0x01, // version
        0x02, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // serial
        // Add more mock data to make it substantial for testing
    ].into_iter().cycle().take(256).collect()
}

fn create_different_mock_cert() -> Vec<u8> {
    // Different mock certificate for non-matching tests
    vec![
        0x30, 0x82, 0x03, 0x88, // Different SEQUENCE length
        0x30, 0x82, 0x02, 0x70, // Different tbsCertificate
        0x02, 0x01, 0x02, // Different version
        0x02, 0x08, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, // Different serial
    ].into_iter().cycle().take(300).collect()
}

#[test]
fn test_thumbprint_algorithm_cose_ids() {
    assert_eq!(ThumbprintAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(ThumbprintAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(ThumbprintAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn test_thumbprint_algorithm_from_cose_id_valid() {
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-16), Some(ThumbprintAlgorithm::Sha256));
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-43), Some(ThumbprintAlgorithm::Sha384));
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-44), Some(ThumbprintAlgorithm::Sha512));
}

#[test]
fn test_thumbprint_algorithm_from_cose_id_invalid() {
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-999), None);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(0), None);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(100), None);
}

#[test]
fn test_compute_thumbprint_sha256() {
    let cert_der = create_mock_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha256);
    
    assert_eq!(thumbprint.len(), 32, "SHA-256 should produce 32-byte hash");
    
    // Verify deterministic - same input should produce same output
    let thumbprint2 = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha256);
    assert_eq!(thumbprint, thumbprint2, "SHA-256 should be deterministic");
}

#[test]
fn test_compute_thumbprint_sha384() {
    let cert_der = create_mock_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha384);
    
    assert_eq!(thumbprint.len(), 48, "SHA-384 should produce 48-byte hash");
    
    // Verify different from SHA-256
    let sha256_thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha256);
    assert_ne!(thumbprint.len(), sha256_thumbprint.len(), "SHA-384 and SHA-256 should produce different lengths");
}

#[test]
fn test_compute_thumbprint_sha512() {
    let cert_der = create_mock_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha512);
    
    assert_eq!(thumbprint.len(), 64, "SHA-512 should produce 64-byte hash");
    
    // Verify different content produces different hash
    let different_cert = create_different_mock_cert();
    let different_thumbprint = compute_thumbprint(&different_cert, ThumbprintAlgorithm::Sha512);
    assert_ne!(thumbprint, different_thumbprint, "Different certificates should produce different hashes");
}

#[test]
fn test_cose_x509_thumbprint_new() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
}

#[test]
fn test_cose_x509_thumbprint_from_cert_default() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    // Should default to SHA-256
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
    
    // Should be equivalent to explicit SHA-256
    let explicit_sha256 = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    assert_eq!(thumbprint.hash_id, explicit_sha256.hash_id);
    assert_eq!(thumbprint.thumbprint, explicit_sha256.thumbprint);
}

#[test]
fn test_cose_x509_thumbprint_serialize() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    
    let serialized = thumbprint.serialize().expect("Should serialize successfully");
    assert!(!serialized.is_empty(), "Serialized data should not be empty");
    
    // Should be CBOR array [int, bstr]
    // Basic check: should start with CBOR array marker
    assert_eq!(serialized[0] & 0xE0, 0x80, "Should start with CBOR array"); // 0x82 = array of 2 items
}

#[test]
fn test_cose_x509_thumbprint_serialize_sha384() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha384);
    
    let serialized = thumbprint.serialize().expect("Should serialize SHA-384 successfully");
    assert!(!serialized.is_empty(), "Serialized SHA-384 data should not be empty");
}

#[test]
fn test_cose_x509_thumbprint_serialize_sha512() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha512);
    
    let serialized = thumbprint.serialize().expect("Should serialize SHA-512 successfully");
    assert!(!serialized.is_empty(), "Serialized SHA-512 data should not be empty");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_roundtrip() {
    let cert_der = create_mock_cert_der();
    let original = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    
    let serialized = original.serialize().expect("Should serialize");
    let deserialized = CoseX509Thumbprint::deserialize(&serialized).expect("Should deserialize");
    
    assert_eq!(original.hash_id, deserialized.hash_id);
    assert_eq!(original.thumbprint, deserialized.thumbprint);
}

#[test]
fn test_cose_x509_thumbprint_deserialize_all_algorithms() {
    let cert_der = create_mock_cert_der();
    
    for algorithm in [ThumbprintAlgorithm::Sha256, ThumbprintAlgorithm::Sha384, ThumbprintAlgorithm::Sha512] {
        let original = CoseX509Thumbprint::new(&cert_der, algorithm);
        let serialized = original.serialize().expect("Should serialize");
        let deserialized = CoseX509Thumbprint::deserialize(&serialized).expect("Should deserialize");
        
        assert_eq!(original.hash_id, deserialized.hash_id);
        assert_eq!(original.thumbprint, deserialized.thumbprint);
    }
}

#[test]
fn test_cose_x509_thumbprint_deserialize_invalid_cbor() {
    let invalid_cbor = b"not valid cbor";
    let result = CoseX509Thumbprint::deserialize(invalid_cbor);
    assert!(result.is_err(), "Should fail with invalid CBOR");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_not_array() {
    // Create CBOR that's not an array (integer 42)
    use cbor_primitives::CborEncoder;
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_i64(42).unwrap();
    let not_array = encoder.into_bytes();
    
    let result = CoseX509Thumbprint::deserialize(&not_array);
    assert!(result.is_err(), "Should fail when not an array");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("first level must be an array"), "Should mention array requirement");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_wrong_array_length() {
    // Create CBOR array with wrong length (3 instead of 2)
    use cbor_primitives::CborEncoder;
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(3).unwrap();
    encoder.encode_i64(-16).unwrap();
    encoder.encode_bstr(b"hash").unwrap();
    encoder.encode_i64(999).unwrap(); // Extra element
    let wrong_length = encoder.into_bytes();
    
    let result = CoseX509Thumbprint::deserialize(&wrong_length);
    assert!(result.is_err(), "Should fail with wrong array length");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("2 element array"), "Should mention 2 element requirement");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_first_not_int() {
    // Create CBOR array where first element is not integer
    use cbor_primitives::CborEncoder;
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_tstr("not_int").unwrap(); // Should be int
    encoder.encode_bstr(b"hash").unwrap();
    let not_int = encoder.into_bytes();
    
    let result = CoseX509Thumbprint::deserialize(&not_int);
    assert!(result.is_err(), "Should fail when first element is not integer");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("first member must be integer"), "Should mention integer requirement");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_unsupported_algorithm() {
    // Create CBOR array with unsupported hash algorithm
    use cbor_primitives::CborEncoder;
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(-999).unwrap(); // Unsupported algorithm
    encoder.encode_bstr(b"hash").unwrap();
    let unsupported = encoder.into_bytes();
    
    let result = CoseX509Thumbprint::deserialize(&unsupported);
    assert!(result.is_err(), "Should fail with unsupported algorithm");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Unsupported thumbprint hash algorithm"), "Should mention unsupported algorithm");
}

#[test]
fn test_cose_x509_thumbprint_deserialize_second_not_bstr() {
    // Create CBOR array where second element is not byte string
    use cbor_primitives::CborEncoder;
    let mut encoder = cose_sign1_primitives::provider::encoder();
    encoder.encode_array(2).unwrap();
    encoder.encode_i64(-16).unwrap();
    encoder.encode_tstr("not_bstr").unwrap(); // Should be bstr
    let not_bstr = encoder.into_bytes();
    
    let result = CoseX509Thumbprint::deserialize(&not_bstr);
    assert!(result.is_err(), "Should fail when second element is not byte string");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("second member must be ByteString"), "Should mention byte string requirement");
}

#[test]
fn test_cose_x509_thumbprint_matches_same_cert() {
    let cert_der = create_mock_cert_der();
    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    let matches = thumbprint.matches(&cert_der).expect("Should check match successfully");
    assert!(matches, "Should match the same certificate");
}

#[test]
fn test_cose_x509_thumbprint_matches_different_cert() {
    let cert_der = create_mock_cert_der();
    let different_cert = create_different_mock_cert();
    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    let matches = thumbprint.matches(&different_cert).expect("Should check match successfully");
    assert!(!matches, "Should not match a different certificate");
}

#[test]
fn test_cose_x509_thumbprint_matches_unsupported_hash() {
    let cert_der = create_mock_cert_der();
    
    // Create thumbprint with unsupported hash ID directly
    let invalid_thumbprint = CoseX509Thumbprint {
        hash_id: -999, // Unsupported
        thumbprint: vec![0u8; 32],
    };
    
    let result = invalid_thumbprint.matches(&cert_der);
    assert!(result.is_err(), "Should fail with unsupported hash ID");
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Unsupported hash ID"), "Should mention unsupported hash ID");
}

#[test]
fn test_cose_x509_thumbprint_matches_different_algorithms() {
    let cert_der = create_mock_cert_der();
    
    // Create thumbprints with different algorithms
    let sha256_thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    let sha384_thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha384);
    let sha512_thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha512);
    
    // Each should match when using the correct algorithm
    assert!(sha256_thumbprint.matches(&cert_der).unwrap(), "SHA-256 thumbprint should match");
    assert!(sha384_thumbprint.matches(&cert_der).unwrap(), "SHA-384 thumbprint should match");
    assert!(sha512_thumbprint.matches(&cert_der).unwrap(), "SHA-512 thumbprint should match");
    
    // Different algorithms should have different hash values
    assert_ne!(sha256_thumbprint.thumbprint, sha384_thumbprint.thumbprint);
    assert_ne!(sha256_thumbprint.thumbprint, sha512_thumbprint.thumbprint);
    assert_ne!(sha384_thumbprint.thumbprint, sha512_thumbprint.thumbprint);
}

#[test]
fn test_cose_x509_thumbprint_empty_certificate() {
    let empty_cert = Vec::new();
    let thumbprint = CoseX509Thumbprint::from_cert(&empty_cert);
    
    // Should still work with empty input (hash of empty data)
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
    
    // Should match empty certificate
    assert!(thumbprint.matches(&empty_cert).unwrap(), "Should match empty certificate");
}

#[test]
fn test_cose_x509_thumbprint_large_certificate() {
    // Test with larger mock certificate
    let large_cert: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let thumbprint = CoseX509Thumbprint::from_cert(&large_cert);
    
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
    assert!(thumbprint.matches(&large_cert).unwrap(), "Should match large certificate");
}