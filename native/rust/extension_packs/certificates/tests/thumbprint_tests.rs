// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::thumbprint::{CoseX509Thumbprint, ThumbprintAlgorithm, compute_thumbprint};

// Test helper to get a deterministic test certificate DER bytes
fn test_cert_der() -> Vec<u8> {
    // Simple predictable test data
    b"test certificate data".to_vec()
}

#[test]
fn test_thumbprint_algorithm_cose_ids() {
    assert_eq!(ThumbprintAlgorithm::Sha256.cose_algorithm_id(), -16);
    assert_eq!(ThumbprintAlgorithm::Sha384.cose_algorithm_id(), -43);
    assert_eq!(ThumbprintAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn test_thumbprint_algorithm_from_cose_id() {
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-16), Some(ThumbprintAlgorithm::Sha256));
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-43), Some(ThumbprintAlgorithm::Sha384));
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-44), Some(ThumbprintAlgorithm::Sha512));
    assert_eq!(ThumbprintAlgorithm::from_cose_id(0), None);
    assert_eq!(ThumbprintAlgorithm::from_cose_id(-999), None);
}

#[test]
fn test_compute_thumbprint_sha256() {
    let cert_der = test_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha256);
    
    // SHA-256 produces 32 bytes
    assert_eq!(thumbprint.len(), 32);
    
    // Deterministic - same input produces same output
    let thumbprint2 = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha256);
    assert_eq!(thumbprint, thumbprint2);
}

#[test]
fn test_compute_thumbprint_sha384() {
    let cert_der = test_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha384);
    
    // SHA-384 produces 48 bytes
    assert_eq!(thumbprint.len(), 48);
    
    // Deterministic
    let thumbprint2 = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha384);
    assert_eq!(thumbprint, thumbprint2);
}

#[test]
fn test_compute_thumbprint_sha512() {
    let cert_der = test_cert_der();
    let thumbprint = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha512);
    
    // SHA-512 produces 64 bytes
    assert_eq!(thumbprint.len(), 64);
    
    // Deterministic
    let thumbprint2 = compute_thumbprint(&cert_der, ThumbprintAlgorithm::Sha512);
    assert_eq!(thumbprint, thumbprint2);
}

#[test]
fn test_cose_x509_thumbprint_new() {
    let cert_der = test_cert_der();
    let thumbprint = CoseX509Thumbprint::new(&cert_der, ThumbprintAlgorithm::Sha256);
    
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
}

#[test]
fn test_cose_x509_thumbprint_from_cert() {
    let cert_der = test_cert_der();
    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    // Default is SHA-256
    assert_eq!(thumbprint.hash_id, -16);
    assert_eq!(thumbprint.thumbprint.len(), 32);
}

#[test]
fn test_cose_x509_thumbprint_matches() {
    let cert_der = test_cert_der();
    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    // Should match the same certificate
    assert!(thumbprint.matches(&cert_der).unwrap());
    
    // Should not match a different certificate
    let other_cert = b"different certificate data".to_vec();
    assert!(!thumbprint.matches(&other_cert).unwrap());
}

#[test]
fn test_cose_x509_thumbprint_matches_unsupported_hash() {
    let cert_der = test_cert_der();
    let mut thumbprint = CoseX509Thumbprint::from_cert(&cert_der);
    
    // Set unsupported hash_id
    thumbprint.hash_id = -999;
    
    let result = thumbprint.matches(&cert_der);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Unsupported hash ID"));
}
