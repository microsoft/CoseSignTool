// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive test coverage for certificate crate components that don't require OpenSSL.
//! Focuses on pure Rust logic, enum variants, display implementations, and utility functions.

use cose_sign1_certificates::{
    cose_key_factory::{HashAlgorithm, X509CertificateCoseKeyFactory},
    CertificateError, CoseX509Thumbprint, ThumbprintAlgorithm, X509ChainSortOrder,
};

// Test CertificateError comprehensive coverage
#[test]
fn test_certificate_error_all_variants() {
    let errors = vec![
        CertificateError::NotFound,
        CertificateError::InvalidCertificate("test error".to_string()),
        CertificateError::ChainBuildFailed("chain error".to_string()),
        CertificateError::NoPrivateKey,
        CertificateError::SigningError("sign error".to_string()),
    ];

    let expected_messages = vec![
        "Certificate not found",
        "Invalid certificate: test error",
        "Chain building failed: chain error",
        "Private key not available",
        "Signing error: sign error",
    ];

    for (error, expected) in errors.iter().zip(expected_messages) {
        assert_eq!(error.to_string(), expected);
        // Test Debug implementation
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
    }
}

#[test]
fn test_certificate_error_std_error_trait() {
    let error = CertificateError::InvalidCertificate("test".to_string());
    let _: &dyn std::error::Error = &error;

    // Test source returns None (no nested errors)
    assert!(std::error::Error::source(&error).is_none());
}

// Test X509ChainSortOrder comprehensive coverage
#[test]
fn test_x509_chain_sort_order_all_variants() {
    let orders = vec![X509ChainSortOrder::LeafFirst, X509ChainSortOrder::RootFirst];

    for order in &orders {
        // Test Debug implementation
        let debug_str = format!("{:?}", order);
        assert!(!debug_str.is_empty());

        // Test Clone
        let cloned = order.clone();
        assert_eq!(order, &cloned);

        // Test Copy behavior
        let copied = *order;
        assert_eq!(order, &copied);

        // Test PartialEq
        assert_eq!(order, order);
    }

    // Test inequality
    assert_ne!(X509ChainSortOrder::LeafFirst, X509ChainSortOrder::RootFirst);
}

// Test ThumbprintAlgorithm comprehensive coverage
#[test]
fn test_thumbprint_algorithm_all_variants() {
    let algorithms = vec![
        ThumbprintAlgorithm::Sha256,
        ThumbprintAlgorithm::Sha384,
        ThumbprintAlgorithm::Sha512,
    ];

    let expected_cose_ids = vec![-16, -43, -44];

    for (algorithm, expected_id) in algorithms.iter().zip(expected_cose_ids) {
        assert_eq!(algorithm.cose_algorithm_id(), expected_id);

        // Test round-trip conversion
        assert_eq!(
            ThumbprintAlgorithm::from_cose_id(expected_id),
            Some(*algorithm)
        );

        // Test Debug, Clone, Copy, PartialEq
        let debug_str = format!("{:?}", algorithm);
        assert!(!debug_str.is_empty());

        let cloned = algorithm.clone();
        assert_eq!(algorithm, &cloned);

        let copied = *algorithm;
        assert_eq!(algorithm, &copied);
    }

    // Test invalid COSE IDs
    let invalid_ids = vec![-1, 0, 1, -100, 100];
    for invalid_id in invalid_ids {
        assert_eq!(ThumbprintAlgorithm::from_cose_id(invalid_id), None);
    }
}

// Test HashAlgorithm comprehensive coverage
#[test]
fn test_hash_algorithm_all_variants() {
    let algorithms = vec![
        HashAlgorithm::Sha256,
        HashAlgorithm::Sha384,
        HashAlgorithm::Sha512,
    ];

    let expected_cose_ids = vec![-16, -43, -44];

    for (algorithm, expected_id) in algorithms.iter().zip(expected_cose_ids) {
        assert_eq!(algorithm.cose_algorithm_id(), expected_id);

        // Test Debug implementation
        let debug_str = format!("{:?}", algorithm);
        assert!(!debug_str.is_empty());
    }
}

// Test X509CertificateCoseKeyFactory utility functions
#[test]
fn test_x509_certificate_cose_key_factory_get_hash_algorithm_comprehensive() {
    // Test RSA key sizes
    let rsa_test_cases = vec![
        (1024, false, HashAlgorithm::Sha256), // Small RSA
        (2048, false, HashAlgorithm::Sha256), // Standard RSA
        (3072, false, HashAlgorithm::Sha384), // Medium RSA
        (4096, false, HashAlgorithm::Sha512), // Large RSA
        (8192, false, HashAlgorithm::Sha512), // Very large RSA
    ];

    for (key_size, is_ec, expected) in rsa_test_cases {
        assert_eq!(
            X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(key_size, is_ec),
            expected,
            "Failed for RSA key size {}",
            key_size
        );
    }

    // Test EC key sizes (all should return Sha384 per code logic)
    let ec_test_cases = vec![
        (256, true),  // P-256
        (384, true),  // P-384
        (521, true),  // P-521
        (1024, true), // Hypothetical large EC
    ];

    for (key_size, is_ec) in ec_test_cases {
        assert_eq!(
            X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(key_size, is_ec),
            HashAlgorithm::Sha384,
            "Failed for EC key size {}",
            key_size
        );
    }

    // Edge cases
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(0, false),
        HashAlgorithm::Sha256
    );

    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(u32::MAX as usize, false),
        HashAlgorithm::Sha512
    );
}

// Test CoseX509Thumbprint construction and methods
#[test]
fn test_cose_x509_thumbprint_basic_operations() {
    // Create a sample cert DER bytes (doesn't need to be valid X.509 for hashing)
    let cert_der = vec![0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05];
    let algorithm = ThumbprintAlgorithm::Sha256;

    let thumbprint = CoseX509Thumbprint::new(&cert_der, algorithm);

    // Check that hash_id matches algorithm
    assert_eq!(thumbprint.hash_id, algorithm.cose_algorithm_id());

    // Thumbprint should be 32 bytes for SHA-256
    assert_eq!(thumbprint.thumbprint.len(), 32);

    // Test Debug implementation
    let debug_str = format!("{:?}", thumbprint);
    assert!(!debug_str.is_empty());
}

#[test]
fn test_cose_x509_thumbprint_from_cert() {
    // Test the from_cert method which defaults to SHA-256
    let cert_der = vec![0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05];

    let thumbprint = CoseX509Thumbprint::from_cert(&cert_der);

    // Default should be SHA-256 (-16)
    assert_eq!(
        thumbprint.hash_id,
        ThumbprintAlgorithm::Sha256.cose_algorithm_id()
    );
    assert_eq!(thumbprint.hash_id, -16);
}

#[test]
fn test_cose_x509_thumbprint_matches() {
    // Test that a thumbprint correctly matches the same cert
    let cert_der1 = vec![0x30, 0x82, 0x01, 0x02, 0x03];
    let cert_der2 = vec![0x30, 0x82, 0x01, 0x02, 0x04]; // Different cert

    let thumbprint = CoseX509Thumbprint::new(&cert_der1, ThumbprintAlgorithm::Sha256);

    // Should match the same cert
    assert!(thumbprint.matches(&cert_der1).unwrap());

    // Should not match a different cert
    assert!(!thumbprint.matches(&cert_der2).unwrap());
}

#[test]
fn test_thumbprint_comprehensive_edge_cases() {
    // Empty cert bytes - should still produce a hash
    let empty_cert = vec![];
    let empty_thumbprint = CoseX509Thumbprint::new(&empty_cert, ThumbprintAlgorithm::Sha256);
    assert_eq!(empty_thumbprint.thumbprint.len(), 32); // SHA-256 always produces 32 bytes

    // Large cert bytes
    let large_cert = vec![0xFF; 1024];
    let large_thumbprint = CoseX509Thumbprint::new(&large_cert, ThumbprintAlgorithm::Sha512);
    assert_eq!(large_thumbprint.thumbprint.len(), 64); // SHA-512 produces 64 bytes
    assert_eq!(
        large_thumbprint.hash_id,
        ThumbprintAlgorithm::Sha512.cose_algorithm_id()
    );

    // Test different algorithms produce different size thumbprints
    let cert = vec![0x42, 0x42, 0x42];
    let tp_256 = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha256);
    let tp_384 = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha384);
    let tp_512 = CoseX509Thumbprint::new(&cert, ThumbprintAlgorithm::Sha512);

    assert_eq!(tp_256.thumbprint.len(), 32);
    assert_eq!(tp_384.thumbprint.len(), 48);
    assert_eq!(tp_512.thumbprint.len(), 64);

    // Different algorithm thumbprints should have different hash_ids
    assert_ne!(tp_256.hash_id, tp_384.hash_id);
    assert_ne!(tp_256.hash_id, tp_512.hash_id);
    assert_ne!(tp_384.hash_id, tp_512.hash_id);
}
