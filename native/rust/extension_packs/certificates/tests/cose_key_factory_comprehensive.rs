// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for X509CertificateCoseKeyFactory.

use cose_sign1_certificates::cose_key_factory::{HashAlgorithm, X509CertificateCoseKeyFactory};
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, KeyAlgorithm,
    SoftwareKeyProvider,
};

#[test]
fn test_create_from_public_key_with_p256_cert() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=test.example.com")
                .add_subject_alternative_name("test.example.com")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(256),
        )
        .unwrap();
    let cert_der = cert.cert_der.clone();

    let result = X509CertificateCoseKeyFactory::create_from_public_key(&cert_der);
    assert!(
        result.is_ok(),
        "Should create verifier from P-256 certificate"
    );
}

#[test]
fn test_create_from_public_key_with_p384_cert() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=test384.example.com")
                .add_subject_alternative_name("test384.example.com")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(384),
        )
        .unwrap();
    let cert_der = cert.cert_der.clone();

    let result = X509CertificateCoseKeyFactory::create_from_public_key(&cert_der);
    assert!(
        result.is_ok(),
        "Should create verifier from P-384 certificate"
    );
}

#[test]
fn test_create_from_public_key_with_invalid_der() {
    let invalid_der = vec![0xFF, 0xFE, 0xFD, 0xFC, 0x00, 0x01, 0x02, 0x03];

    let result = X509CertificateCoseKeyFactory::create_from_public_key(&invalid_der);
    assert!(result.is_err(), "Should fail with invalid DER");

    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(
                msg.contains("Failed to parse certificate"),
                "Error should mention parse failure: {}",
                msg
            );
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_create_from_public_key_with_empty_input() {
    let result = X509CertificateCoseKeyFactory::create_from_public_key(&[]);
    assert!(result.is_err(), "Should fail with empty input");

    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(
                msg.contains("Failed to parse certificate"),
                "Error should mention parse failure"
            );
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_create_from_public_key_extracts_correct_public_key() {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=extract-test.example.com")
                .add_subject_alternative_name("extract-test.example.com")
                .with_key_algorithm(KeyAlgorithm::Ecdsa)
                .with_key_size(256),
        )
        .unwrap();
    let cert_der = cert.cert_der.clone();

    let result = X509CertificateCoseKeyFactory::create_from_public_key(&cert_der);
    assert!(result.is_ok(), "Should successfully extract public key");

    let verifier = result.unwrap();
    // Verifier should have algorithm set based on the key
    assert!(
        verifier.algorithm() != 0,
        "Verifier should have a valid algorithm"
    );
}

#[test]
fn test_get_hash_algorithm_for_key_size_2048_rsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(2048, false);
    assert_eq!(
        result,
        HashAlgorithm::Sha256,
        "2048-bit RSA should use SHA-256"
    );
}

#[test]
fn test_get_hash_algorithm_for_key_size_3072_rsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3072, false);
    assert_eq!(
        result,
        HashAlgorithm::Sha384,
        "3072-bit RSA should use SHA-384"
    );
}

#[test]
fn test_get_hash_algorithm_for_key_size_4096_rsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4096, false);
    assert_eq!(
        result,
        HashAlgorithm::Sha512,
        "4096-bit RSA should use SHA-512"
    );
}

#[test]
fn test_get_hash_algorithm_for_key_size_8192_rsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(8192, false);
    assert_eq!(
        result,
        HashAlgorithm::Sha512,
        "8192-bit RSA should use SHA-512"
    );
}

#[test]
fn test_get_hash_algorithm_for_p521_ecdsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(521, true);
    assert_eq!(result, HashAlgorithm::Sha384, "P-521 should use SHA-384");
}

#[test]
fn test_get_hash_algorithm_for_p256_ecdsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(256, false);
    assert_eq!(result, HashAlgorithm::Sha256, "P-256 should use SHA-256");
}

#[test]
fn test_get_hash_algorithm_for_p384_ecdsa() {
    let result = X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(384, false);
    assert_eq!(
        result,
        HashAlgorithm::Sha256,
        "P-384 (below 3072) should use SHA-256"
    );
}

#[test]
fn test_get_hash_algorithm_boundary_at_3072() {
    // Test exact boundary
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3071, false),
        HashAlgorithm::Sha256,
        "3071 bits should use SHA-256"
    );
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(3072, false),
        HashAlgorithm::Sha384,
        "3072 bits should use SHA-384"
    );
}

#[test]
fn test_get_hash_algorithm_boundary_at_4096() {
    // Test exact boundary
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4095, false),
        HashAlgorithm::Sha384,
        "4095 bits should use SHA-384"
    );
    assert_eq!(
        X509CertificateCoseKeyFactory::get_hash_algorithm_for_key_size(4096, false),
        HashAlgorithm::Sha512,
        "4096 bits should use SHA-512"
    );
}

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha256() {
    assert_eq!(HashAlgorithm::Sha256.cose_algorithm_id(), -16);
}

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha384() {
    assert_eq!(HashAlgorithm::Sha384.cose_algorithm_id(), -43);
}

#[test]
fn test_hash_algorithm_cose_algorithm_id_sha512() {
    assert_eq!(HashAlgorithm::Sha512.cose_algorithm_id(), -44);
}

#[test]
fn test_hash_algorithm_debug() {
    let sha256 = HashAlgorithm::Sha256;
    let debug_str = format!("{:?}", sha256);
    assert_eq!(debug_str, "Sha256");
}

#[test]
fn test_hash_algorithm_clone() {
    let sha256 = HashAlgorithm::Sha256;
    let cloned = sha256.clone();
    assert_eq!(sha256, cloned);
}

#[test]
fn test_hash_algorithm_copy() {
    let sha256 = HashAlgorithm::Sha256;
    let copied = sha256;
    assert_eq!(sha256, copied);
}

#[test]
fn test_hash_algorithm_partial_eq() {
    assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
    assert_ne!(HashAlgorithm::Sha384, HashAlgorithm::Sha512);
}
