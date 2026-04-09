// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for cose_sign1_certificates_local.

use cose_sign1_certificates_local::*;

#[test]
fn test_software_key_provider_name() {
    let provider = SoftwareKeyProvider::new();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

#[test]
fn test_supports_algorithms() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::Rsa));
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
    #[cfg(feature = "pqc")]
    assert!(!provider.supports_algorithm(KeyAlgorithm::MlDsa));
}

#[test]
fn test_key_generation_rsa_supported() {
    let provider = SoftwareKeyProvider::new();
    let result = provider.generate_key(KeyAlgorithm::Rsa, Some(2048));
    assert!(result.is_ok(), "RSA key generation should succeed: {:?}", result.err());
    let key = result.unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(key.key_size, 2048);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn test_key_generation_ecdsa_works() {
    let provider = SoftwareKeyProvider::new();
    let result = provider.generate_key(KeyAlgorithm::Ecdsa, Some(256));
    assert!(result.is_ok());
    let key = result.unwrap();
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn test_key_algorithm_defaults() {
    assert_eq!(KeyAlgorithm::Rsa.default_key_size(), 2048);
    assert_eq!(KeyAlgorithm::Ecdsa.default_key_size(), 256);
    #[cfg(feature = "pqc")]
    assert_eq!(KeyAlgorithm::MlDsa.default_key_size(), 65);
}

#[test]
fn test_certificate_options_defaults() {
    let opts = CertificateOptions::default();
    assert_eq!(opts.subject_name, "CN=Ephemeral Certificate");
    assert!(matches!(opts.key_algorithm, KeyAlgorithm::Ecdsa));
    assert!(matches!(opts.hash_algorithm, HashAlgorithm::Sha256));
    assert_eq!(opts.validity.as_secs(), 3600); // 1 hour
    assert_eq!(opts.not_before_offset.as_secs(), 300); // 5 minutes
    assert!(!opts.is_ca);
    assert_eq!(opts.path_length_constraint, 0);
    assert_eq!(opts.enhanced_key_usages.len(), 1);
    assert_eq!(opts.enhanced_key_usages[0], "1.3.6.1.5.5.7.3.3");
}

#[test]
fn test_certificate_options_builder() {
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Test Certificate")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(384)
        .with_hash_algorithm(HashAlgorithm::Sha384)
        .as_ca(2);

    assert_eq!(opts.subject_name, "CN=Test Certificate");
    assert!(matches!(opts.key_algorithm, KeyAlgorithm::Ecdsa));
    assert_eq!(opts.key_size, Some(384));
    assert!(matches!(opts.hash_algorithm, HashAlgorithm::Sha384));
    assert!(opts.is_ca);
    assert_eq!(opts.path_length_constraint, 2);
}

#[test]
fn test_certificate_new() {
    let cert_der = vec![0x30, 0x82]; // Mock DER certificate start
    let cert = Certificate::new(cert_der.clone());
    assert_eq!(cert.cert_der, cert_der);
    assert!(!cert.has_private_key());
    assert_eq!(cert.chain.len(), 0);
}

#[test]
fn test_certificate_with_private_key() {
    let cert_der = vec![0x30, 0x82];
    let key_der = vec![0x30, 0x81];
    let cert = Certificate::with_private_key(cert_der, key_der);
    assert!(cert.has_private_key());
}

#[test]
fn test_certificate_with_chain() {
    let cert_der = vec![0x30, 0x82];
    let chain = vec![vec![0x30, 0x83], vec![0x30, 0x84]];
    let cert = Certificate::new(cert_der).with_chain(chain.clone());
    assert_eq!(cert.chain.len(), 2);
}
