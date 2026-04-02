// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for factory.rs module in certificates local.

use cose_sign1_certificates_local::key_algorithm::KeyAlgorithm;
use cose_sign1_certificates_local::options::{CertificateOptions, HashAlgorithm, KeyUsageFlags};
use cose_sign1_certificates_local::traits::GeneratedKey;
use cose_sign1_certificates_local::Certificate;
use std::time::Duration;

#[test]
fn test_certificate_options_default() {
    let options = CertificateOptions::default();
    assert_eq!(options.subject_name, "CN=Ephemeral Certificate");
    assert_eq!(options.key_algorithm, KeyAlgorithm::Ecdsa);
    assert_eq!(options.validity, Duration::from_secs(3600));
    assert!(!options.is_ca);
}

#[test]
fn test_certificate_options_new() {
    let options = CertificateOptions::new();
    assert_eq!(options.subject_name, "CN=Ephemeral Certificate");
}

#[test]
fn test_certificate_options_with_subject_name() {
    let options = CertificateOptions::new().with_subject_name("CN=test.example.com");
    assert_eq!(options.subject_name, "CN=test.example.com");
}

#[test]
fn test_certificate_options_with_key_algorithm() {
    let options = CertificateOptions::new().with_key_algorithm(KeyAlgorithm::Rsa);
    assert_eq!(options.key_algorithm, KeyAlgorithm::Rsa);
}

#[test]
fn test_certificate_options_with_key_size() {
    let options = CertificateOptions::new().with_key_size(4096);
    assert_eq!(options.key_size, Some(4096));
}

#[test]
fn test_certificate_options_with_hash_algorithm() {
    let options = CertificateOptions::new().with_hash_algorithm(HashAlgorithm::Sha512);
    assert!(matches!(options.hash_algorithm, HashAlgorithm::Sha512));
}

#[test]
fn test_certificate_options_with_validity() {
    let duration = Duration::from_secs(86400); // 1 day
    let options = CertificateOptions::new().with_validity(duration);
    assert_eq!(options.validity, duration);
}

#[test]
fn test_certificate_options_with_not_before_offset() {
    let offset = Duration::from_secs(300); // 5 minutes
    let options = CertificateOptions::new().with_not_before_offset(offset);
    assert_eq!(options.not_before_offset, offset);
}

#[test]
fn test_certificate_options_as_ca() {
    let options = CertificateOptions::new().as_ca(3);
    assert!(options.is_ca);
    assert_eq!(options.path_length_constraint, 3);
}

#[test]
fn test_certificate_options_with_key_usage() {
    let options = CertificateOptions::new().with_key_usage(KeyUsageFlags::KEY_ENCIPHERMENT);
    assert_eq!(
        options.key_usage.flags,
        KeyUsageFlags::KEY_ENCIPHERMENT.flags
    );
}

#[test]
fn test_certificate_options_with_enhanced_key_usages() {
    let ekus = vec!["serverAuth".to_string(), "clientAuth".to_string()];
    let options = CertificateOptions::new().with_enhanced_key_usages(ekus.clone());
    assert_eq!(options.enhanced_key_usages, ekus);
}

#[test]
fn test_certificate_options_add_subject_alternative_name() {
    let options = CertificateOptions::new()
        .add_subject_alternative_name("dns:alt1.example.com")
        .add_subject_alternative_name("dns:alt2.example.com");
    assert_eq!(options.subject_alternative_names.len(), 2);
    assert_eq!(options.subject_alternative_names[0], "dns:alt1.example.com");
    assert_eq!(options.subject_alternative_names[1], "dns:alt2.example.com");
}

#[test]
fn test_certificate_options_signed_by() {
    let issuer = Certificate::new(vec![1, 2, 3, 4]);
    let options = CertificateOptions::new().signed_by(issuer);
    assert!(options.issuer.is_some());
}

#[test]
fn test_certificate_options_add_custom_extension_der() {
    let ext = vec![0x30, 0x00]; // Empty sequence
    let options = CertificateOptions::new().add_custom_extension_der(ext.clone());
    assert_eq!(options.custom_extensions_der.len(), 1);
    assert_eq!(options.custom_extensions_der[0], ext);
}

#[test]
fn test_certificate_new() {
    let cert_der = vec![1, 2, 3, 4, 5];
    let cert = Certificate::new(cert_der.clone());
    assert_eq!(cert.cert_der, cert_der);
    assert!(cert.private_key_der.is_none());
    assert!(cert.chain.is_empty());
}

#[test]
fn test_certificate_with_private_key() {
    let cert_der = vec![1, 2, 3];
    let key_der = vec![4, 5, 6];
    let cert = Certificate::with_private_key(cert_der.clone(), key_der.clone());
    assert_eq!(cert.cert_der, cert_der);
    assert_eq!(cert.private_key_der, Some(key_der));
}

#[test]
fn test_certificate_has_private_key() {
    let cert_without = Certificate::new(vec![1, 2, 3]);
    assert!(!cert_without.has_private_key());

    let cert_with = Certificate::with_private_key(vec![1, 2, 3], vec![4, 5, 6]);
    assert!(cert_with.has_private_key());
}

#[test]
fn test_certificate_with_chain() {
    let cert = Certificate::new(vec![1, 2, 3]);
    let chain = vec![vec![7, 8, 9], vec![10, 11, 12]];
    let cert_with_chain = cert.with_chain(chain.clone());
    assert_eq!(cert_with_chain.chain, chain);
}

#[test]
fn test_certificate_thumbprint_sha256() {
    let cert = Certificate::new(vec![1, 2, 3, 4, 5]);
    let thumbprint = cert.thumbprint_sha256();
    assert_eq!(thumbprint.len(), 32);
}

#[test]
fn test_certificate_clone() {
    let cert = Certificate::with_private_key(vec![1, 2, 3], vec![4, 5, 6]);
    let cloned = cert.clone();
    assert_eq!(cloned.cert_der, cert.cert_der);
    assert_eq!(cloned.private_key_der, cert.private_key_der);
}

#[test]
fn test_certificate_debug() {
    let cert = Certificate::with_private_key(vec![1, 2, 3], vec![4, 5, 6]);
    let debug_str = format!("{:?}", cert);
    assert!(debug_str.contains("Certificate"));
    assert!(debug_str.contains("cert_der_len"));
    assert!(debug_str.contains("has_private_key"));
}

#[test]
fn test_generated_key_clone() {
    let key = GeneratedKey {
        private_key_der: vec![1, 2, 3],
        public_key_der: vec![4, 5, 6],
        algorithm: KeyAlgorithm::Ecdsa,
        key_size: 256,
    };
    let cloned = key.clone();
    assert_eq!(cloned.private_key_der, key.private_key_der);
    assert_eq!(cloned.public_key_der, key.public_key_der);
    assert_eq!(cloned.algorithm, key.algorithm);
    assert_eq!(cloned.key_size, key.key_size);
}

#[test]
fn test_generated_key_debug() {
    let key = GeneratedKey {
        private_key_der: vec![1, 2, 3],
        public_key_der: vec![4, 5, 6],
        algorithm: KeyAlgorithm::Ecdsa,
        key_size: 256,
    };
    let debug_str = format!("{:?}", key);
    assert!(debug_str.contains("GeneratedKey"));
}

#[test]
fn test_key_algorithm_default() {
    let alg = KeyAlgorithm::default();
    assert!(matches!(alg, KeyAlgorithm::Ecdsa));
}

#[test]
fn test_key_algorithm_default_key_size_ecdsa() {
    assert_eq!(KeyAlgorithm::Ecdsa.default_key_size(), 256);
}

#[test]
fn test_key_algorithm_default_key_size_rsa() {
    assert_eq!(KeyAlgorithm::Rsa.default_key_size(), 2048);
}

#[test]
fn test_hash_algorithm_default() {
    let alg = HashAlgorithm::default();
    assert!(matches!(alg, HashAlgorithm::Sha256));
}

#[test]
fn test_key_usage_flags_digital_signature() {
    let flags = KeyUsageFlags::DIGITAL_SIGNATURE;
    assert_eq!(flags.flags, 0x80);
}

#[test]
fn test_key_usage_flags_key_encipherment() {
    let flags = KeyUsageFlags::KEY_ENCIPHERMENT;
    assert_eq!(flags.flags, 0x20);
}

#[test]
fn test_key_usage_flags_key_cert_sign() {
    let flags = KeyUsageFlags::KEY_CERT_SIGN;
    assert_eq!(flags.flags, 0x04);
}

#[test]
fn test_key_usage_flags_default() {
    let flags = KeyUsageFlags::default();
    assert_eq!(flags.flags, KeyUsageFlags::DIGITAL_SIGNATURE.flags);
}
