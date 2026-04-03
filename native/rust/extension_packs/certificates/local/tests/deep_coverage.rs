// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for cose_sign1_certificates_local targeting specific uncovered lines.
//!
//! Focuses on code paths not exercised by existing tests:
//! - SoftwareKeyProvider::generate_key() called directly (software_key.rs)
//! - SoftwareKeyProvider::name(), supports_algorithm(), Default trait (software_key.rs)
//! - Certificate::subject(), thumbprint_sha256(), Debug (certificate.rs)
//! - DER loader: missing key file path (loaders/der.rs)
//! - PEM loader: missing end marker, invalid UTF-8 (loaders/pem.rs)
//! - CertificateChainFactory: leaf-first two-tier chain (chain_factory.rs)
//! - CertificateOptions fluent builder methods: with_hash_algorithm,
//!   add_subject_alternative_name, add_custom_extension_der
//! - KeyAlgorithm::default_key_size() for RSA
//! - HashAlgorithm variants and Default
//! - KeyUsageFlags combinations
//! - LoadedCertificate with various formats

use cose_sign1_certificates_local::loaders;
use cose_sign1_certificates_local::*;
use std::time::Duration;

/// Helper: create factory with SoftwareKeyProvider.
fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

/// Helper: create a valid self-signed ECDSA certificate.
fn make_cert() -> Certificate {
    let factory = make_factory();
    factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Test Certificate")
                .with_key_algorithm(KeyAlgorithm::Ecdsa),
        )
        .unwrap()
}

// ===========================================================================
// software_key.rs — SoftwareKeyProvider direct usage
// ===========================================================================

#[test]
fn software_key_provider_name() {
    let provider = SoftwareKeyProvider::new();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

#[test]
fn software_key_provider_default_trait() {
    let provider = SoftwareKeyProvider::default();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

#[test]
fn software_key_provider_supports_ecdsa() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
}

#[test]
fn software_key_provider_does_not_support_rsa() {
    let provider = SoftwareKeyProvider::new();
    assert!(!provider.supports_algorithm(KeyAlgorithm::Rsa));
}

#[test]
fn software_key_provider_generate_ecdsa_key() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Ecdsa, None).unwrap();

    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
    assert_eq!(key.key_size, KeyAlgorithm::Ecdsa.default_key_size());
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn software_key_provider_generate_ecdsa_with_explicit_size() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Ecdsa, Some(256))
        .unwrap();

    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
    assert_eq!(key.key_size, 256);
    assert!(!key.private_key_der.is_empty());
}

#[test]
fn software_key_provider_generate_rsa_fails() {
    let provider = SoftwareKeyProvider::new();
    let result = provider.generate_key(KeyAlgorithm::Rsa, None);

    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("not supported") || err.contains("not yet implemented"),
        "got: {err}"
    );
}

#[test]
fn software_key_provider_generate_rsa_with_size_fails() {
    let provider = SoftwareKeyProvider::new();
    let result = provider.generate_key(KeyAlgorithm::Rsa, Some(2048));
    assert!(result.is_err());
}

// ===========================================================================
// certificate.rs — Certificate utility methods
// ===========================================================================

#[test]
fn certificate_subject() {
    let cert = make_cert();
    let subject = cert.subject().unwrap();
    assert!(subject.contains("Test Certificate"), "subject: {subject}");
}

#[test]
fn certificate_thumbprint_sha256() {
    let cert = make_cert();
    let thumbprint = cert.thumbprint_sha256();

    // SHA-256 thumbprint is 32 bytes
    assert_eq!(thumbprint.len(), 32);

    // Should be deterministic
    let thumbprint2 = cert.thumbprint_sha256();
    assert_eq!(thumbprint, thumbprint2);
}

#[test]
fn certificate_debug_formatting() {
    let cert = make_cert();
    let debug_str = format!("{:?}", cert);

    assert!(debug_str.contains("Certificate"));
    assert!(debug_str.contains("cert_der_len"));
    assert!(debug_str.contains("has_private_key"));
    assert!(debug_str.contains("chain_len"));
}

#[test]
fn certificate_new_without_key() {
    let cert = make_cert();
    let pub_only = Certificate::new(cert.cert_der.clone());

    assert!(!pub_only.has_private_key());
    assert!(pub_only.private_key_der.is_none());
    assert!(pub_only.chain.is_empty());
}

#[test]
fn certificate_with_chain_builder() {
    let cert1 = make_cert();
    let cert2 = make_cert();

    let cert_with_chain =
        Certificate::new(cert1.cert_der.clone()).with_chain(vec![cert2.cert_der.clone()]);

    assert_eq!(cert_with_chain.chain.len(), 1);
    assert_eq!(cert_with_chain.chain[0], cert2.cert_der);
}

// ===========================================================================
// key_algorithm.rs — KeyAlgorithm defaults
// ===========================================================================

#[test]
fn key_algorithm_default_is_ecdsa() {
    let default = KeyAlgorithm::default();
    assert_eq!(default, KeyAlgorithm::Ecdsa);
}

#[test]
fn key_algorithm_default_key_sizes() {
    assert_eq!(KeyAlgorithm::Ecdsa.default_key_size(), 256);
    assert_eq!(KeyAlgorithm::Rsa.default_key_size(), 2048);
}

// ===========================================================================
// options.rs — HashAlgorithm and KeyUsageFlags
// ===========================================================================

#[test]
fn hash_algorithm_default_is_sha256() {
    let default = HashAlgorithm::default();
    assert_eq!(default, HashAlgorithm::Sha256);
}

#[test]
fn hash_algorithm_variants() {
    // Just ensure they're distinct and constructible
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
    assert_ne!(HashAlgorithm::Sha384, HashAlgorithm::Sha512);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha512);
}

#[test]
fn key_usage_flags_default_is_digital_signature() {
    let default = KeyUsageFlags::default();
    assert_eq!(default.flags, KeyUsageFlags::DIGITAL_SIGNATURE.flags);
}

#[test]
fn key_usage_flags_combinations() {
    let combined = KeyUsageFlags {
        flags: KeyUsageFlags::DIGITAL_SIGNATURE.flags
            | KeyUsageFlags::KEY_CERT_SIGN.flags
            | KeyUsageFlags::KEY_ENCIPHERMENT.flags,
    };
    assert_ne!(combined.flags, 0);
    assert!(combined.flags & KeyUsageFlags::DIGITAL_SIGNATURE.flags != 0);
    assert!(combined.flags & KeyUsageFlags::KEY_CERT_SIGN.flags != 0);
    assert!(combined.flags & KeyUsageFlags::KEY_ENCIPHERMENT.flags != 0);
}

// ===========================================================================
// options.rs — CertificateOptions fluent builder methods
// ===========================================================================

#[test]
fn certificate_options_with_hash_algorithm() {
    let opts = CertificateOptions::new().with_hash_algorithm(HashAlgorithm::Sha384);
    assert_eq!(opts.hash_algorithm, HashAlgorithm::Sha384);
}

#[test]
fn certificate_options_add_subject_alternative_name() {
    let opts = CertificateOptions::new()
        .add_subject_alternative_name("dns:example.com")
        .add_subject_alternative_name("dns:test.example.com");

    assert_eq!(opts.subject_alternative_names.len(), 2);
    assert_eq!(opts.subject_alternative_names[0], "dns:example.com");
    assert_eq!(opts.subject_alternative_names[1], "dns:test.example.com");
}

#[test]
fn certificate_options_add_custom_extension_der() {
    let ext_bytes = vec![0x30, 0x03, 0x01, 0x01, 0xFF];
    let opts = CertificateOptions::new().add_custom_extension_der(ext_bytes.clone());

    assert_eq!(opts.custom_extensions_der.len(), 1);
    assert_eq!(opts.custom_extensions_der[0], ext_bytes);
}

#[test]
fn certificate_options_with_not_before_offset() {
    let opts = CertificateOptions::new().with_not_before_offset(Duration::from_secs(300));
    assert_eq!(opts.not_before_offset, Duration::from_secs(300));
}

#[test]
fn certificate_options_with_enhanced_key_usages() {
    let opts =
        CertificateOptions::new().with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.1".to_string()]);

    assert_eq!(opts.enhanced_key_usages.len(), 1);
    assert_eq!(opts.enhanced_key_usages[0], "1.3.6.1.5.5.7.3.1");
}

// ===========================================================================
// loaders/der.rs — Error paths
// ===========================================================================

#[test]
fn der_load_missing_cert_file() {
    let result = loaders::der::load_cert_from_der("nonexistent_cert_file.der");
    assert!(result.is_err());
    match result {
        Err(CertLocalError::IoError(msg)) => {
            assert!(!msg.is_empty());
        }
        _other => panic!("expected IoError, got unexpected error variant"),
    }
}

#[test]
fn der_load_missing_key_file() {
    let cert = make_cert();
    let temp_dir = std::env::temp_dir().join("deep_coverage_der_tests");
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cert_path = temp_dir.join("valid_cert.der");
    std::fs::write(&cert_path, &cert.cert_der).unwrap();

    let missing_key_path = temp_dir.join("nonexistent_key.der");
    let result = loaders::der::load_cert_and_key_from_der(&cert_path, &missing_key_path);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::IoError(msg)) => {
            assert!(!msg.is_empty());
        }
        _other => panic!("expected IoError, got unexpected error variant"),
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn der_load_invalid_cert_bytes() {
    let result = loaders::der::load_cert_from_der_bytes(&[0x00, 0x01, 0x02]);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("invalid DER"));
        }
        _other => panic!("expected LoadFailed, got unexpected error variant"),
    }
}

// ===========================================================================
// loaders/pem.rs — Error paths
// ===========================================================================

#[test]
fn pem_load_missing_end_marker() {
    let pem = b"-----BEGIN CERTIFICATE-----\nSGVsbG8=\n";
    let result = loaders::pem::load_cert_from_pem_bytes(pem);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(
                msg.contains("missing end marker"),
                "error did not contain expected 'missing end marker' substring"
            );
        }
        _other => {
            panic!("expected LoadFailed with missing end marker, got unexpected error variant")
        }
    }
}

#[test]
fn pem_load_invalid_utf8() {
    let invalid_bytes: &[u8] = &[0xFF, 0xFE, 0xFD];
    let result = loaders::pem::load_cert_from_pem_bytes(invalid_bytes);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(
                msg.contains("UTF-8"),
                "error did not contain expected 'UTF-8' substring"
            );
        }
        _other => panic!("expected LoadFailed with UTF-8 error, got unexpected error variant"),
    }
}

#[test]
fn pem_load_no_certificate_only_key() {
    let pem = b"-----BEGIN PRIVATE KEY-----\nSGVsbG8=\n-----END PRIVATE KEY-----\n";
    let result = loaders::pem::load_cert_from_pem_bytes(pem);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(
                msg.contains("no certificate"),
                "error did not contain expected 'no certificate' substring"
            );
        }
        _other => {
            panic!("expected LoadFailed with no certificate error, got unexpected error variant")
        }
    }
}

#[test]
fn pem_load_missing_file() {
    let result = loaders::pem::load_cert_from_pem("nonexistent_pem_file.pem");
    assert!(result.is_err());
    match result {
        Err(CertLocalError::IoError(_)) => {}
        _other => panic!("expected IoError, got unexpected error variant"),
    }
}

// ===========================================================================
// loaders/mod.rs — LoadedCertificate wrapper
// ===========================================================================

#[test]
fn loaded_certificate_all_formats() {
    let cert = make_cert();

    for format in [
        CertificateFormat::Der,
        CertificateFormat::Pem,
        CertificateFormat::Pfx,
        CertificateFormat::WindowsStore,
    ] {
        let loaded = LoadedCertificate::new(cert.clone(), format);
        assert_eq!(loaded.source_format, format);
        assert_eq!(loaded.certificate.cert_der, cert.cert_der);
    }
}

// ===========================================================================
// error.rs — CertLocalError Display and conversions
// ===========================================================================

#[test]
fn cert_local_error_display_variants() {
    let errors = vec![
        CertLocalError::KeyGenerationFailed("test".to_string()),
        CertLocalError::CertificateCreationFailed("test".to_string()),
        CertLocalError::InvalidOptions("test".to_string()),
        CertLocalError::UnsupportedAlgorithm("test".to_string()),
        CertLocalError::IoError("test".to_string()),
        CertLocalError::LoadFailed("test".to_string()),
    ];

    for err in &errors {
        let display = format!("{}", err);
        assert!(display.contains("test"), "display for {:?}: {display}", err);
    }
}

#[test]
fn cert_local_error_is_std_error() {
    let err = CertLocalError::KeyGenerationFailed("test".to_string());
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// chain_factory.rs — Two-tier chain with leaf-first ordering
// ===========================================================================

#[test]
fn chain_two_tier_leaf_first() {
    let factory = make_factory();
    let chain_factory = CertificateChainFactory::new(factory);

    let opts = CertificateChainOptions::new()
        .with_intermediate_name(None::<String>)
        .with_leaf_first(true);

    let chain = chain_factory.create_chain_with_options(opts).unwrap();
    assert_eq!(chain.len(), 2);

    use x509_parser::prelude::*;
    let first = X509Certificate::from_der(&chain[0].cert_der).unwrap().1;
    let second = X509Certificate::from_der(&chain[1].cert_der).unwrap().1;

    // First should be leaf, second should be root
    assert!(
        first.subject().to_string().contains("Leaf"),
        "first should be leaf: {}",
        first.subject()
    );
    assert!(
        second.subject().to_string().contains("Root"),
        "second should be root: {}",
        second.subject()
    );
}

// ===========================================================================
// chain_factory.rs — CertificateChainOptions fluent builder
// ===========================================================================

#[test]
fn chain_options_all_setters() {
    let opts = CertificateChainOptions::new()
        .with_root_name("CN=My Root")
        .with_intermediate_name(Some("CN=My Intermediate"))
        .with_leaf_name("CN=My Leaf")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256)
        .with_root_validity(Duration::from_secs(86400))
        .with_intermediate_validity(Duration::from_secs(43200))
        .with_leaf_validity(Duration::from_secs(3600))
        .with_leaf_only_private_key(true)
        .with_leaf_first(false)
        .with_leaf_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.3".to_string()]);

    assert_eq!(opts.root_name, "CN=My Root");
    assert_eq!(
        opts.intermediate_name.as_deref(),
        Some("CN=My Intermediate")
    );
    assert_eq!(opts.leaf_name, "CN=My Leaf");
    assert_eq!(opts.key_algorithm, KeyAlgorithm::Ecdsa);
    assert_eq!(opts.key_size, Some(256));
    assert_eq!(opts.root_validity, Duration::from_secs(86400));
    assert_eq!(opts.intermediate_validity, Duration::from_secs(43200));
    assert_eq!(opts.leaf_validity, Duration::from_secs(3600));
    assert!(opts.leaf_only_private_key);
    assert!(!opts.leaf_first);
    assert_eq!(opts.leaf_enhanced_key_usages.unwrap().len(), 1);
}

// ===========================================================================
// factory.rs — CertificateFactory trait default method
// ===========================================================================

#[test]
fn certificate_factory_trait_key_provider() {
    let factory = make_factory();
    let provider: &dyn PrivateKeyProvider = factory.key_provider();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
    assert!(!provider.supports_algorithm(KeyAlgorithm::Rsa));
}

// ===========================================================================
// factory.rs — Issuer-signed cert with typed key round-trip
// ===========================================================================

#[test]
fn issuer_signed_cert_chain_linkage() {
    let factory = make_factory();

    let root = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Deep Root CA")
                .as_ca(1)
                .with_validity(Duration::from_secs(86400)),
        )
        .unwrap();

    let leaf = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Deep Leaf")
                .with_validity(Duration::from_secs(3600))
                .signed_by(root.clone()),
        )
        .unwrap();

    assert!(leaf.has_private_key());

    use x509_parser::prelude::*;
    let parsed_root = X509Certificate::from_der(&root.cert_der).unwrap().1;
    let parsed_leaf = X509Certificate::from_der(&leaf.cert_der).unwrap().1;

    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_root.subject().to_string(),
        "leaf issuer should match root subject"
    );
}

// ===========================================================================
// factory.rs — Issuer without private key error
// ===========================================================================

#[test]
fn issuer_without_private_key_returns_error() {
    let factory = make_factory();

    // Create issuer with no private key
    let cert = make_cert();
    let issuer_no_key = Certificate::new(cert.cert_der);

    let result = factory.create_certificate(
        CertificateOptions::new()
            .with_subject_name("CN=Should Fail Leaf")
            .signed_by(issuer_no_key),
    );

    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("private key"), "got: {err}");
}

// ===========================================================================
// Miscellaneous: GeneratedKey Clone derive
// ===========================================================================

#[test]
fn generated_key_clone() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Ecdsa, None).unwrap();

    let cloned = key.clone();
    assert_eq!(cloned.algorithm, key.algorithm);
    assert_eq!(cloned.key_size, key.key_size);
    assert_eq!(cloned.private_key_der, key.private_key_der);
    assert_eq!(cloned.public_key_der, key.public_key_der);
}

#[test]
fn generated_key_debug() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Ecdsa, None).unwrap();
    let debug_str = format!("{:?}", key);
    assert!(debug_str.contains("GeneratedKey"));
}
