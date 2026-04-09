// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge-case coverage for cose_sign1_certificates_local: error Display,
//! CertificateFormat, KeyAlgorithm, CertificateOptions builder,
//! LoadedCertificate, loader error paths, and SoftwareKeyProvider.

use std::time::Duration;

use cose_sign1_certificates_local::traits::PrivateKeyProvider;
use cose_sign1_certificates_local::{
    CertLocalError, Certificate, CertificateFormat, CertificateOptions, HashAlgorithm,
    KeyAlgorithm, LoadedCertificate, SoftwareKeyProvider,
};

// ---------- error Display (all variants) ----------

#[test]
fn error_display_all_variants() {
    let cases: Vec<(CertLocalError, &str)> = vec![
        (
            CertLocalError::KeyGenerationFailed("k".into()),
            "key generation failed: k",
        ),
        (
            CertLocalError::CertificateCreationFailed("c".into()),
            "certificate creation failed: c",
        ),
        (
            CertLocalError::InvalidOptions("o".into()),
            "invalid options: o",
        ),
        (
            CertLocalError::UnsupportedAlgorithm("a".into()),
            "unsupported algorithm: a",
        ),
        (CertLocalError::IoError("i".into()), "I/O error: i"),
        (CertLocalError::LoadFailed("l".into()), "load failed: l"),
    ];
    for (err, expected) in cases {
        assert_eq!(format!("{err}"), expected);
    }
}

#[test]
fn error_implements_std_error() {
    let err = CertLocalError::IoError("test".into());
    let _: &dyn std::error::Error = &err;
}

// ---------- CertificateFormat ----------

#[test]
fn certificate_format_variants() {
    assert_eq!(CertificateFormat::Der, CertificateFormat::Der);
    assert_ne!(CertificateFormat::Pem, CertificateFormat::Pfx);
    let _ = format!("{:?}", CertificateFormat::WindowsStore);
}

// ---------- KeyAlgorithm ----------

#[test]
fn key_algorithm_defaults_to_ecdsa() {
    assert_eq!(KeyAlgorithm::default(), KeyAlgorithm::Ecdsa);
}

#[test]
fn key_algorithm_default_sizes() {
    assert_eq!(KeyAlgorithm::Rsa.default_key_size(), 2048);
    assert_eq!(KeyAlgorithm::Ecdsa.default_key_size(), 256);
}

// ---------- HashAlgorithm ----------

#[test]
fn hash_algorithm_default_is_sha256() {
    assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha256);
}

// ---------- CertificateOptions builder ----------

#[test]
fn options_default_subject_name() {
    let opts = CertificateOptions::new();
    assert_eq!(opts.subject_name, "CN=Ephemeral Certificate");
    assert!(!opts.is_ca);
}

#[test]
fn options_fluent_builder_chain() {
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Test")
        .with_key_algorithm(KeyAlgorithm::Rsa)
        .with_key_size(4096)
        .with_hash_algorithm(HashAlgorithm::Sha512)
        .with_validity(Duration::from_secs(7200))
        .as_ca(2)
        .add_subject_alternative_name("dns:example.com");

    assert_eq!(opts.subject_name, "CN=Test");
    assert_eq!(opts.key_algorithm, KeyAlgorithm::Rsa);
    assert_eq!(opts.key_size, Some(4096));
    assert_eq!(opts.hash_algorithm, HashAlgorithm::Sha512);
    assert!(opts.is_ca);
    assert_eq!(opts.path_length_constraint, 2);
    assert_eq!(opts.subject_alternative_names.len(), 1);
}

// ---------- Certificate ----------

#[test]
fn certificate_new_no_key() {
    let cert = Certificate::new(vec![1, 2, 3]);
    assert!(!cert.has_private_key());
    assert!(cert.chain.is_empty());
}

#[test]
fn certificate_with_private_key() {
    let cert = Certificate::with_private_key(vec![1], vec![2]);
    assert!(cert.has_private_key());
}

#[test]
fn certificate_with_chain() {
    let cert = Certificate::new(vec![1]).with_chain(vec![vec![2], vec![3]]);
    assert_eq!(cert.chain.len(), 2);
}

// ---------- LoadedCertificate ----------

#[test]
fn loaded_certificate_construction() {
    let cert = Certificate::new(vec![0xAA]);
    let loaded = LoadedCertificate::new(cert, CertificateFormat::Der);
    assert_eq!(loaded.source_format, CertificateFormat::Der);
}

// ---------- Loader error paths ----------

#[test]
fn load_der_nonexistent_path() {
    let result = cose_sign1_certificates_local::loaders::der::load_cert_from_der(
        "/tmp/nonexistent_cert_file_abc123.der",
    );
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("I/O error"), "got: {msg}");
}

#[test]
fn load_pem_nonexistent_path() {
    let result = cose_sign1_certificates_local::loaders::pem::load_cert_from_pem(
        "/tmp/nonexistent_cert_file_abc123.pem",
    );
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("I/O error"), "got: {msg}");
}

// ---------- SoftwareKeyProvider ----------

#[test]
fn software_key_provider_supports_ecdsa() {
    let provider = SoftwareKeyProvider::new();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
    assert!(provider.supports_algorithm(KeyAlgorithm::Rsa));
}

#[test]
fn software_key_provider_generate_ecdsa() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Ecdsa, None).unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn software_key_provider_rsa_supported() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Rsa, None).unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Rsa);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}
