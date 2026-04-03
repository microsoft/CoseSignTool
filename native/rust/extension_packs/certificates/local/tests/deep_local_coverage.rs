// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for cose_sign1_certificates_local factory.rs.
//!
//! Targets uncovered lines in factory.rs:
//! - RSA unsupported error path (line 156-160)
//! - Issuer-signed certificate path (lines 228-256)
//! - Issuer without private key error (lines 245-248)
//! - CA certificate creation with BasicConstraints + KeyUsage (lines 211-224)
//! - CA with path_length_constraint == u32::MAX (no pathlen bound, line 214)
//! - Subject name with and without "CN=" prefix (line 187)
//! - get_generated_key / release_key lifecycle
//! - key_algorithm.default_key_size() for key_size default (line 298)

use cose_sign1_certificates_local::traits::CertificateFactory;
use cose_sign1_certificates_local::*;
use std::time::Duration;
use x509_parser::prelude::*;

/// Helper: create factory with SoftwareKeyProvider.
fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

/// Helper: parse cert and return the X509Certificate for assertions.
fn parse_cert(der: &[u8]) -> X509Certificate<'_> {
    X509Certificate::from_der(der).unwrap().1
}

// =========================================================================
// factory.rs — RSA unsupported path (lines 156-160)
// =========================================================================

#[test]
fn create_certificate_rsa_returns_unsupported() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=RSA Unsupported")
        .with_key_algorithm(KeyAlgorithm::Rsa);

    let result = factory.create_certificate(opts);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = format!("{}", err);
    assert!(
        msg.contains("not yet implemented") || msg.contains("unsupported"),
        "got: {msg}"
    );
}

// =========================================================================
// factory.rs — self-signed cert with explicit "CN=" prefix (line 187)
// =========================================================================

#[test]
fn create_certificate_subject_with_cn_prefix() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Explicit Prefix");

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    assert!(
        parsed.subject().to_string().contains("Explicit Prefix"),
        "subject: {}",
        parsed.subject()
    );
}

#[test]
fn create_certificate_subject_without_cn_prefix() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("No Prefix Here");

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    assert!(
        parsed.subject().to_string().contains("No Prefix Here"),
        "subject: {}",
        parsed.subject()
    );
}

// =========================================================================
// factory.rs — CA with BasicConstraints + KeyUsage (lines 211-224)
// =========================================================================

#[test]
fn create_ca_certificate_with_path_length() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Test CA")
        .as_ca(2);

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);

    let bc = parsed.basic_constraints().unwrap().unwrap().value;
    assert!(bc.ca);
    assert_eq!(bc.path_len_constraint, Some(2));

    // KeyUsage should include keyCertSign and cRLSign.
    let ku = parsed.key_usage().unwrap().unwrap().value;
    assert!(ku.key_cert_sign());
    assert!(ku.crl_sign());
}

#[test]
fn create_ca_certificate_with_max_path_length() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Unbounded CA")
        .as_ca(u32::MAX);

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);

    let bc = parsed.basic_constraints().unwrap().unwrap().value;
    assert!(bc.ca, "should be CA");
    // When path_length_constraint == u32::MAX, pathlen is NOT set.
    assert!(
        bc.path_len_constraint.is_none(),
        "u32::MAX should mean no pathlen constraint"
    );
}

#[test]
fn create_non_ca_certificate_has_no_basic_constraints_ca() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Not A CA");

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);

    // Non-CA certs may or may not have BasicConstraints, but if present, ca should be false.
    if let Ok(Some(bc_ext)) = parsed.basic_constraints() {
        assert!(!bc_ext.value.ca);
    }
}

// =========================================================================
// factory.rs — Issuer-signed certificate path (lines 228-256)
// =========================================================================

#[test]
fn create_issuer_signed_certificate() {
    let factory = make_factory();

    // Create CA cert.
    let ca_opts = CertificateOptions::new()
        .with_subject_name("CN=Issuer CA")
        .as_ca(1);
    let ca_cert = factory.create_certificate(ca_opts).unwrap();

    // Create leaf signed by CA.
    let leaf_opts = CertificateOptions::new()
        .with_subject_name("CN=Leaf Signed By CA")
        .signed_by(ca_cert.clone());

    let leaf_cert = factory.create_certificate(leaf_opts).unwrap();
    assert!(leaf_cert.has_private_key());

    let parsed_leaf = parse_cert(&leaf_cert.cert_der);
    assert!(
        parsed_leaf
            .subject()
            .to_string()
            .contains("Leaf Signed By CA"),
        "subject: {}",
        parsed_leaf.subject()
    );

    // Issuer should be the CA subject.
    let parsed_ca = parse_cert(&ca_cert.cert_der);
    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_ca.subject().to_string(),
        "leaf issuer should match CA subject"
    );
}

#[test]
fn create_issuer_signed_certificate_without_private_key_fails() {
    let factory = make_factory();

    // Create an issuer cert WITHOUT a private key.
    let issuer_no_key = Certificate::new(vec![0x30, 0x00]);

    let leaf_opts = CertificateOptions::new()
        .with_subject_name("CN=Should Fail")
        .signed_by(issuer_no_key);

    let result = factory.create_certificate(leaf_opts);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("private key"),
        "expected private key error, got: {msg}"
    );
}

// =========================================================================
// factory.rs — Validity period with not_before_offset (lines 195-204)
// =========================================================================

#[test]
fn create_certificate_custom_validity_and_offset() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=Validity Test")
        .with_validity(Duration::from_secs(86400)) // 1 day
        .with_not_before_offset(Duration::from_secs(600)); // 10 minutes

    let cert = factory.create_certificate(opts).unwrap();
    let parsed = parse_cert(&cert.cert_der);
    let validity = parsed.validity();

    let diff = validity.not_after.timestamp() - validity.not_before.timestamp();
    // Validity should be roughly 86400 + 600 = 87000 seconds
    assert!(
        diff >= 86000 && diff <= 88000,
        "unexpected validity diff: {diff}"
    );
}

// =========================================================================
// factory.rs — get_generated_key / release_key lifecycle (lines 45-60, 282-303)
// =========================================================================

#[test]
fn generated_key_lifecycle() {
    let factory = make_factory();
    let cert = factory.create_certificate_default().unwrap();

    // Extract serial hex.
    let parsed = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    // get_generated_key should find it.
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some(), "key should be stored after creation");
    let key = key.unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());

    // release_key should remove it.
    assert!(factory.release_key(&serial_hex));
    assert!(factory.get_generated_key(&serial_hex).is_none());

    // Releasing again should return false.
    assert!(!factory.release_key(&serial_hex));
}

#[test]
fn get_generated_key_returns_none_for_unknown() {
    let factory = make_factory();
    assert!(factory.get_generated_key("DEADBEEF").is_none());
}

#[test]
fn release_key_returns_false_for_unknown() {
    let factory = make_factory();
    assert!(!factory.release_key("DEADBEEF"));
}

// =========================================================================
// factory.rs — key_provider accessor (line 148-149)
// =========================================================================

#[test]
fn key_provider_returns_software_provider() {
    let factory = make_factory();
    let provider = factory.key_provider();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
}

// =========================================================================
// factory.rs — default key size used when key_size is None (line 298)
// =========================================================================

#[test]
fn create_certificate_uses_default_key_size_when_none() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=Default Key Size");
    // key_size is None by default.
    assert!(opts.key_size.is_none());

    let cert = factory.create_certificate(opts).unwrap();
    assert!(cert.has_private_key());

    // Extract serial to get the generated key and check its key_size.
    let parsed = parse_cert(&cert.cert_der);
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    let key = factory.get_generated_key(&serial_hex).unwrap();
    assert_eq!(key.key_size, KeyAlgorithm::Ecdsa.default_key_size());
}

// =========================================================================
// factory.rs — create_certificate_default (trait default impl)
// =========================================================================

#[test]
fn create_certificate_default_produces_valid_cert() {
    let factory = make_factory();
    let cert = factory.create_certificate_default().unwrap();
    assert!(cert.has_private_key());

    let parsed = parse_cert(&cert.cert_der);
    assert!(parsed
        .subject()
        .to_string()
        .contains("Ephemeral Certificate"));
    assert_eq!(parsed.version(), X509Version::V3);
}

// =========================================================================
// factory.rs — two-level chain: CA -> intermediate -> leaf
// =========================================================================

#[test]
fn create_three_level_chain() {
    let factory = make_factory();

    let root_opts = CertificateOptions::new()
        .with_subject_name("CN=Root CA")
        .as_ca(2);
    let root = factory.create_certificate(root_opts).unwrap();

    let intermediate_opts = CertificateOptions::new()
        .with_subject_name("CN=Intermediate CA")
        .as_ca(0)
        .signed_by(root.clone());
    let intermediate = factory.create_certificate(intermediate_opts).unwrap();

    let leaf_opts = CertificateOptions::new()
        .with_subject_name("CN=Leaf Certificate")
        .signed_by(intermediate.clone());
    let leaf = factory.create_certificate(leaf_opts).unwrap();

    // Verify chain: leaf.issuer == intermediate.subject
    let parsed_leaf = parse_cert(&leaf.cert_der);
    let parsed_intermediate = parse_cert(&intermediate.cert_der);
    let parsed_root = parse_cert(&root.cert_der);

    assert_eq!(
        parsed_leaf.issuer().to_string(),
        parsed_intermediate.subject().to_string()
    );
    assert_eq!(
        parsed_intermediate.issuer().to_string(),
        parsed_root.subject().to_string()
    );
}
