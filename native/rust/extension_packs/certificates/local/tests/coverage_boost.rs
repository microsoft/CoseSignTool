// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered lines in `cose_sign1_certificates_local`.
//!
//! Covers:
//! - factory.rs: EphemeralCertificateFactory self-signed creation, issuer-signed creation,
//!   RSA support, get_generated_key, release_key, CA cert with path constraints,
//!   key_provider accessor.
//! - loaders/pem.rs: missing end marker, invalid base64, no-certificate PEM,
//!   PEM with unknown label.
//! - software_key.rs: Default, name(), supports_algorithm(), generate_key() for ECDSA,
//!   generate_key() for RSA.

use cose_sign1_certificates_local::certificate::Certificate;
use cose_sign1_certificates_local::error::CertLocalError;
use cose_sign1_certificates_local::factory::EphemeralCertificateFactory;
use cose_sign1_certificates_local::key_algorithm::KeyAlgorithm;
use cose_sign1_certificates_local::loaders::pem::{load_cert_from_pem, load_cert_from_pem_bytes};
use cose_sign1_certificates_local::options::CertificateOptions;
use cose_sign1_certificates_local::software_key::SoftwareKeyProvider;
use cose_sign1_certificates_local::traits::{CertificateFactory, PrivateKeyProvider};
use std::time::Duration;
use x509_parser::prelude::FromDer;

// ===========================================================================
// Helper: create a factory with the software key provider
// ===========================================================================

fn make_factory() -> EphemeralCertificateFactory {
    EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()))
}

// ===========================================================================
// software_key.rs — Default impl (L30-32)
// ===========================================================================

#[test]
fn software_key_provider_default() {
    let provider = SoftwareKeyProvider::default();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

// ===========================================================================
// software_key.rs — name() (L37)
// ===========================================================================

#[test]
fn software_key_provider_name() {
    let provider = SoftwareKeyProvider::new();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

// ===========================================================================
// software_key.rs — supports_algorithm() (L40-47)
// ===========================================================================

#[test]
fn software_key_provider_supports_ecdsa() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
}

#[test]
fn software_key_provider_supports_rsa() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::Rsa));
}

// ===========================================================================
// software_key.rs — generate_key ECDSA success (L65-86)
// ===========================================================================

#[test]
fn software_key_provider_generate_ecdsa_key() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Ecdsa, None).unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
    assert_eq!(key.key_size, 256); // default for ECDSA
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

#[test]
fn software_key_provider_generate_ecdsa_key_with_size() {
    let provider = SoftwareKeyProvider::new();
    let key = provider
        .generate_key(KeyAlgorithm::Ecdsa, Some(256))
        .unwrap();
    assert_eq!(key.key_size, 256);
}

// ===========================================================================
// software_key.rs — generate_key RSA succeeds
// ===========================================================================

#[test]
fn software_key_provider_generate_rsa_key() {
    let provider = SoftwareKeyProvider::new();
    let key = provider.generate_key(KeyAlgorithm::Rsa, None).unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Rsa);
    assert_eq!(key.key_size, 2048);
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
}

// ===========================================================================
// factory.rs — create_certificate self-signed ECDSA (L155, L167-208)
// ===========================================================================

#[test]
fn factory_create_self_signed_ecdsa() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=test-self-signed")
        .with_key_algorithm(KeyAlgorithm::Ecdsa);

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());

    // Verify the cert subject
    let subject = cert.subject().unwrap();
    assert!(
        subject.contains("test-self-signed"),
        "subject was: {subject}"
    );
}

// ===========================================================================
// factory.rs — create_certificate RSA succeeds
// ===========================================================================

#[test]
fn factory_create_rsa_certificate() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_key_algorithm(KeyAlgorithm::Rsa);

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — create_certificate CA cert (L211-224)
// ===========================================================================

#[test]
fn factory_create_ca_cert_with_path_len() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=test-ca")
        .as_ca(3);

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());

    // Verify it's a CA by parsing with x509-parser
    let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&cert.cert_der).unwrap();
    let bc = parsed
        .basic_constraints()
        .expect("should have basic constraints extension")
        .expect("should parse ok");
    assert!(bc.value.ca);
}

// ===========================================================================
// factory.rs — create_certificate CA cert with path_length_constraint = u32::MAX (L214)
// ===========================================================================

#[test]
fn factory_create_ca_cert_unlimited_path_length() {
    let factory = make_factory();
    let mut opts = CertificateOptions::new().with_subject_name("CN=unlimited-ca");
    opts.is_ca = true;
    opts.path_length_constraint = u32::MAX;

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());
}

// ===========================================================================
// factory.rs — issuer-signed certificate (L228-254)
// ===========================================================================

#[test]
fn factory_create_issuer_signed_cert() {
    let factory = make_factory();

    // First, create a CA
    let ca_opts = CertificateOptions::new()
        .with_subject_name("CN=issuer-ca")
        .as_ca(1);
    let ca_cert = factory.create_certificate(ca_opts).unwrap();

    // Now create a leaf signed by the CA
    let leaf_opts = CertificateOptions::new()
        .with_subject_name("CN=issued-leaf")
        .signed_by(ca_cert.clone());

    let leaf_cert = factory.create_certificate(leaf_opts).unwrap();
    assert!(!leaf_cert.cert_der.is_empty());
    assert!(leaf_cert.has_private_key());

    // Verify the issuer name matches the CA subject
    let (_, leaf_parsed) =
        x509_parser::prelude::X509Certificate::from_der(&leaf_cert.cert_der).unwrap();
    let (_, ca_parsed) =
        x509_parser::prelude::X509Certificate::from_der(&ca_cert.cert_der).unwrap();
    assert_eq!(
        leaf_parsed.issuer().to_string(),
        ca_parsed.subject().to_string()
    );
}

// ===========================================================================
// factory.rs — issuer without private key error (L246-248)
// ===========================================================================

#[test]
fn factory_create_issuer_signed_without_key_errors() {
    let factory = make_factory();

    // Create a certificate without a private key (Certificate::new has no key)
    let issuer_no_key = Certificate::new(vec![0x30, 0x00]); // minimal DER stub

    let opts = CertificateOptions::new()
        .with_subject_name("CN=fail-leaf")
        .signed_by(issuer_no_key);

    let result = factory.create_certificate(opts);
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::CertificateCreationFailed(msg) => {
            assert!(msg.contains("private key"), "msg was: {msg}");
        }
        other => panic!("expected CertificateCreationFailed, got {other:?}"),
    }
}

// ===========================================================================
// factory.rs — get_generated_key and release_key (L45-60)
// ===========================================================================

#[test]
fn factory_get_and_release_generated_key() {
    let factory = make_factory();
    let opts = CertificateOptions::new().with_subject_name("CN=key-mgmt");

    let cert = factory.create_certificate(opts).unwrap();

    // Parse cert to get serial number hex
    let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&cert.cert_der).unwrap();
    let serial_hex: String = parsed
        .serial
        .to_bytes_be()
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    // get_generated_key should return Some
    let key = factory.get_generated_key(&serial_hex);
    assert!(key.is_some(), "expected key for serial {serial_hex}");
    let key = key.unwrap();
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);

    // release_key should return true the first time
    assert!(factory.release_key(&serial_hex));
    // Now get should return None
    assert!(factory.get_generated_key(&serial_hex).is_none());
    // release again should return false
    assert!(!factory.release_key(&serial_hex));
}

// ===========================================================================
// factory.rs — key_provider accessor (L148-150)
// ===========================================================================

#[test]
fn factory_key_provider_accessor() {
    let factory = make_factory();
    let provider = factory.key_provider();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

// ===========================================================================
// factory.rs — create_certificate_default (trait method)
// ===========================================================================

#[test]
fn factory_create_certificate_default() {
    let factory = make_factory();
    let cert = factory.create_certificate_default().unwrap();
    assert!(!cert.cert_der.is_empty());
    assert!(cert.has_private_key());
}

// ===========================================================================
// factory.rs — validity and not_before_offset (L195-204)
// ===========================================================================

#[test]
fn factory_create_cert_custom_validity() {
    let factory = make_factory();
    let opts = CertificateOptions::new()
        .with_subject_name("CN=custom-validity")
        .with_validity(Duration::from_secs(86400))
        .with_not_before_offset(Duration::from_secs(0));

    let cert = factory.create_certificate(opts).unwrap();
    assert!(!cert.cert_der.is_empty());

    let (_, parsed) = x509_parser::prelude::X509Certificate::from_der(&cert.cert_der).unwrap();
    let nb = parsed.validity().not_before.timestamp();
    let na = parsed.validity().not_after.timestamp();
    // validity of ~86400 seconds
    let diff = na - nb;
    assert!(
        diff >= 86300 && diff <= 86500,
        "unexpected validity: {diff}s"
    );
}

// ===========================================================================
// loaders/pem.rs — invalid UTF-8 error (L44-45)
// ===========================================================================

#[test]
fn pem_invalid_utf8() {
    let bad: &[u8] = &[0xFF, 0xFE, 0xFD];
    let result = load_cert_from_pem_bytes(bad);
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => assert!(msg.contains("UTF-8")),
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — no PEM blocks (L49-52)
// ===========================================================================

#[test]
fn pem_empty_content() {
    let result = load_cert_from_pem_bytes(b"just some random text");
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => assert!(msg.contains("no valid PEM blocks")),
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — no certificate in PEM blocks (L77-78)
// ===========================================================================

#[test]
fn pem_no_certificate_block() {
    // A PEM with only a private key — no certificate
    let ec_group =
        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let result = load_cert_from_pem_bytes(key_pem.as_bytes());
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => assert!(msg.contains("no certificate")),
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — missing end marker (L131-135)
// ===========================================================================

#[test]
fn pem_missing_end_marker() {
    let truncated = "-----BEGIN CERTIFICATE-----\nMIIB...\n";
    let result = load_cert_from_pem_bytes(truncated.as_bytes());
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => assert!(msg.contains("missing end marker")),
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — invalid base64 (L138-140)
// ===========================================================================

#[test]
fn pem_invalid_base64_content() {
    let bad_pem = "-----BEGIN CERTIFICATE-----\n!@#$%^&*()\n-----END CERTIFICATE-----\n";
    let result = load_cert_from_pem_bytes(bad_pem.as_bytes());
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => {
            assert!(
                msg.contains("base64") || msg.contains("invalid"),
                "unexpected msg: {msg}"
            );
        }
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — invalid certificate DER (L80-81)
// ===========================================================================

#[test]
fn pem_invalid_der_in_cert_block() {
    // Valid base64 but not a valid DER certificate
    // "AAAA" decodes to [0, 0, 0]
    let bad_pem = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let result = load_cert_from_pem_bytes(bad_pem.as_bytes());
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::LoadFailed(msg) => {
            assert!(msg.contains("invalid certificate"), "unexpected msg: {msg}");
        }
        other => panic!("expected LoadFailed, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — PEM with unknown label is skipped (L73)
// ===========================================================================

#[test]
fn pem_unknown_label_skipped() {
    // Create a real cert + an extra block with unknown label
    let ec_group =
        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = openssl::x509::X509Name::builder().unwrap();
    name_builder
        .append_entry_by_text("CN", "test.example.com")
        .unwrap();
    let name = name_builder.build();

    let mut builder = openssl::x509::X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(
            &openssl::bn::BigNum::from_u32(1)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let not_after = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert = builder.build();
    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();

    let combined = format!(
        "{}\n-----BEGIN CUSTOM DATA-----\nSGVsbG8=\n-----END CUSTOM DATA-----\n",
        cert_pem
    );

    let result = load_cert_from_pem_bytes(combined.as_bytes());
    assert!(result.is_ok());
    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
}

// ===========================================================================
// loaders/pem.rs — load_cert_from_pem file not found (L25-27)
// ===========================================================================

#[test]
fn pem_file_not_found() {
    let result = load_cert_from_pem("nonexistent_file_12345.pem");
    assert!(result.is_err());
    match result.unwrap_err() {
        CertLocalError::IoError(_) => { /* expected */ }
        other => panic!("expected IoError, got {other:?}"),
    }
}

// ===========================================================================
// loaders/pem.rs — multi-cert chain + key (covers chain push and key assignment)
// ===========================================================================

#[test]
fn pem_multi_cert_with_key() {
    // Create two certs and a key
    let ec_group =
        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key1 = openssl::ec::EcKey::generate(&ec_group).unwrap();
    let pkey1 = openssl::pkey::PKey::from_ec_key(ec_key1).unwrap();
    let ec_key2 = openssl::ec::EcKey::generate(&ec_group).unwrap();
    let pkey2 = openssl::pkey::PKey::from_ec_key(ec_key2).unwrap();

    let make_cert = |pkey: &openssl::pkey::PKey<openssl::pkey::Private>, cn: &str| -> String {
        let mut nb = openssl::x509::X509Name::builder().unwrap();
        nb.append_entry_by_text("CN", cn).unwrap();
        let name = nb.build();
        let mut builder = openssl::x509::X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(
                &openssl::bn::BigNum::from_u32(1)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(pkey).unwrap();
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
        builder.set_not_before(&not_before).unwrap();
        builder.set_not_after(&not_after).unwrap();
        builder
            .sign(pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        String::from_utf8(builder.build().to_pem().unwrap()).unwrap()
    };

    let cert1_pem = make_cert(&pkey1, "leaf.example.com");
    let cert2_pem = make_cert(&pkey2, "ca.example.com");
    let key_pem = String::from_utf8(pkey1.private_key_to_pem_pkcs8().unwrap()).unwrap();

    let combined = format!("{cert1_pem}\n{key_pem}\n{cert2_pem}\n");
    let result = load_cert_from_pem_bytes(combined.as_bytes());
    assert!(result.is_ok());
    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.private_key_der.is_some());
    assert_eq!(certificate.chain.len(), 1);
}

// ===========================================================================
// loaders/pem.rs — base64_decode with valid + padding (L172 area)
// ===========================================================================

#[test]
fn pem_valid_cert_with_padding() {
    // This tests the base64 decode logic including padding
    let ec_group =
        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&ec_group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();

    let mut nb = openssl::x509::X509Name::builder().unwrap();
    nb.append_entry_by_text("CN", "padding-test").unwrap();
    let name = nb.build();
    let mut builder = openssl::x509::X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(
            &openssl::bn::BigNum::from_u32(42)
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let not_after = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder
        .sign(&pkey, openssl::hash::MessageDigest::sha256())
        .unwrap();
    let cert_pem = String::from_utf8(builder.build().to_pem().unwrap()).unwrap();

    let result = load_cert_from_pem_bytes(cert_pem.as_bytes());
    assert!(result.is_ok());
}
