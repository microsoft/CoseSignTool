// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for x509_extensions module.
//!
//! Tests with real certificates generated via certificates_local to cover all code paths.

use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use did_x509::x509_extensions::{
    extract_eku_oids, extract_extended_key_usage, extract_fulcio_issuer, is_ca_certificate,
};
use x509_parser::prelude::*;

/// Generate a certificate with multiple EKU flags.
fn generate_cert_with_multiple_ekus() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Multi-EKU Test")
                .with_enhanced_key_usages(vec![
                    "1.3.6.1.5.5.7.3.1".to_string(),
                    "1.3.6.1.5.5.7.3.2".to_string(),
                    "1.3.6.1.5.5.7.3.3".to_string(),
                    "1.3.6.1.5.5.7.3.4".to_string(),
                    "1.3.6.1.5.5.7.3.8".to_string(),
                    "1.3.6.1.5.5.7.3.9".to_string(),
                ]),
        )
        .unwrap();
    cert.cert_der
}

/// Generate a CA certificate with Basic Constraints.
fn generate_ca_cert() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Test CA")
                .as_ca(u32::MAX)
                .with_enhanced_key_usages(vec![]),
        )
        .unwrap();
    cert.cert_der
}

/// Generate a non-CA certificate (leaf).
fn generate_leaf_cert() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Test Leaf")
                .with_enhanced_key_usages(vec![]),
        )
        .unwrap();
    cert.cert_der
}

/// Generate a certificate with a specific single EKU.
fn generate_cert_with_single_eku(eku_oid: &str) -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=Single EKU Test")
                .with_enhanced_key_usages(vec![eku_oid.to_string()]),
        )
        .unwrap();
    cert.cert_der
}

#[test]
fn test_extract_eku_server_auth() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.1");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.1"),
        "Should contain server auth OID"
    );
}

#[test]
fn test_extract_eku_client_auth() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.2");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.2"),
        "Should contain client auth OID"
    );
}

#[test]
fn test_extract_eku_code_signing() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.3");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.3"),
        "Should contain code signing OID"
    );
}

#[test]
fn test_extract_eku_email_protection() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.4");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.4"),
        "Should contain email protection OID"
    );
}

#[test]
fn test_extract_eku_time_stamping() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.8");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.8"),
        "Should contain time stamping OID"
    );
}

#[test]
fn test_extract_eku_ocsp_signing() {
    let cert_der = generate_cert_with_single_eku("1.3.6.1.5.5.7.3.9");
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.9"),
        "Should contain OCSP signing OID"
    );
}

#[test]
fn test_extract_eku_multiple_flags() {
    let cert_der = generate_cert_with_multiple_ekus();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);

    // Should contain all the EKU OIDs
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.1"),
        "Missing server auth"
    );
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.2"),
        "Missing client auth"
    );
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.3"),
        "Missing code signing"
    );
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.4"),
        "Missing email protection"
    );
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.8"),
        "Missing time stamping"
    );
    assert!(
        ekus.iter().any(|x| x == "1.3.6.1.5.5.7.3.9"),
        "Missing OCSP signing"
    );
}

#[test]
fn test_extract_eku_oids_wrapper() {
    let cert_der = generate_cert_with_multiple_ekus();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = extract_eku_oids(&cert);
    assert!(result.is_ok());

    let oids = result.unwrap();
    assert!(!oids.is_empty(), "Should have EKU OIDs");
}

#[test]
fn test_is_ca_certificate_true() {
    let cert_der = generate_ca_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let is_ca = is_ca_certificate(&cert);
    assert!(is_ca, "CA certificate should be detected as CA");
}

#[test]
fn test_is_ca_certificate_false() {
    let cert_der = generate_leaf_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let is_ca = is_ca_certificate(&cert);
    assert!(!is_ca, "Leaf certificate should not be detected as CA");
}

#[test]
fn test_extract_fulcio_issuer_not_present() {
    // Regular certificate without Fulcio extension
    let cert_der = generate_leaf_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let issuer = extract_fulcio_issuer(&cert);
    assert!(
        issuer.is_none(),
        "Should return None when Fulcio extension not present"
    );
}

#[test]
fn test_extract_eku_no_extension() {
    // Certificate without EKU extension
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=No EKU")
                .with_enhanced_key_usages(vec![]),
        )
        .unwrap();
    let cert_der = cert.cert_der;

    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.is_empty(),
        "Should return empty list when no EKU extension"
    );
}
