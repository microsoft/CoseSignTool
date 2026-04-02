// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for x509_extensions module.
//!
//! Tests with real certificates generated via rcgen to cover all code paths.

use did_x509::x509_extensions::{
    extract_eku_oids, extract_extended_key_usage, extract_fulcio_issuer, is_ca_certificate,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use x509_parser::prelude::*;

/// Generate a certificate with multiple EKU flags.
fn generate_cert_with_multiple_ekus() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Multi-EKU Test");

    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::OcspSigning,
    ];

    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

/// Generate a CA certificate with Basic Constraints.
fn generate_ca_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

/// Generate a non-CA certificate (leaf).
fn generate_leaf_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Leaf");
    params.is_ca = IsCa::NoCa;

    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

/// Generate a certificate with specific single EKU.
fn generate_cert_with_single_eku(purpose: ExtendedKeyUsagePurpose) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Single EKU Test");
    params.extended_key_usages = vec![purpose];

    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

#[test]
fn test_extract_eku_server_auth() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::ServerAuth);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.1".to_string()),
        "Should contain server auth OID"
    );
}

#[test]
fn test_extract_eku_client_auth() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::ClientAuth);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.2".to_string()),
        "Should contain client auth OID"
    );
}

#[test]
fn test_extract_eku_code_signing() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::CodeSigning);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.3".to_string()),
        "Should contain code signing OID"
    );
}

#[test]
fn test_extract_eku_email_protection() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::EmailProtection);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.4".to_string()),
        "Should contain email protection OID"
    );
}

#[test]
fn test_extract_eku_time_stamping() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::TimeStamping);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.8".to_string()),
        "Should contain time stamping OID"
    );
}

#[test]
fn test_extract_eku_ocsp_signing() {
    let cert_der = generate_cert_with_single_eku(ExtendedKeyUsagePurpose::OcspSigning);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.9".to_string()),
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
        ekus.contains(&"1.3.6.1.5.5.7.3.1".to_string()),
        "Missing server auth"
    );
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.2".to_string()),
        "Missing client auth"
    );
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.3".to_string()),
        "Missing code signing"
    );
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.4".to_string()),
        "Missing email protection"
    );
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.8".to_string()),
        "Missing time stamping"
    );
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.9".to_string()),
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
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "No EKU");
    // Don't add any EKU

    let key = KeyPair::generate().unwrap();
    let cert_der = params.self_signed(&key).unwrap().der().to_vec();

    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let ekus = extract_extended_key_usage(&cert);
    assert!(
        ekus.is_empty(),
        "Should return empty list when no EKU extension"
    );
}
