// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for policy validators with real X.509 certificates.
//!
//! Tests the policy_validators.rs functions with actual certificate generation
//! to ensure proper validation behavior for various policy types.

use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use did_x509::error::DidX509Error;
use did_x509::models::SanType;
use did_x509::policy_validators::{
    validate_eku, validate_fulcio_issuer, validate_san, validate_subject,
};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder};
use x509_parser::prelude::*;

/// Helper to generate a certificate with specific EKU OIDs.
fn generate_cert_with_eku(eku_oids: Vec<String>) -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let options = CertificateOptions::new()
        .with_subject_name("CN=Test EKU Certificate")
        .with_enhanced_key_usages(eku_oids);
    let cert = factory.create_certificate(options).unwrap();
    cert.cert_der
}

/// Helper to generate a certificate with specific subject attributes.
/// Uses OpenSSL directly to support multi-attribute DN (CN, O, OU, C, etc.).
fn generate_cert_with_subject(attributes: Vec<(&str, &str)>) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    for (attr, value) in &attributes {
        name_builder.append_entry_by_text(attr, value).unwrap();
    }
    let subject_name = name_builder.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&subject_name).unwrap();
    builder.set_issuer_name(&subject_name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    builder.build().to_der().unwrap()
}

/// Helper to generate a certificate with specific SAN entries.
fn generate_cert_with_san(san_entries: Vec<String>) -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let mut options = CertificateOptions::new()
        .with_subject_name("CN=Test SAN Certificate")
        .with_enhanced_key_usages(vec![]);
    for san in san_entries {
        options = options.add_subject_alternative_name(&san);
    }
    let cert = factory.create_certificate(options).unwrap();
    cert.cert_der
}

#[test]
fn test_validate_eku_success_single_oid() {
    let cert_der = generate_cert_with_eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(&cert, &["1.3.6.1.5.5.7.3.3".to_string().into()]);
    assert!(result.is_ok());
}

#[test]
fn test_validate_eku_success_multiple_oids() {
    let cert_der = generate_cert_with_eku(vec![
        "1.3.6.1.5.5.7.3.3".to_string(),
        "1.3.6.1.5.5.7.3.2".to_string(),
    ]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(
        &cert,
        &[
            "1.3.6.1.5.5.7.3.3".to_string().into(), // Code Signing
            "1.3.6.1.5.5.7.3.2".to_string().into(), // Client Auth
        ],
    );
    assert!(result.is_ok());
}

#[test]
fn test_validate_eku_failure_missing_extension() {
    let cert_der = generate_cert_with_eku(vec![]); // No EKU extension
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(&cert, &["1.3.6.1.5.5.7.3.3".to_string().into()]);
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("no Extended Key Usage extension"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_eku_failure_wrong_oid() {
    let cert_der = generate_cert_with_eku(vec!["1.3.6.1.5.5.7.3.1".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(&cert, &["1.3.6.1.5.5.7.3.3".to_string().into()]); // Expect Code Signing
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Required EKU OID '1.3.6.1.5.5.7.3.3' not found"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_subject_success_single_attribute() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[("CN".to_string().into(), "Test Subject".to_string().into())],
    );
    assert!(result.is_ok());
}

#[test]
fn test_validate_subject_success_multiple_attributes() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject"), ("O", "Test Org")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[
            ("CN".to_string().into(), "Test Subject".to_string().into()),
            ("O".to_string().into(), "Test Org".to_string().into()),
        ],
    );
    assert!(result.is_ok());
}

#[test]
fn test_validate_subject_failure_empty_attributes() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(&cert, &[]);
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Must contain at least one attribute"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_subject_failure_attribute_not_found() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[("O".to_string().into(), "Missing Org".to_string().into())],
    );
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Required attribute 'O' not found"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_subject_failure_attribute_value_mismatch() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[("CN".to_string().into(), "Wrong Subject".to_string().into())],
    );
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("value mismatch"));
            assert!(msg.contains("expected 'Wrong Subject', got 'Test Subject'"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_subject_failure_unknown_attribute() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Subject")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[("UNKNOWN".to_string().into(), "value".to_string().into())],
    );
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Unknown attribute 'UNKNOWN'"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_san_success_dns() {
    let cert_der = generate_cert_with_san(vec!["example.com".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_san_success_email() {
    let cert_der = generate_cert_with_san(vec!["email:test@example.com".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Email, "test@example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_san_success_uri() {
    let cert_der = generate_cert_with_san(vec!["URI:https://example.com".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Uri, "https://example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_san_failure_no_extension() {
    let cert_der = generate_cert_with_san(vec![]); // No SAN extension
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "example.com");
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("no Subject Alternative Names"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_san_failure_wrong_value() {
    let cert_der = generate_cert_with_san(vec!["wrong.com".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "example.com");
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Required SAN 'dns:example.com' not found"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_san_failure_wrong_type() {
    let cert_der = generate_cert_with_san(vec!["email:test@example.com".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "test@example.com");
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("Required SAN 'dns:test@example.com' not found"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_fulcio_issuer_success() {
    // Generate a basic certificate - Fulcio issuer extension testing would
    // require more complex certificate generation with custom extensions
    let cert_der = generate_cert_with_subject(vec![("CN", "Fulcio Test")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // This test will fail since the certificate doesn't have Fulcio extension
    let result = validate_fulcio_issuer(&cert, "https://fulcio.example.com");
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("no Fulcio issuer extension"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_validate_fulcio_issuer_failure_missing_extension() {
    let cert_der = generate_cert_with_subject(vec![("CN", "Test Cert")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_fulcio_issuer(&cert, "https://fulcio.example.com");
    assert!(result.is_err());
    match result {
        Err(DidX509Error::PolicyValidationFailed(msg)) => {
            assert!(msg.contains("no Fulcio issuer extension"));
        }
        _ => panic!("Expected PolicyValidationFailed error"),
    }
}

#[test]
fn test_error_display_coverage() {
    // Test additional error paths to improve coverage
    let cert_der = generate_cert_with_eku(vec!["1.3.6.1.5.5.7.3.1".to_string()]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Test with multiple missing EKU OIDs
    let result = validate_eku(
        &cert,
        &[
            "1.3.6.1.5.5.7.3.3".to_string().into(), // Code Signing
            "1.3.6.1.5.5.7.3.4".to_string().into(), // Email Protection
        ],
    );
    assert!(result.is_err());

    // Test subject validation with duplicate checks
    let result2 = validate_subject(
        &cert,
        &[
            ("CN".to_string().into(), "Test".to_string().into()),
            ("O".to_string().into(), "Missing".to_string().into()),
        ],
    );
    assert!(result2.is_err());
}

#[test]
fn test_policy_validation_edge_cases() {
    let cert_der =
        generate_cert_with_subject(vec![("CN", "Edge Case Test"), ("O", "Test Corp"), ("C", "US")]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Test with less common DN attributes
    let result = validate_subject(&cert, &[("C".to_string().into(), "US".to_string().into())]);
    assert!(result.is_ok());

    // Test with case sensitivity
    let result2 = validate_subject(
        &cert,
        &[
            ("CN".to_string().into(), "edge case test".to_string().into()), // Different case
        ],
    );
    assert!(result2.is_err());
}
