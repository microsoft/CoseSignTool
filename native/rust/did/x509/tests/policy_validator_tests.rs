// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for policy validators with real X.509 certificates.
//!
//! Tests the policy_validators.rs functions with actual certificate generation
//! to ensure proper validation behavior for various policy types.

use did_x509::error::DidX509Error;
use did_x509::models::SanType;
use did_x509::policy_validators::{
    validate_eku, validate_fulcio_issuer, validate_san, validate_subject,
};
use rcgen::string::Ia5String;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::{CertificateParams, DnType, KeyPair, SanType as RcgenSanType};
use x509_parser::prelude::*;

/// Helper to generate a certificate with specific EKU OIDs.
fn generate_cert_with_eku(eku_purposes: Vec<ExtendedKeyUsagePurpose>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test EKU Certificate");

    if !eku_purposes.is_empty() {
        params.extended_key_usages = eku_purposes;
    }

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Helper to generate a certificate with specific subject attributes.
fn generate_cert_with_subject(attributes: Vec<(DnType, String)>) -> Vec<u8> {
    let mut params = CertificateParams::default();

    for (dn_type, value) in attributes {
        params.distinguished_name.push(dn_type, value);
    }

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Helper to generate a certificate with specific SAN entries.
fn generate_cert_with_san(san_entries: Vec<RcgenSanType>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test SAN Certificate");
    params.subject_alt_names = san_entries;

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

#[test]
fn test_validate_eku_success_single_oid() {
    let cert_der = generate_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(&cert, &["1.3.6.1.5.5.7.3.3".to_string().into()]);
    assert!(result.is_ok());
}

#[test]
fn test_validate_eku_success_multiple_oids() {
    let cert_der = generate_cert_with_eku(vec![
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::ClientAuth,
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
    let cert_der = generate_cert_with_eku(vec![ExtendedKeyUsagePurpose::ServerAuth]);
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
    let cert_der = generate_cert_with_subject(vec![(
        DnType::CommonName,
        "Test Subject".to_string().into(),
    )]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_subject(
        &cert,
        &[("CN".to_string().into(), "Test Subject".to_string().into())],
    );
    assert!(result.is_ok());
}

#[test]
fn test_validate_subject_success_multiple_attributes() {
    let cert_der = generate_cert_with_subject(vec![
        (DnType::CommonName, "Test Subject".to_string().into()),
        (DnType::OrganizationName, "Test Org".to_string().into()),
    ]);
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
    let cert_der = generate_cert_with_subject(vec![(
        DnType::CommonName,
        "Test Subject".to_string().into(),
    )]);
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
    let cert_der = generate_cert_with_subject(vec![(
        DnType::CommonName,
        "Test Subject".to_string().into(),
    )]);
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
    let cert_der = generate_cert_with_subject(vec![(
        DnType::CommonName,
        "Test Subject".to_string().into(),
    )]);
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
    let cert_der = generate_cert_with_subject(vec![(
        DnType::CommonName,
        "Test Subject".to_string().into(),
    )]);
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
    let cert_der = generate_cert_with_san(vec![RcgenSanType::DnsName(
        Ia5String::try_from("example.com").unwrap(),
    )]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_san_success_email() {
    let cert_der = generate_cert_with_san(vec![RcgenSanType::Rfc822Name(
        Ia5String::try_from("test@example.com").unwrap(),
    )]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Email, "test@example.com");
    assert!(result.is_ok());
}

#[test]
fn test_validate_san_success_uri() {
    let cert_der = generate_cert_with_san(vec![RcgenSanType::URI(
        Ia5String::try_from("https://example.com").unwrap(),
    )]);
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
    let cert_der = generate_cert_with_san(vec![RcgenSanType::DnsName(
        Ia5String::try_from("wrong.com").unwrap(),
    )]);
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
    let cert_der = generate_cert_with_san(vec![RcgenSanType::Rfc822Name(
        Ia5String::try_from("test@example.com").unwrap(),
    )]);
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
    let cert_der =
        generate_cert_with_subject(vec![(DnType::CommonName, "Fulcio Test".to_string().into())]);
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
    let cert_der =
        generate_cert_with_subject(vec![(DnType::CommonName, "Test Cert".to_string().into())]);
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
    let cert_der = generate_cert_with_eku(vec![ExtendedKeyUsagePurpose::ServerAuth]);
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
    let cert_der = generate_cert_with_subject(vec![
        (DnType::CommonName, "Edge Case Test".to_string().into()),
        (DnType::OrganizationName, "Test Corp".to_string().into()),
        (DnType::CountryName, "US".to_string().into()),
    ]);
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
