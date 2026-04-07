// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for policy validators to cover uncovered lines in policy_validators.rs.
//!
//! These tests target specific edge cases and error paths not covered by existing tests.

use did_x509::error::DidX509Error;
use did_x509::models::SanType;
use did_x509::policy_validators::{
    validate_eku, validate_fulcio_issuer, validate_san, validate_subject,
};
use rcgen::string::Ia5String;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::{CertificateParams, DnType, KeyPair, SanType as RcgenSanType};
use x509_parser::prelude::*;

/// Helper to generate a certificate with no EKU extension.
fn generate_cert_without_eku() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test No EKU Certificate");
    // Explicitly don't add extended_key_usages

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Helper to generate a certificate with specific subject attributes, including parsing edge cases.
fn generate_cert_with_subject_edge_cases() -> Vec<u8> {
    let mut params = CertificateParams::default();
    // Add multiple types of subject attributes to test parsing
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Subject");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test Org");
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, "Test Unit");
    params.distinguished_name.push(DnType::CountryName, "US");

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Helper to generate a certificate with no SAN extension.
fn generate_cert_without_san() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test No SAN Certificate");
    // Explicitly don't add subject_alt_names

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Helper to generate a certificate with specific SAN entries for edge case testing.
fn generate_cert_with_multiple_sans() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Multi SAN Certificate");

    // Add multiple types of SANs
    params.subject_alt_names = vec![
        RcgenSanType::DnsName(Ia5String::try_from("test1.example.com").unwrap()),
        RcgenSanType::DnsName(Ia5String::try_from("test2.example.com").unwrap()),
        RcgenSanType::Rfc822Name(Ia5String::try_from("test@example.com").unwrap()),
        RcgenSanType::IpAddress("192.168.1.1".parse().unwrap()),
    ];

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

#[test]
fn test_validate_eku_no_extension() {
    let cert_der = generate_cert_without_eku();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(&cert, &["1.3.6.1.5.5.7.3.3".to_string().into()]);

    // Should fail because certificate has no EKU extension
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(msg.contains("no Extended Key Usage"), "Error: {}", msg);
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_eku_missing_required_oid() {
    // Generate cert with only code signing, but require both code signing and client auth
    let cert_der = generate_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_eku(
        &cert,
        &[
            "1.3.6.1.5.5.7.3.3".to_string().into(), // Code Signing (present)
            "1.3.6.1.5.5.7.3.2".to_string().into(), // Client Auth (missing)
        ],
    );

    // Should fail because Client Auth EKU is missing
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("1.3.6.1.5.5.7.3.2") && msg.contains("not found"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

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

#[test]
fn test_validate_subject_empty_attributes() {
    let cert_der = generate_cert_with_subject_edge_cases();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Empty expected attributes should fail
    let result = validate_subject(&cert, &[]);

    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(msg.contains("at least one attribute"), "Error: {}", msg);
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_subject_unknown_attribute() {
    let cert_der = generate_cert_with_subject_edge_cases();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Use an unknown attribute label
    let result = validate_subject(
        &cert,
        &[(
            "UnknownAttribute".to_string().into(),
            "SomeValue".to_string().into(),
        )],
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("Unknown attribute") && msg.contains("UnknownAttribute"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_subject_missing_attribute() {
    let cert_der = generate_cert_with_subject_edge_cases();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Request an attribute that doesn't exist in the certificate
    let result = validate_subject(
        &cert,
        &[
            ("L".to_string().into(), "NonExistent".to_string().into()), // Locality
        ],
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("not found") && msg.contains("L"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_subject_value_mismatch() {
    let cert_der = generate_cert_with_subject_edge_cases();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Request CommonName with wrong value
    let result = validate_subject(
        &cert,
        &[("CN".to_string().into(), "Wrong Name".to_string().into())],
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("value mismatch") && msg.contains("CN"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_subject_success_multiple_attributes() {
    let cert_der = generate_cert_with_subject_edge_cases();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Request multiple attributes that exist with correct values
    let result = validate_subject(
        &cert,
        &[
            ("CN".to_string().into(), "Test Subject".to_string().into()),
            ("O".to_string().into(), "Test Org".to_string().into()),
            ("C".to_string().into(), "US".to_string().into()),
        ],
    );

    assert!(
        result.is_ok(),
        "Multiple attribute validation should succeed"
    );
}

#[test]
fn test_validate_san_no_extension() {
    let cert_der = generate_cert_without_san();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "test.example.com");

    // Should fail because certificate has no SAN extension
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("no Subject Alternative Names"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_san_not_found() {
    let cert_der = generate_cert_with_multiple_sans();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_san(&cert, &SanType::Dns, "nonexistent.example.com");

    // Should fail because requested SAN doesn't exist
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("not found") && msg.contains("nonexistent.example.com"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_san_wrong_type() {
    let cert_der = generate_cert_with_multiple_sans();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Look for "test1.example.com" as an email instead of DNS name
    let result = validate_san(&cert, &SanType::Email, "test1.example.com");

    // Should fail because type doesn't match (it's a DNS name, not email)
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(
                msg.contains("not found") && msg.contains("email"),
                "Error: {}",
                msg
            );
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

#[test]
fn test_validate_san_success_multiple_types() {
    let cert_der = generate_cert_with_multiple_sans();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // Test each SAN type we added
    assert!(validate_san(&cert, &SanType::Dns, "test1.example.com").is_ok());
    assert!(validate_san(&cert, &SanType::Dns, "test2.example.com").is_ok());
    assert!(validate_san(&cert, &SanType::Email, "test@example.com").is_ok());
}

#[test]
fn test_validate_fulcio_issuer_no_extension() {
    let cert_der = generate_cert_without_san(); // Regular cert without Fulcio extension
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    let result = validate_fulcio_issuer(&cert, "github.com");

    // Should fail because certificate has no Fulcio issuer extension
    assert!(result.is_err());
    match result.unwrap_err() {
        DidX509Error::PolicyValidationFailed(msg) => {
            assert!(msg.contains("no Fulcio issuer extension"), "Error: {}", msg);
        }
        _ => panic!("Expected PolicyValidationFailed"),
    }
}

// Note: Testing successful Fulcio validation is difficult without creating certificates
// with the specific Fulcio extension, which would require more complex certificate creation.
// The main coverage goal is to test the error paths which we've done above.

#[test]
fn test_validate_fulcio_issuer_url_normalization() {
    // This test would ideally check the URL normalization logic in validate_fulcio_issuer,
    // but since we can't easily create certificates with Fulcio extensions using rcgen,
    // we've focused on the error path testing above.

    // The URL normalization logic (adding https:// prefix) is covered when the extension
    // exists but doesn't match, which we can't easily test without the extension.

    // Test case showing the expected behavior:
    // If we had a cert with Fulcio issuer "https://github.com" and expected "github.com",
    // it should normalize to "https://github.com" and match.

    let cert_der = generate_cert_without_san();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();

    // This will fail with "no extension" but shows the expected interface
    let result = validate_fulcio_issuer(&cert, "github.com");
    assert!(result.is_err()); // Expected due to no extension
}
