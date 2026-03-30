// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for X.509 name and certificate models

use did_x509::models::x509_name::X509NameAttribute;
use did_x509::models::{CertificateInfo, SanType, SubjectAlternativeName, X509Name};

#[test]
fn test_x509_name_attribute_construction() {
    let attr = X509NameAttribute::new("CN".to_string(), "example.com".to_string());
    assert_eq!(attr.label, "CN");
    assert_eq!(attr.value, "example.com");
}

#[test]
fn test_x509_name_construction() {
    let attrs = vec![
        X509NameAttribute::new("CN".to_string(), "example.com".to_string()),
        X509NameAttribute::new("O".to_string(), "Example Org".to_string()),
        X509NameAttribute::new("C".to_string(), "US".to_string()),
    ];

    let name = X509Name::new(attrs.clone());
    assert_eq!(name.attributes.len(), 3);
    assert_eq!(name.attributes, attrs);
}

#[test]
fn test_x509_name_empty() {
    let name = X509Name::empty();
    assert!(name.attributes.is_empty());
}

#[test]
fn test_x509_name_get_attribute() {
    let attrs = vec![
        X509NameAttribute::new("CN".to_string(), "example.com".to_string()),
        X509NameAttribute::new("O".to_string(), "Example Org".to_string()),
        X509NameAttribute::new("c".to_string(), "US".to_string()), // lowercase
    ];

    let name = X509Name::new(attrs);

    // Test exact match
    assert_eq!(name.get_attribute("CN"), Some("example.com"));
    assert_eq!(name.get_attribute("O"), Some("Example Org"));

    // Test case insensitive match
    assert_eq!(name.get_attribute("cn"), Some("example.com"));
    assert_eq!(name.get_attribute("CN"), Some("example.com"));
    assert_eq!(name.get_attribute("C"), Some("US")); // uppercase lookup for lowercase attribute
    assert_eq!(name.get_attribute("c"), Some("US")); // lowercase lookup

    // Test non-existent attribute
    assert_eq!(name.get_attribute("L"), None);
    assert_eq!(name.get_attribute("nonexistent"), None);
}

#[test]
fn test_x509_name_convenience_methods() {
    let attrs = vec![
        X509NameAttribute::new("CN".to_string(), "example.com".to_string()),
        X509NameAttribute::new("O".to_string(), "Example Org".to_string()),
        X509NameAttribute::new("C".to_string(), "US".to_string()),
    ];

    let name = X509Name::new(attrs);

    assert_eq!(name.common_name(), Some("example.com"));
    assert_eq!(name.organization(), Some("Example Org"));
    assert_eq!(name.country(), Some("US"));
}

#[test]
fn test_x509_name_convenience_methods_missing() {
    let attrs = vec![X509NameAttribute::new(
        "L".to_string(),
        "Seattle".to_string(),
    )];

    let name = X509Name::new(attrs);

    assert_eq!(name.common_name(), None);
    assert_eq!(name.organization(), None);
    assert_eq!(name.country(), None);
}

#[test]
fn test_subject_alternative_name_construction() {
    let san = SubjectAlternativeName::new(SanType::Email, "test@example.com".to_string());
    assert_eq!(san.san_type, SanType::Email);
    assert_eq!(san.value, "test@example.com");
}

#[test]
fn test_subject_alternative_name_convenience_constructors() {
    let email_san = SubjectAlternativeName::email("test@example.com".to_string());
    assert_eq!(email_san.san_type, SanType::Email);
    assert_eq!(email_san.value, "test@example.com");

    let dns_san = SubjectAlternativeName::dns("example.com".to_string());
    assert_eq!(dns_san.san_type, SanType::Dns);
    assert_eq!(dns_san.value, "example.com");

    let uri_san = SubjectAlternativeName::uri("https://example.com".to_string());
    assert_eq!(uri_san.san_type, SanType::Uri);
    assert_eq!(uri_san.value, "https://example.com");

    let dn_san = SubjectAlternativeName::dn("CN=Test".to_string());
    assert_eq!(dn_san.san_type, SanType::Dn);
    assert_eq!(dn_san.value, "CN=Test");
}

#[test]
fn test_certificate_info_construction() {
    let subject = X509Name::new(vec![X509NameAttribute::new(
        "CN".to_string(),
        "subject.example.com".to_string(),
    )]);

    let issuer = X509Name::new(vec![X509NameAttribute::new(
        "CN".to_string(),
        "issuer.example.com".to_string(),
    )]);

    let fingerprint = vec![0x01, 0x02, 0x03, 0x04];
    let fingerprint_hex = "01020304".to_string();

    let sans = vec![
        SubjectAlternativeName::email("test@example.com".to_string()),
        SubjectAlternativeName::dns("example.com".to_string()),
    ];

    let ekus = vec!["1.3.6.1.5.5.7.3.1".to_string()]; // Server Authentication

    let cert_info = CertificateInfo::new(
        subject.clone(),
        issuer.clone(),
        fingerprint.clone(),
        fingerprint_hex.clone(),
        sans.clone(),
        ekus.clone(),
        true,
        Some("accounts.google.com".to_string()),
    );

    assert_eq!(cert_info.subject, subject);
    assert_eq!(cert_info.issuer, issuer);
    assert_eq!(cert_info.fingerprint, fingerprint);
    assert_eq!(cert_info.fingerprint_hex, fingerprint_hex);
    assert_eq!(cert_info.subject_alternative_names, sans);
    assert_eq!(cert_info.extended_key_usage, ekus);
    assert!(cert_info.is_ca);
    assert_eq!(
        cert_info.fulcio_issuer,
        Some("accounts.google.com".to_string())
    );
}

#[test]
fn test_certificate_info_minimal() {
    let cert_info = CertificateInfo::new(
        X509Name::empty(),
        X509Name::empty(),
        Vec::new(),
        String::new(),
        Vec::new(),
        Vec::new(),
        false,
        None,
    );

    assert!(cert_info.subject.attributes.is_empty());
    assert!(cert_info.issuer.attributes.is_empty());
    assert!(cert_info.fingerprint.is_empty());
    assert!(cert_info.fingerprint_hex.is_empty());
    assert!(cert_info.subject_alternative_names.is_empty());
    assert!(cert_info.extended_key_usage.is_empty());
    assert!(!cert_info.is_ca);
    assert_eq!(cert_info.fulcio_issuer, None);
}

// Test Debug implementations
#[test]
fn test_debug_implementations() {
    let attr = X509NameAttribute::new("CN".to_string(), "example.com".to_string());
    let debug_str = format!("{:?}", attr);
    assert!(debug_str.contains("CN"));
    assert!(debug_str.contains("example.com"));

    let name = X509Name::new(vec![attr]);
    let debug_str = format!("{:?}", name);
    assert!(debug_str.contains("X509Name"));

    let san = SubjectAlternativeName::email("test@example.com".to_string());
    let debug_str = format!("{:?}", san);
    assert!(debug_str.contains("Email"));
    assert!(debug_str.contains("test@example.com"));

    let cert_info = CertificateInfo::new(
        name,
        X509Name::empty(),
        Vec::new(),
        String::new(),
        vec![san],
        Vec::new(),
        false,
        None,
    );
    let debug_str = format!("{:?}", cert_info);
    assert!(debug_str.contains("CertificateInfo"));
}

// Test PartialEq implementations
#[test]
fn test_partial_eq_implementations() {
    let attr1 = X509NameAttribute::new("CN".to_string(), "example.com".to_string());
    let attr2 = X509NameAttribute::new("CN".to_string(), "example.com".to_string());
    let attr3 = X509NameAttribute::new("O".to_string(), "Example Org".to_string());

    assert_eq!(attr1, attr2);
    assert_ne!(attr1, attr3);

    let name1 = X509Name::new(vec![attr1.clone()]);
    let name2 = X509Name::new(vec![attr2]);
    let name3 = X509Name::new(vec![attr3]);

    assert_eq!(name1, name2);
    assert_ne!(name1, name3);

    let san1 = SubjectAlternativeName::email("test@example.com".to_string());
    let san2 = SubjectAlternativeName::email("test@example.com".to_string());
    let san3 = SubjectAlternativeName::dns("example.com".to_string());

    assert_eq!(san1, san2);
    assert_ne!(san1, san3);
}

// Test Hash implementations for types that need it
#[test]
fn test_hash_implementations() {
    use std::collections::HashMap;

    let mut attr_map = HashMap::new();
    let attr = X509NameAttribute::new("CN".to_string(), "example.com".to_string());
    attr_map.insert(attr, "value");

    let mut san_map = HashMap::new();
    let san = SubjectAlternativeName::email("test@example.com".to_string());
    san_map.insert(san, "value");

    // Should be able to use these types as keys in HashMap
    assert_eq!(attr_map.len(), 1);
    assert_eq!(san_map.len(), 1);
}

// Test SanType::as_str and from_str
#[test]
fn test_san_type_as_str() {
    assert_eq!(SanType::Email.as_str(), "email");
    assert_eq!(SanType::Dns.as_str(), "dns");
    assert_eq!(SanType::Uri.as_str(), "uri");
    assert_eq!(SanType::Dn.as_str(), "dn");
}

#[test]
fn test_san_type_from_str() {
    assert_eq!(SanType::from_str("email"), Some(SanType::Email));
    assert_eq!(SanType::from_str("dns"), Some(SanType::Dns));
    assert_eq!(SanType::from_str("uri"), Some(SanType::Uri));
    assert_eq!(SanType::from_str("dn"), Some(SanType::Dn));
    assert_eq!(SanType::from_str("EMAIL"), Some(SanType::Email)); // case insensitive
    assert_eq!(SanType::from_str("DNS"), Some(SanType::Dns));
    assert_eq!(SanType::from_str("unknown"), None);
}
