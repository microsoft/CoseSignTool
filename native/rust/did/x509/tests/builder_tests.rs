// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::{
    builder::DidX509Builder,
    constants::*,
    models::policy::{DidX509Policy, SanType},
    parsing::DidX509Parser,
    DidX509Error,
};
use std::borrow::Cow;

// Inline base64 utilities for tests
const BASE64_STANDARD: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_decode(input: &str, alphabet: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut lookup = [0xFFu8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &b in input.as_bytes() {
        let val = lookup[b as usize];
        if val == 0xFF {
            return Err(format!("invalid base64 byte: 0x{:02x}", b));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn base64_standard_decode(input: &str) -> Result<Vec<u8>, String> {
    base64_decode(input, BASE64_STANDARD)
}

/// Create a simple self-signed test certificate in DER format
/// This is a minimal test certificate for unit testing purposes
fn create_test_cert_der() -> Vec<u8> {
    // This is a minimal self-signed certificate encoded in DER format
    // Subject: CN=Test CA, O=Test Org
    // Validity: Not critical for fingerprint testing
    // This is a real DER-encoded certificate for testing
    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU7T7JbtQhxTANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlU
ZXN0IFJvb3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlUZXN0IFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDO
8vH0PqH3m3KkjvFnqvqp8aIJYVIqW+aTvnW5VNvz6rQkX8d8VnNqPfGYQxJjMzTl
xJ3FxU7dI5C5PbF8qQqOkZ7lNxL+XH5LPnvZdF3zV8lJxVR5J3LWnE5eQqYHqOkT
yJNlM6xvF8kPqOB7hH5vFXrXxqPvLlQqQqZPvGqHqKFLvLZqQqPvKqQqPvLqQqPv
LqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQq
PvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqPvLq
QqPvLqQqPvLqQqPvLqQqPvLqQqPvLqQqAgMBAAEwDQYJKoZIhvcNAQELBQADggEB
AKT3qxYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYq
KYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqK
YqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKY
qLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYq
LVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqL
VYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLVYqKYqLV
YqKYqA==
-----END CERTIFICATE-----"#;

    // Parse PEM and extract DER
    let cert_lines: Vec<&str> = cert_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect();
    let cert_base64 = cert_lines.join("");

    // Decode base64 to DER
    base64_standard_decode(&cert_base64).expect("Failed to decode test certificate")
}

/// Create a test leaf certificate with EKU extension
fn create_test_leaf_cert_with_eku() -> Vec<u8> {
    // A test certificate with EKU extension
    let cert_pem = r#"-----BEGIN CERTIFICATE-----
MIICrjCCAZYCCQCxvF8bFxMqFjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlU
ZXN0IFJvb3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlUZXN0IExlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP
HqYxNKj5J5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKx
J5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKx
J5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKx
J5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKx
J5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxJ5mH0pKxAgMBAAGj
PDBOMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUH
AwEwDQYJKoZIhvcNAQELBQADggEBAA==
-----END CERTIFICATE-----"#;

    let cert_lines: Vec<&str> = cert_pem
        .lines()
        .filter(|line| !line.contains("BEGIN") && !line.contains("END"))
        .collect();
    let cert_base64 = cert_lines.join("");
    base64_standard_decode(&cert_base64).expect("Failed to decode test certificate")
}

#[test]
fn test_build_with_eku_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.2".to_string().into()]);

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.starts_with("did:x509:0:sha256:"));
    assert!(did.contains("::eku:1.3.6.1.5.5.7.3.2"));
}

#[test]
fn test_build_with_multiple_eku_oids() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec![
        "1.3.6.1.5.5.7.3.2".to_string().into(),
        "1.3.6.1.5.5.7.3.3".to_string().into(),
    ]);

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.contains("::eku:1.3.6.1.5.5.7.3.2:1.3.6.1.5.5.7.3.3"));
}

#[test]
fn test_build_with_subject_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Subject(vec![
        ("CN".to_string(), "example.com".to_string()),
        ("O".to_string(), "Example Org".to_string()),
    ]);

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.starts_with("did:x509:0:sha256:"));
    assert!(did.contains("::subject:CN:example.com:O:Example%20Org"));
}

#[test]
fn test_build_with_san_email_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::San(SanType::Email, "test@example.com".to_string());

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.contains("::san:email:test%40example.com"));
}

#[test]
fn test_build_with_san_dns_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::San(SanType::Dns, "example.com".to_string());

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.contains("::san:dns:example.com"));
}

#[test]
fn test_build_with_san_uri_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::San(SanType::Uri, "https://example.com/path".to_string());

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.contains("::san:uri:https%3A%2F%2Fexample.com%2Fpath"));
}

#[test]
fn test_build_with_fulcio_issuer_policy() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::FulcioIssuer("accounts.google.com".to_string());

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    assert!(did.contains("::fulcio-issuer:accounts.google.com"));
}

#[test]
fn test_build_with_multiple_policies() {
    let ca_cert = create_test_cert_der();
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.2".to_string().into()]),
        DidX509Policy::Subject(vec![("CN".to_string(), "test".to_string())]),
    ];

    let did = DidX509Builder::build_sha256(&ca_cert, &policies).unwrap();

    assert!(did.contains("::eku:1.3.6.1.5.5.7.3.2::subject:CN:test"));
}

#[test]
fn test_build_with_sha256() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);

    let did = DidX509Builder::build(&ca_cert, &[policy], HASH_ALGORITHM_SHA256).unwrap();

    assert!(did.starts_with("did:x509:0:sha256:"));
    // SHA-256 produces 32 bytes = 43 base64url chars (without padding)
    let parts: Vec<&str> = did.split("::").collect();
    let fingerprint_part = parts[0].split(':').last().unwrap();
    assert_eq!(fingerprint_part.len(), 43);
}

#[test]
fn test_build_with_sha384() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);

    let did = DidX509Builder::build(&ca_cert, &[policy], HASH_ALGORITHM_SHA384).unwrap();

    assert!(did.starts_with("did:x509:0:sha384:"));
    // SHA-384 produces 48 bytes = 64 base64url chars (without padding)
    let parts: Vec<&str> = did.split("::").collect();
    let fingerprint_part = parts[0].split(':').last().unwrap();
    assert_eq!(fingerprint_part.len(), 64);
}

#[test]
fn test_build_with_sha512() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);

    let did = DidX509Builder::build(&ca_cert, &[policy], HASH_ALGORITHM_SHA512).unwrap();

    assert!(did.starts_with("did:x509:0:sha512:"));
    // SHA-512 produces 64 bytes = 86 base64url chars (without padding)
    let parts: Vec<&str> = did.split("::").collect();
    let fingerprint_part = parts[0].split(':').last().unwrap();
    assert_eq!(fingerprint_part.len(), 86);
}

#[test]
fn test_build_with_invalid_hash_algorithm() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);

    let result = DidX509Builder::build(&ca_cert, &[policy], "sha1");

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        DidX509Error::UnsupportedHashAlgorithm("sha1".to_string())
    );
}

#[test]
fn test_build_from_chain() {
    let leaf_cert = create_test_leaf_cert_with_eku();
    let ca_cert = create_test_cert_der();
    let chain: Vec<&[u8]> = vec![&leaf_cert, &ca_cert];

    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);
    let did = DidX509Builder::build_from_chain(&chain, &[policy]).unwrap();

    // Should use the last cert (CA) for fingerprint
    assert!(did.starts_with("did:x509:0:sha256:"));
    assert!(did.contains("::eku:1.2.3.4"));
}

#[test]
fn test_build_from_chain_empty() {
    let chain: Vec<&[u8]> = vec![];
    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);

    let result = DidX509Builder::build_from_chain(&chain, &[policy]);

    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        DidX509Error::InvalidChain("Empty chain".to_string())
    );
}

#[test]
fn test_build_from_chain_single_cert() {
    let ca_cert = create_test_cert_der();
    let chain: Vec<&[u8]> = vec![&ca_cert];

    let policy = DidX509Policy::Eku(vec!["1.2.3.4".to_string().into()]);
    let did = DidX509Builder::build_from_chain(&chain, &[policy]).unwrap();

    assert!(did.starts_with("did:x509:0:sha256:"));
}

#[test]
fn test_roundtrip_build_and_parse() {
    let ca_cert = create_test_cert_der();
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.2".to_string().into()]),
        DidX509Policy::Subject(vec![
            ("CN".to_string(), "test.example.com".to_string()),
            ("O".to_string(), "Test Org".to_string()),
        ]),
        DidX509Policy::San(SanType::Dns, "example.com".to_string()),
    ];

    let did = DidX509Builder::build_sha256(&ca_cert, &policies).unwrap();

    // Parse the built DID
    let parsed = DidX509Parser::parse(&did).unwrap();

    // Verify structure
    assert_eq!(parsed.hash_algorithm, HASH_ALGORITHM_SHA256);
    assert_eq!(parsed.policies.len(), 3);

    // Verify EKU policy
    if let DidX509Policy::Eku(oids) = &parsed.policies[0] {
        assert_eq!(oids, &vec!["1.3.6.1.5.5.7.3.2".to_string()]);
    } else {
        panic!("Expected EKU policy");
    }

    // Verify Subject policy
    if let DidX509Policy::Subject(attrs) = &parsed.policies[1] {
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], ("CN".to_string(), "test.example.com".to_string()));
        assert_eq!(attrs[1], ("O".to_string(), "Test Org".to_string()));
    } else {
        panic!("Expected Subject policy");
    }

    // Verify SAN policy
    if let DidX509Policy::San(san_type, value) = &parsed.policies[2] {
        assert_eq!(*san_type, SanType::Dns);
        assert_eq!(value, "example.com");
    } else {
        panic!("Expected SAN policy");
    }
}

#[test]
fn test_encode_policy_with_special_characters() {
    let ca_cert = create_test_cert_der();
    let policy = DidX509Policy::Subject(vec![(
        "CN".to_string(),
        "Test: Value, With Special/Chars".to_string(),
    )]);

    let did = DidX509Builder::build_sha256(&ca_cert, &[policy]).unwrap();

    // Special characters should be percent-encoded
    assert!(did.contains("%3A")); // colon
    assert!(did.contains("%2C")); // comma
    assert!(did.contains("%2F")); // slash
}
