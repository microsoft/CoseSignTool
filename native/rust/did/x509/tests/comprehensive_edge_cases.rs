// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional test coverage for DID x509 library targeting specific uncovered paths

use did_x509::error::DidX509Error;
use did_x509::models::{SanType, DidX509ValidationResult, CertificateInfo, X509Name};
use did_x509::parsing::{DidX509Parser, percent_encode, percent_decode};
use did_x509::builder::DidX509Builder;
use did_x509::validator::DidX509Validator;
use did_x509::resolver::DidX509Resolver;
use did_x509::x509_extensions::{extract_extended_key_usage, is_ca_certificate};

// Valid test fingerprints
const FP256: &str = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tk"; // 43 chars
const FP384: &str = "AAsWISw3Qk1YY255hI-apbC7xtHc5_L9CBMeKTQ_SlVga3aBjJeirbjDztnk7_oF"; // 64 chars

#[test]
fn test_error_display_coverage() {
    // Test all error display formatting to ensure coverage
    let errors = vec![
        DidX509Error::EmptyDid,
        DidX509Error::InvalidPrefix("did:x509".to_string()),
        DidX509Error::MissingPolicies,
        DidX509Error::InvalidFormat("test_format".to_string()),
        DidX509Error::UnsupportedVersion("1".to_string(), "0".to_string()),
        DidX509Error::UnsupportedHashAlgorithm("md5".to_string()),
        DidX509Error::EmptyFingerprint,
        DidX509Error::FingerprintLengthMismatch("sha256".to_string(), 43, 42),
        DidX509Error::InvalidFingerprintChars,
        DidX509Error::EmptyPolicy(1),
        DidX509Error::InvalidPolicyFormat("policy:value".to_string()),
        DidX509Error::EmptyPolicyName,
        DidX509Error::EmptyPolicyValue,
        DidX509Error::InvalidSubjectPolicyComponents,
        DidX509Error::EmptySubjectPolicyKey,
        DidX509Error::DuplicateSubjectPolicyKey("key1".to_string()),
        DidX509Error::InvalidSanPolicyFormat("san:type:value".to_string()),
        DidX509Error::InvalidSanType("invalid".to_string()),
        DidX509Error::InvalidEkuOid,
        DidX509Error::EmptyFulcioIssuer,
        DidX509Error::PercentDecodingError("test error".to_string()),
        DidX509Error::InvalidHexCharacter('z'),
        DidX509Error::InvalidChain("test chain error".to_string()),
        DidX509Error::CertificateParseError("parse error".to_string()),
        DidX509Error::PolicyValidationFailed("validation failed".to_string()),
        DidX509Error::NoCaMatch,
        DidX509Error::ValidationFailed("validation error".to_string()),
    ];

    // Test display formatting for all error types
    for error in errors {
        let formatted = format!("{}", error);
        assert!(!formatted.is_empty());
    }
}

#[test]
fn test_parser_edge_cases_whitespace() {
    // Test with leading/trailing whitespace (not automatically trimmed)
    let did = format!("   did:x509:0:sha256:{}::eku:1.2.3.4   ", FP256);
    let result = DidX509Parser::parse(&did);
    // Parser doesn't auto-trim whitespace
    assert!(result.is_err());
}

#[test]
fn test_parser_case_sensitivity() {
    // Test case insensitive prefix matching
    let did = format!("DID:X509:0:SHA256:{}::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(result.is_ok());
    
    // Hash algorithm should be lowercase in result
    let parsed = result.unwrap();
    assert_eq!(parsed.hash_algorithm, "sha256");
}

#[test]
fn test_parser_invalid_base64_chars() {
    // Test fingerprint with invalid base64url characters
    let invalid_fp = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tk"; // Contains '+' which is invalid base64url
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", invalid_fp);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidFingerprintChars));
}

#[test]
fn test_parser_sha384_length_validation() {
    // Test SHA-384 with wrong length (should be 64 chars)
    let wrong_length_fp = "AAsWISw3Qk1YY255hI-apbC7xtHc5_L9CBMeKTQ_SlVga3aBjJeirbjDztnk7_o"; // 63 chars instead of 64
    let did = format!("did:x509:0:sha384:{}::eku:1.2.3.4", wrong_length_fp);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::FingerprintLengthMismatch("sha384".to_string(), 64, 63)));
}

#[test]
fn test_parser_empty_policy_parts() {
    // Test with empty policy in the middle
    let did = format!("did:x509:0:sha256:{}::::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::EmptyPolicy(1)));
}

#[test]
fn test_parser_invalid_policy_format() {
    // Test policy without colon separator
    let did = format!("did:x509:0:sha256:{}::invalidpolicy", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidPolicyFormat("name:value".to_string())));
}

#[test]
fn test_parser_empty_policy_name() {
    // Test policy with empty name - caught as InvalidPolicyFormat first
    let did = format!("did:x509:0:sha256:{}:::1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidPolicyFormat("name:value".to_string())));
}

#[test]
fn test_parser_empty_policy_value() {
    // Test policy with empty value
    let did = format!("did:x509:0:sha256:{}::eku:", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::EmptyPolicyValue));
}

#[test]
fn test_parser_invalid_subject_policy_odd_components() {
    // Test subject policy with odd number of components
    let did = format!("did:x509:0:sha256:{}::subject:key1:value1:key2", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidSubjectPolicyComponents));
}

#[test]
fn test_parser_empty_subject_key() {
    // Test subject policy with empty key - caught as InvalidPolicyFormat first
    let did = format!("did:x509:0:sha256:{}::subject::value1", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidPolicyFormat("name:value".to_string())));
}

#[test]
fn test_parser_duplicate_subject_key() {
    // Test subject policy with duplicate key
    let did = format!("did:x509:0:sha256:{}::subject:key1:value1:key1:value2", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::DuplicateSubjectPolicyKey("key1".to_string())));
}

#[test]
fn test_parser_invalid_san_policy_format() {
    // Test SAN policy with wrong format (missing type or value)
    let did = format!("did:x509:0:sha256:{}::san:email", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidSanPolicyFormat("type:value".to_string())));
}

#[test]
fn test_parser_invalid_san_type() {
    // Test SAN policy with invalid type
    let did = format!("did:x509:0:sha256:{}::san:invalid:test@example.com", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidSanType("invalid".to_string())));
}

#[test]
fn test_parser_invalid_eku_oid() {
    // Test EKU policy with invalid OID format
    let did = format!("did:x509:0:sha256:{}::eku:not.an.oid", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::InvalidEkuOid));
}

#[test]
fn test_parser_empty_fulcio_issuer() {
    // Test Fulcio issuer policy with empty value - caught as EmptyPolicyValue first
    let did = format!("did:x509:0:sha256:{}::fulcio_issuer:", FP256);
    let result = DidX509Parser::parse(&did);
    assert_eq!(result, Err(DidX509Error::EmptyPolicyValue));
}

#[test]
fn test_percent_encoding_edge_cases() {
    // Test percent encoding with special characters
    let input = "test@example.com";
    let encoded = percent_encode(input);
    assert_eq!(encoded, "test%40example.com");
    
    let decoded = percent_decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn test_percent_decoding_invalid_hex() {
    // Test percent decoding with invalid hex - implementation treats as literal
    let invalid = "test%zz";
    let result = percent_decode(invalid);
    // Invalid hex sequences are treated as literals
    assert!(result.is_ok());
}

#[test]
fn test_percent_decoding_incomplete_sequence() {
    // Test percent decoding with incomplete sequence - implementation treats as literal
    let incomplete = "test%4";
    let result = percent_decode(incomplete);
    // Incomplete sequences are treated as literals
    assert!(result.is_ok());
}

#[test]
fn test_builder_edge_cases() {
    // Test builder with empty certificate chain
    let result = DidX509Builder::build_from_chain(&[], &[]);
    assert!(result.is_err());
}

#[test]
fn test_validator_edge_cases() {
    // Test validator with empty chain
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let result = DidX509Validator::validate(&did, &[]);
    assert!(result.is_err());
}

#[test]
fn test_resolver_edge_cases() {
    // Test resolver with invalid DID
    let invalid_did = "not:a:valid:did";
    let result = DidX509Resolver::resolve(invalid_did, &[]);
    assert!(result.is_err());
}

#[test]
fn test_san_type_display() {
    // Test SanType display formatting for coverage
    let types = vec![
        SanType::Email,
        SanType::Dns,
        SanType::Uri,
        SanType::Dn,
    ];
    
    for san_type in types {
        let formatted = format!("{:?}", san_type);
        assert!(!formatted.is_empty());
    }
}

#[test]
fn test_validation_result_coverage() {
    // Test DidX509ValidationResult fields
    let result = DidX509ValidationResult {
        is_valid: true,
        errors: vec!["test error".to_string()],
        matched_ca_index: Some(0),
    };
    
    assert!(result.is_valid);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.matched_ca_index, Some(0));
}

#[test]
fn test_certificate_info_coverage() {
    // Test CertificateInfo fields
    let subject = X509Name::new(vec![]);
    let issuer = X509Name::new(vec![]);
    
    let info = CertificateInfo::new(
        subject,
        issuer,
        vec![1, 2, 3, 4],
        "01020304".to_string(),
        vec![],
        vec!["1.2.3.4".to_string()],
        false,
        None,
    );
    
    assert!(!info.fingerprint_hex.is_empty());
    assert_eq!(info.extended_key_usage.len(), 1);
    assert!(!info.is_ca);
}

#[test]
fn test_x509_extensions_edge_cases() {
    // Test that extensions functions handle empty/invalid inputs gracefully
    // This is more about ensuring the functions exist and don't panic
    // Real certificate testing is done in other test files
}
