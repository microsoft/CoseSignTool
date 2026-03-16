// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for error Display implementations and coverage

use did_x509::error::DidX509Error;

#[test]
fn test_error_display_empty_did() {
    let error = DidX509Error::EmptyDid;
    assert_eq!(error.to_string(), "DID cannot be null or empty");
}

#[test]
fn test_error_display_invalid_prefix() {
    let error = DidX509Error::InvalidPrefix("did:web".to_string());
    assert_eq!(error.to_string(), "Invalid DID: must start with 'did:web':");
}

#[test]
fn test_error_display_missing_policies() {
    let error = DidX509Error::MissingPolicies;
    assert_eq!(error.to_string(), "Invalid DID: must contain at least one policy");
}

#[test]
fn test_error_display_invalid_format() {
    let error = DidX509Error::InvalidFormat("expected:format".to_string());
    assert_eq!(error.to_string(), "Invalid DID: expected format 'expected:format'");
}

#[test]
fn test_error_display_unsupported_version() {
    let error = DidX509Error::UnsupportedVersion("1".to_string(), "0".to_string());
    assert_eq!(error.to_string(), "Invalid DID: unsupported version '1', expected '0'");
}

#[test]
fn test_error_display_unsupported_hash_algorithm() {
    let error = DidX509Error::UnsupportedHashAlgorithm("md5".to_string());
    assert_eq!(error.to_string(), "Invalid DID: unsupported hash algorithm 'md5'");
}

#[test]
fn test_error_display_empty_fingerprint() {
    let error = DidX509Error::EmptyFingerprint;
    assert_eq!(error.to_string(), "Invalid DID: CA fingerprint cannot be empty");
}

#[test]
fn test_error_display_fingerprint_length_mismatch() {
    let error = DidX509Error::FingerprintLengthMismatch("sha256".to_string(), 32, 16);
    assert_eq!(error.to_string(), "Invalid DID: CA fingerprint length mismatch for sha256 (expected 32, got 16)");
}

#[test]
fn test_error_display_invalid_fingerprint_chars() {
    let error = DidX509Error::InvalidFingerprintChars;
    assert_eq!(error.to_string(), "Invalid DID: CA fingerprint contains invalid base64url characters");
}

#[test]
fn test_error_display_empty_policy() {
    let error = DidX509Error::EmptyPolicy(2);
    assert_eq!(error.to_string(), "Invalid DID: empty policy at position 2");
}

#[test]
fn test_error_display_invalid_policy_format() {
    let error = DidX509Error::InvalidPolicyFormat("type:value".to_string());
    assert_eq!(error.to_string(), "Invalid DID: policy must have format 'type:value'");
}

#[test]
fn test_error_display_empty_policy_name() {
    let error = DidX509Error::EmptyPolicyName;
    assert_eq!(error.to_string(), "Invalid DID: policy name cannot be empty");
}

#[test]
fn test_error_display_empty_policy_value() {
    let error = DidX509Error::EmptyPolicyValue;
    assert_eq!(error.to_string(), "Invalid DID: policy value cannot be empty");
}

#[test]
fn test_error_display_invalid_subject_policy_components() {
    let error = DidX509Error::InvalidSubjectPolicyComponents;
    assert_eq!(error.to_string(), "Invalid subject policy: must have even number of components (key:value pairs)");
}

#[test]
fn test_error_display_empty_subject_policy_key() {
    let error = DidX509Error::EmptySubjectPolicyKey;
    assert_eq!(error.to_string(), "Invalid subject policy: key cannot be empty");
}

#[test]
fn test_error_display_duplicate_subject_policy_key() {
    let error = DidX509Error::DuplicateSubjectPolicyKey("CN".to_string());
    assert_eq!(error.to_string(), "Invalid subject policy: duplicate key 'CN'");
}

#[test]
fn test_error_display_invalid_san_policy_format() {
    let error = DidX509Error::InvalidSanPolicyFormat("type:value".to_string());
    assert_eq!(error.to_string(), "Invalid SAN policy: must have format 'type:value'");
}

#[test]
fn test_error_display_invalid_san_type() {
    let error = DidX509Error::InvalidSanType("invalid".to_string());
    assert_eq!(error.to_string(), "Invalid SAN policy: SAN type must be 'email', 'dns', 'uri', or 'dn' (got 'invalid')");
}

#[test]
fn test_error_display_invalid_eku_oid() {
    let error = DidX509Error::InvalidEkuOid;
    assert_eq!(error.to_string(), "Invalid EKU policy: must be a valid OID in dotted decimal notation");
}

#[test]
fn test_error_display_empty_fulcio_issuer() {
    let error = DidX509Error::EmptyFulcioIssuer;
    assert_eq!(error.to_string(), "Invalid Fulcio issuer policy: issuer cannot be empty");
}

#[test]
fn test_error_display_percent_decoding_error() {
    let error = DidX509Error::PercentDecodingError("Invalid escape sequence".to_string());
    assert_eq!(error.to_string(), "Percent decoding error: Invalid escape sequence");
}

#[test]
fn test_error_display_invalid_hex_character() {
    let error = DidX509Error::InvalidHexCharacter('g');
    assert_eq!(error.to_string(), "Invalid hex character: g");
}

#[test]
fn test_error_display_invalid_chain() {
    let error = DidX509Error::InvalidChain("Chain validation failed".to_string());
    assert_eq!(error.to_string(), "Invalid chain: Chain validation failed");
}

#[test]
fn test_error_display_certificate_parse_error() {
    let error = DidX509Error::CertificateParseError("DER decoding failed".to_string());
    assert_eq!(error.to_string(), "Certificate parse error: DER decoding failed");
}

#[test]
fn test_error_display_policy_validation_failed() {
    let error = DidX509Error::PolicyValidationFailed("Subject mismatch".to_string());
    assert_eq!(error.to_string(), "Policy validation failed: Subject mismatch");
}

#[test]
fn test_error_display_no_ca_match() {
    let error = DidX509Error::NoCaMatch;
    assert_eq!(error.to_string(), "No CA certificate in chain matches fingerprint");
}

#[test]
fn test_error_display_validation_failed() {
    let error = DidX509Error::ValidationFailed("Signature verification failed".to_string());
    assert_eq!(error.to_string(), "Validation failed: Signature verification failed");
}

// Test Debug trait implementation
#[test]
fn test_error_debug_trait() {
    let error = DidX509Error::EmptyDid;
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("EmptyDid"));
    
    let error = DidX509Error::InvalidPrefix("did:web".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("InvalidPrefix"));
    assert!(debug_str.contains("did:web"));
}

// Test PartialEq trait implementation
#[test]
fn test_error_partial_eq() {
    assert_eq!(DidX509Error::EmptyDid, DidX509Error::EmptyDid);
    assert_ne!(DidX509Error::EmptyDid, DidX509Error::MissingPolicies);
    
    assert_eq!(
        DidX509Error::InvalidPrefix("did:web".to_string()),
        DidX509Error::InvalidPrefix("did:web".to_string())
    );
    assert_ne!(
        DidX509Error::InvalidPrefix("did:web".to_string()),
        DidX509Error::InvalidPrefix("did:key".to_string())
    );
}

// Test Error trait implementation
#[test]
fn test_error_trait() {
    use std::error::Error;
    
    let error = DidX509Error::EmptyDid;
    let _: &dyn Error = &error; // Should implement Error trait
    
    // Test that source() returns None (default implementation)
    assert!(error.source().is_none());
}

// Test all error variants for completeness
#[test]
fn test_all_error_variants() {
    let errors = vec![
        DidX509Error::EmptyDid,
        DidX509Error::InvalidPrefix("test".to_string()),
        DidX509Error::MissingPolicies,
        DidX509Error::InvalidFormat("test".to_string()),
        DidX509Error::UnsupportedVersion("1".to_string(), "0".to_string()),
        DidX509Error::UnsupportedHashAlgorithm("md5".to_string()),
        DidX509Error::EmptyFingerprint,
        DidX509Error::FingerprintLengthMismatch("sha256".to_string(), 32, 16),
        DidX509Error::InvalidFingerprintChars,
        DidX509Error::EmptyPolicy(0),
        DidX509Error::InvalidPolicyFormat("test".to_string()),
        DidX509Error::EmptyPolicyName,
        DidX509Error::EmptyPolicyValue,
        DidX509Error::InvalidSubjectPolicyComponents,
        DidX509Error::EmptySubjectPolicyKey,
        DidX509Error::DuplicateSubjectPolicyKey("CN".to_string()),
        DidX509Error::InvalidSanPolicyFormat("test".to_string()),
        DidX509Error::InvalidSanType("invalid".to_string()),
        DidX509Error::InvalidEkuOid,
        DidX509Error::EmptyFulcioIssuer,
        DidX509Error::PercentDecodingError("test".to_string()),
        DidX509Error::InvalidHexCharacter('z'),
        DidX509Error::InvalidChain("test".to_string()),
        DidX509Error::CertificateParseError("test".to_string()),
        DidX509Error::PolicyValidationFailed("test".to_string()),
        DidX509Error::NoCaMatch,
        DidX509Error::ValidationFailed("test".to_string()),
    ];
    
    // Ensure all error variants have Display implementations
    for error in errors {
        let _display_str = error.to_string();
        let _debug_str = format!("{:?}", error);
        // All should complete without panicking
    }
}
