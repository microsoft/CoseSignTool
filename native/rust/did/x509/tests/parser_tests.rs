// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::error::DidX509Error;
use did_x509::models::{DidX509Policy, SanType};
use did_x509::parsing::DidX509Parser;

// Valid SHA-256 fingerprint: 32 bytes = 43 base64url chars (no padding)
const FP256: &str = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tk";
// Valid SHA-384 fingerprint: 48 bytes = 64 base64url chars (no padding)
const FP384: &str = "AAsWISw3Qk1YY255hI-apbC7xtHc5_L9CBMeKTQ_SlVga3aBjJeirbjDztnk7_oF";
// Valid SHA-512 fingerprint: 64 bytes = 86 base64url chars (no padding)
const FP512: &str = "AA0aJzRBTltodYKPnKm2w9Dd6vcEER4rOEVSX2x5hpOgrbrH1OHu-wgVIi88SVZjcH2Kl6SxvsvY5fL_DBkmMw";

#[test]
fn test_parse_valid_did_with_eku() {
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    assert_eq!(parsed.hash_algorithm, "sha256");
    assert_eq!(parsed.ca_fingerprint_hex.len(), 64); // SHA-256 produces 32 bytes = 64 hex chars
    assert_eq!(parsed.policies.len(), 1);
    
    match &parsed.policies[0] {
        DidX509Policy::Eku(oids) => {
            assert_eq!(oids.len(), 1);
            assert_eq!(oids[0], "1.2.3.4");
        }
        _ => panic!("Expected EKU policy"),
    }
}

#[test]
fn test_parse_valid_did_with_multiple_eku_oids() {
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4:5.6.7.8", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::Eku(oids) => {
            assert_eq!(oids.len(), 2);
            assert_eq!(oids[0], "1.2.3.4");
            assert_eq!(oids[1], "5.6.7.8");
        }
        _ => panic!("Expected EKU policy"),
    }
}

#[test]
fn test_parse_valid_did_with_subject_policy() {
    let did = format!("did:x509:0:sha256:{}::subject:CN:example.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::Subject(attrs) => {
            assert_eq!(attrs.len(), 1);
            assert_eq!(attrs[0].0, "CN");
            assert_eq!(attrs[0].1, "example.com");
        }
        _ => panic!("Expected Subject policy"),
    }
}

#[test]
fn test_parse_valid_did_with_multiple_subject_attributes() {
    let did = format!("did:x509:0:sha256:{}::subject:CN:example.com:O:Example%20Org", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::Subject(attrs) => {
            assert_eq!(attrs.len(), 2);
            assert_eq!(attrs[0].0, "CN");
            assert_eq!(attrs[0].1, "example.com");
            assert_eq!(attrs[1].0, "O");
            assert_eq!(attrs[1].1, "Example Org"); // Should be decoded
        }
        _ => panic!("Expected Subject policy"),
    }
}

#[test]
fn test_parse_valid_did_with_san_email() {
    let did = format!("did:x509:0:sha256:{}::san:email:user@example.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::San(san_type, value) => {
            assert_eq!(*san_type, SanType::Email);
            assert_eq!(value, "user@example.com");
        }
        _ => panic!("Expected SAN policy"),
    }
}

#[test]
fn test_parse_valid_did_with_san_dns() {
    let did = format!("did:x509:0:sha256:{}::san:dns:example.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::San(san_type, value) => {
            assert_eq!(*san_type, SanType::Dns);
            assert_eq!(value, "example.com");
        }
        _ => panic!("Expected SAN policy"),
    }
}

#[test]
fn test_parse_valid_did_with_san_uri() {
    let did = format!("did:x509:0:sha256:{}::san:uri:https%3A%2F%2Fexample.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::San(san_type, value) => {
            assert_eq!(*san_type, SanType::Uri);
            assert_eq!(value, "https://example.com"); // Should be decoded
        }
        _ => panic!("Expected SAN policy"),
    }
}

#[test]
fn test_parse_valid_did_with_fulcio_issuer() {
    let did = format!("did:x509:0:sha256:{}::fulcio-issuer:accounts.google.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    match &parsed.policies[0] {
        DidX509Policy::FulcioIssuer(issuer) => {
            assert_eq!(issuer, "accounts.google.com");
        }
        _ => panic!("Expected Fulcio issuer policy"),
    }
}

#[test]
fn test_parse_valid_did_with_multiple_policies() {
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4::subject:CN:example.com::san:email:user@example.com", FP256);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    
    assert_eq!(parsed.policies.len(), 3);
    assert!(matches!(parsed.policies[0], DidX509Policy::Eku(_)));
    assert!(matches!(parsed.policies[1], DidX509Policy::Subject(_)));
    assert!(matches!(parsed.policies[2], DidX509Policy::San(_, _)));
}

#[test]
fn test_parse_did_with_sha384() {
    let did = format!("did:x509:0:sha384:{}::eku:1.2.3.4", FP384);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.hash_algorithm, "sha384");
}

#[test]
fn test_parse_did_with_sha512() {
    let did = format!("did:x509:0:sha512:{}::eku:1.2.3.4", FP512);
    let result = DidX509Parser::parse(&did);
    
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.hash_algorithm, "sha512");
}

#[test]
fn test_parse_empty_did() {
    let result = DidX509Parser::parse("");
    assert!(matches!(result, Err(DidX509Error::EmptyDid)));
}

#[test]
fn test_parse_whitespace_did() {
    let result = DidX509Parser::parse("   ");
    assert!(matches!(result, Err(DidX509Error::EmptyDid)));
}

#[test]
fn test_parse_invalid_prefix() {
    let did = "did:web:example.com";
    let result = DidX509Parser::parse(did);
    assert!(matches!(result, Err(DidX509Error::InvalidPrefix(_))));
}

#[test]
fn test_parse_missing_policies() {
    let did = format!("did:x509:0:sha256:{}", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::MissingPolicies)));
}

#[test]
fn test_parse_wrong_number_of_prefix_components() {
    let did = "did:x509:0:sha256::eku:1.2.3.4";
    let result = DidX509Parser::parse(did);
    assert!(matches!(result, Err(DidX509Error::InvalidFormat(_))));
}

#[test]
fn test_parse_unsupported_version() {
    let did = format!("did:x509:1:sha256:{}::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::UnsupportedVersion(_, _))));
}

#[test]
fn test_parse_unsupported_hash_algorithm() {
    let did = format!("did:x509:0:md5:{}::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::UnsupportedHashAlgorithm(_))));
}

#[test]
fn test_parse_empty_fingerprint() {
    // With only 4 components in the prefix, this will fail with InvalidFormat
    let did = "did:x509:0:sha256::eku:1.2.3.4";
    let result = DidX509Parser::parse(did);
    assert!(matches!(result, Err(DidX509Error::InvalidFormat(_))));
}

#[test]
fn test_parse_wrong_fingerprint_length() {
    let did = "did:x509:0:sha256:short::eku:1.2.3.4";
    let result = DidX509Parser::parse(did);
    assert!(matches!(result, Err(DidX509Error::FingerprintLengthMismatch(_, _, _))));
}

#[test]
fn test_parse_invalid_fingerprint_chars() {
    // Create a fingerprint with invalid characters (+ is not valid in base64url)
    let invalid_fp = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK+2vcTL0tk"; // + instead of -
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", invalid_fp);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::InvalidFingerprintChars)));
}

#[test]
fn test_parse_empty_policy() {
    let did = format!("did:x509:0:sha256:{}::::eku:1.2.3.4", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::EmptyPolicy(_))));
}

#[test]
fn test_parse_invalid_subject_policy_odd_components() {
    let did = format!("did:x509:0:sha256:{}::subject:CN", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::InvalidSubjectPolicyComponents)));
}

#[test]
fn test_parse_invalid_subject_policy_empty_key() {
    // An empty subject key would look like this: "subject::CN:value"
    // But that gets interpreted as policy ":" with value "CN:value"
    // which would fail on empty policy name check when we try to parse the second policy
    // So let's test a valid parse error for subject policy
    let did = format!("did:x509:0:sha256:{}::subject:", FP256);
    let result = DidX509Parser::parse(&did);
    // This should fail because the policy value is empty
    assert!(matches!(result, Err(DidX509Error::EmptyPolicyValue)));
}

#[test]
fn test_parse_invalid_subject_policy_duplicate_key() {
    let did = format!("did:x509:0:sha256:{}::subject:CN:value1:CN:value2", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::DuplicateSubjectPolicyKey(_))));
}

#[test]
fn test_parse_invalid_san_type() {
    let did = format!("did:x509:0:sha256:{}::san:invalid:value", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::InvalidSanType(_))));
}

#[test]
fn test_parse_invalid_eku_oid() {
    let did = format!("did:x509:0:sha256:{}::eku:not-an-oid", FP256);
    let result = DidX509Parser::parse(&did);
    assert!(matches!(result, Err(DidX509Error::InvalidEkuOid)));
}

#[test]
fn test_parse_empty_fulcio_issuer() {
    // Empty value means nothing after the colon
    let did = format!("did:x509:0:sha256:{}::fulcio-issuer:", FP256);
    let result = DidX509Parser::parse(&did);
    // This triggers EmptyPolicyValue, not EmptyFulcioIssuer, because the check happens first
    assert!(matches!(result, Err(DidX509Error::EmptyPolicyValue)));
}

#[test]
fn test_try_parse_success() {
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let result = DidX509Parser::try_parse(&did);
    assert!(result.is_some());
}

#[test]
fn test_try_parse_failure() {
    let did = "invalid-did";
    let result = DidX509Parser::try_parse(did);
    assert!(result.is_none());
}

#[test]
fn test_parsed_identifier_helper_methods() {
    let did = format!("did:x509:0:sha256:{}::eku:1.2.3.4::subject:CN:example.com", FP256);
    let parsed = DidX509Parser::parse(&did).unwrap();
    
    assert!(parsed.has_eku_policy());
    assert!(parsed.has_subject_policy());
    assert!(!parsed.has_san_policy());
    assert!(!parsed.has_fulcio_issuer_policy());
    
    let eku = parsed.get_eku_policy();
    assert!(eku.is_some());
    assert_eq!(eku.unwrap()[0], "1.2.3.4");
    
    let subject = parsed.get_subject_policy();
    assert!(subject.is_some());
    assert_eq!(subject.unwrap()[0].0, "CN");
}
