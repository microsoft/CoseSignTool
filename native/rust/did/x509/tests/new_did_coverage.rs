// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::error::DidX509Error;
use did_x509::parsing::DidX509Parser;
use did_x509::*;

// A valid DID string with a 43-char base64url SHA-256 fingerprint and an EKU policy.
const VALID_DID: &str =
    "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkSomeFakeBase64url::eku:1.3.6.1.5.5.7.3.3";

#[test]
fn parse_empty_string_returns_empty_did_error() {
    assert_eq!(DidX509Parser::parse(""), Err(DidX509Error::EmptyDid));
    assert_eq!(DidX509Parser::parse("   "), Err(DidX509Error::EmptyDid));
}

#[test]
fn parse_invalid_prefix_returns_error() {
    let err = DidX509Parser::parse("did:web:example.com").unwrap_err();
    assert!(matches!(err, DidX509Error::InvalidPrefix(_)));
}

#[test]
fn parse_missing_policies_returns_error() {
    let err = DidX509Parser::parse("did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkSomeFakeBase64url")
        .unwrap_err();
    assert!(matches!(err, DidX509Error::MissingPolicies));
}

#[test]
fn parse_valid_did_succeeds() {
    let parsed = DidX509Parser::parse(VALID_DID).unwrap();
    assert_eq!(parsed.hash_algorithm, "sha256");
    assert!(!parsed.ca_fingerprint_hex.is_empty());
    assert!(parsed.has_eku_policy());
    assert!(!parsed.has_subject_policy());
    assert!(!parsed.has_san_policy());
    assert!(!parsed.has_fulcio_issuer_policy());
}

#[test]
fn try_parse_returns_none_for_invalid_and_some_for_valid() {
    assert!(DidX509Parser::try_parse("garbage").is_none());
    assert!(DidX509Parser::try_parse(VALID_DID).is_some());
}

#[test]
fn percent_encode_decode_roundtrip() {
    let original = "hello world/foo@bar";
    let encoded = percent_encode(original);
    let decoded = percent_decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn percent_encode_preserves_allowed_chars() {
    let allowed = "abcABC012-._";
    assert_eq!(percent_encode(allowed), allowed);
}

#[test]
fn percent_decode_empty_string() {
    assert_eq!(percent_decode("").unwrap(), "");
}

#[test]
fn is_valid_oid_checks() {
    use did_x509::parsing::is_valid_oid;
    assert!(is_valid_oid("1.2.3.4"));
    assert!(is_valid_oid("2.5.29.37"));
    assert!(!is_valid_oid(""));
    assert!(!is_valid_oid("1"));
    assert!(!is_valid_oid("abc.def"));
    assert!(!is_valid_oid("1..2"));
}

#[test]
fn san_type_as_str_and_from_str() {
    assert_eq!(SanType::Email.as_str(), "email");
    assert_eq!(SanType::Dns.as_str(), "dns");
    assert_eq!(SanType::Uri.as_str(), "uri");
    assert_eq!(SanType::Dn.as_str(), "dn");

    assert_eq!(SanType::from_str("email"), Some(SanType::Email));
    assert_eq!(SanType::from_str("DNS"), Some(SanType::Dns));
    assert_eq!(SanType::from_str("Uri"), Some(SanType::Uri));
    assert_eq!(SanType::from_str("dn"), Some(SanType::Dn));
    assert_eq!(SanType::from_str("unknown"), None);
}

#[test]
fn subject_alternative_name_convenience_constructors() {
    let email = SubjectAlternativeName::email("a@b.com".into());
    assert_eq!(email.san_type, SanType::Email);
    assert_eq!(email.value, "a@b.com");

    let dns = SubjectAlternativeName::dns("example.com".into());
    assert_eq!(dns.san_type, SanType::Dns);

    let uri = SubjectAlternativeName::uri("https://example.com".into());
    assert_eq!(uri.san_type, SanType::Uri);

    let dn = SubjectAlternativeName::dn("CN=Test".into());
    assert_eq!(dn.san_type, SanType::Dn);
}

#[test]
fn validation_result_methods() {
    let valid = DidX509ValidationResult::valid(2);
    assert!(valid.is_valid);
    assert!(valid.errors.is_empty());
    assert_eq!(valid.matched_ca_index, Some(2));

    let invalid = DidX509ValidationResult::invalid("bad".into());
    assert!(!invalid.is_valid);
    assert_eq!(invalid.errors.len(), 1);

    let multi = DidX509ValidationResult::invalid_multiple(vec!["a".into(), "b".into()]);
    assert!(!multi.is_valid);
    assert_eq!(multi.errors.len(), 2);

    let mut result = DidX509ValidationResult::valid(0);
    result.add_error("oops".into());
    assert!(!result.is_valid);
    assert_eq!(result.errors.len(), 1);
}

#[test]
fn did_x509_error_display_variants() {
    assert_eq!(
        DidX509Error::EmptyDid.to_string(),
        "DID cannot be null or empty"
    );
    assert!(DidX509Error::InvalidPrefix("did:x509".into())
        .to_string()
        .contains("did:x509"));
    assert!(DidX509Error::MissingPolicies.to_string().contains("policy"));
    assert!(DidX509Error::InvalidEkuOid.to_string().contains("OID"));
    assert!(DidX509Error::NoCaMatch.to_string().contains("fingerprint"));
}

#[test]
fn did_x509_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(DidX509Error::EmptyDid);
    assert!(!err.to_string().is_empty());
}

#[test]
fn parsed_identifier_has_and_get_methods() {
    let parsed = DidX509Parser::parse(VALID_DID).unwrap();
    assert!(parsed.has_eku_policy());
    assert!(parsed.get_eku_policy().is_some());
    assert!(!parsed.has_subject_policy());
    assert!(parsed.get_subject_policy().is_none());
}
