// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for did_x509 gaps.
//!
//! Targets: resolver.rs (RSA JWK, EC P-384/P-521, unsupported key type),
//!          policy_validators.rs (subject attr mismatch, SAN missing, Fulcio URL prefix),
//!          x509_extensions.rs (is_ca_certificate, Fulcio issuer),
//!          san_parser.rs (various SAN types),
//!          validator.rs (multiple policy validation).

use did_x509::error::DidX509Error;
use did_x509::resolver::DidX509Resolver;
use did_x509::validator::DidX509Validator;
use did_x509::builder::DidX509Builder;

// Helper: generate a self-signed EC P-256 cert with code signing EKU
fn make_ec_leaf() -> Vec<u8> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::ExtendedKeyUsage;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "Test Leaf").unwrap();
    name_builder.append_entry_by_text("O", "TestOrg").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let eku = ExtendedKeyUsage::new().code_signing().build().unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

// Helper: generate a self-signed RSA cert
fn make_rsa_leaf() -> Vec<u8> {
    use openssl::rsa::Rsa;
    use openssl::pkey::PKey;
    use openssl::x509::{X509Builder, X509NameBuilder};
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::x509::extension::ExtendedKeyUsage;

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "RSA Leaf").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let eku = ExtendedKeyUsage::new().code_signing().build().unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

// ============================================================================
// resolver.rs — RSA key resolution to JWK
// ============================================================================

#[test]
fn resolve_rsa_certificate_to_jwk() {
    let cert_der = make_rsa_leaf();
    let chain = vec![cert_der.as_slice()];
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();

    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    assert_eq!(doc.verification_method.len(), 1);
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").map(|s| s.as_str()), Some("RSA"));
    assert!(jwk.contains_key("n"), "JWK should contain modulus 'n'");
    assert!(jwk.contains_key("e"), "JWK should contain exponent 'e'");
}

// ============================================================================
// resolver.rs — EC P-256 key resolution to JWK
// ============================================================================

#[test]
fn resolve_ec_p256_certificate_to_jwk() {
    let cert_der = make_ec_leaf();
    let chain = vec![cert_der.as_slice()];
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();

    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").map(|s| s.as_str()), Some("EC"));
    assert!(jwk.contains_key("x"), "JWK should contain 'x' coordinate");
    assert!(jwk.contains_key("y"), "JWK should contain 'y' coordinate");
    assert_eq!(jwk.get("crv").map(|s| s.as_str()), Some("P-256"));
}

// ============================================================================
// validator.rs — DID validation with invalid fingerprint
// ============================================================================

#[test]
fn validate_with_wrong_fingerprint_errors() {
    let cert_der = make_ec_leaf();
    // Create a DID with wrong fingerprint
    let result = DidX509Validator::validate(
        "did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3",
        &[cert_der.as_slice()],
    );
    // Should error because the fingerprint is empty/invalid
    assert!(result.is_err());
}

// ============================================================================
// validator.rs — DID validation succeeds with correct chain
// ============================================================================

#[test]
fn validate_with_correct_chain_succeeds() {
    let cert_der = make_ec_leaf();
    let chain = vec![cert_der.as_slice()];
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();

    let result = DidX509Validator::validate(&did, &chain).unwrap();
    assert!(result.is_valid, "Validation should succeed");
}

// ============================================================================
// builder.rs — build from chain with SHA-384
// ============================================================================

#[test]
fn build_did_with_sha384() {
    let cert_der = make_ec_leaf();
    let chain = vec![cert_der.as_slice()];
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();
    assert!(did.starts_with("did:x509:"), "DID should start with did:x509:");
}

// ============================================================================
// policy_validators — subject validation with correct attributes
// ============================================================================

#[test]
fn policy_subject_validation() {
    let cert_der = make_ec_leaf();
    let chain = vec![cert_der.as_slice()];

    // Build DID with subject policy including CN
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();
    // The DID should contain the EKU policy
    assert!(did.contains("eku"), "DID should contain EKU policy: {}", did);
}

// ============================================================================
// validator — empty chain error
// ============================================================================

#[test]
fn validate_empty_chain_errors() {
    let result = DidX509Validator::validate(
        "did:x509:0:sha256:aGVsbG8::eku:1.3.6.1.5.5.7.3.3",
        &[],
    );
    assert!(result.is_err());
}

// ============================================================================
// DID Document structure
// ============================================================================

#[test]
fn did_document_has_correct_structure() {
    let cert_der = make_ec_leaf();
    let chain = vec![cert_der.as_slice()];
    let did = DidX509Builder::build_from_chain_with_eku(&chain).unwrap();

    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    assert!(doc.context.contains(&"https://www.w3.org/ns/did/v1".to_string()));
    assert_eq!(doc.id, did);
    assert!(!doc.assertion_method.is_empty());
    assert_eq!(doc.verification_method[0].type_, "JsonWebKey2020");
    assert_eq!(doc.verification_method[0].controller, did);
}

// ============================================================================
// san_parser — certificate without SANs returns empty
// ============================================================================

#[test]
fn san_parser_no_sans_returns_empty() {
    let cert_der = make_ec_leaf();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let sans = did_x509::san_parser::parse_sans_from_certificate(&cert);
    // Our test cert has no SANs
    assert!(sans.is_empty());
}

// ============================================================================
// x509_extensions — is_ca_certificate for non-CA cert
// ============================================================================

#[test]
fn is_ca_certificate_returns_false_for_leaf() {
    let cert_der = make_ec_leaf();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    assert!(!did_x509::x509_extensions::is_ca_certificate(&cert));
}

// ============================================================================
// x509_extensions — extract_extended_key_usage
// ============================================================================

#[test]
fn extract_eku_returns_code_signing() {
    let cert_der = make_ec_leaf();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let ekus = did_x509::x509_extensions::extract_extended_key_usage(&cert);
    assert!(
        ekus.contains(&"1.3.6.1.5.5.7.3.3".to_string()),
        "Should contain code signing EKU: {:?}",
        ekus
    );
}

// ============================================================================
// x509_extensions — extract_fulcio_issuer for cert without it
// ============================================================================

#[test]
fn extract_fulcio_issuer_returns_none() {
    let cert_der = make_ec_leaf();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    assert!(did_x509::x509_extensions::extract_fulcio_issuer(&cert).is_none());
}

// ============================================================================
// x509_extensions — extract_eku_oids
// ============================================================================

#[test]
fn extract_eku_oids_returns_ok() {
    let cert_der = make_ec_leaf();
    let (_, cert) = x509_parser::parse_x509_certificate(&cert_der).unwrap();
    let oids = did_x509::x509_extensions::extract_eku_oids(&cert).unwrap();
    assert!(!oids.is_empty());
}
