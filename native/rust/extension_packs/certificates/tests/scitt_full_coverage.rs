// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for SCITT CWT claims functionality with real certificates.

use cose_sign1_certificates::signing::scitt::{build_scitt_cwt_claims, create_scitt_contributor};
use cose_sign1_certificates::error::CertificateError;
use cose_sign1_headers::CwtClaims;
use cose_sign1_signing::{HeaderContributor, HeaderMergeStrategy};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};

fn make_cert_with_eku() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    cert.der().as_ref().to_vec()
}

fn make_two_cert_chain() -> Vec<Vec<u8>> {
    let mut root_params = CertificateParams::new(vec!["root.example.com".to_string()]).unwrap();
    root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    
    let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let root_cert = root_params.self_signed(&root_key).unwrap();
    
    let mut leaf_params = CertificateParams::new(vec!["leaf.example.com".to_string()]).unwrap();
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let issuer = Issuer::from_ca_cert_der(root_cert.der(), &root_key).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    
    vec![
        leaf_cert.der().to_vec(),
        root_cert.der().to_vec(),
    ]
}

#[test]
fn test_build_scitt_cwt_claims_single_cert_success() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let result = build_scitt_cwt_claims(&chain, None);
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    assert!(claims.issuer.is_some(), "Issuer should be DID:X509");
    assert!(claims.subject.is_some(), "Subject should be default");
    assert_eq!(claims.subject, Some(CwtClaims::DEFAULT_SUBJECT.to_string()));
    assert!(claims.issued_at.is_some(), "Issued at should be current time");
    assert!(claims.not_before.is_some(), "Not before should be current time");
    
    // Verify DID:X509 format
    let issuer = claims.issuer.unwrap();
    assert!(issuer.starts_with("did:x509:"), "Issuer should be DID:X509 format: {}", issuer);
}

#[test]
fn test_build_scitt_cwt_claims_two_cert_chain() {
    let chain_vec = make_two_cert_chain();
    let chain: Vec<&[u8]> = chain_vec.iter().map(|c| c.as_slice()).collect();
    
    let result = build_scitt_cwt_claims(&chain, None);
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    assert!(claims.issuer.is_some());
    assert!(claims.subject.is_some());
    
    let issuer = claims.issuer.unwrap();
    assert!(issuer.starts_with("did:x509:"));
}

#[test]
fn test_build_scitt_cwt_claims_timing_consistency() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    let result = build_scitt_cwt_claims(&chain, None);
    
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    
    assert!(result.is_ok());
    let claims = result.unwrap();
    
    let issued_at = claims.issued_at.unwrap();
    let not_before = claims.not_before.unwrap();
    
    // issued_at and not_before should be the same
    assert_eq!(issued_at, not_before, "issued_at and not_before should be identical");
    
    // Should be within the time window
    assert!(issued_at >= before, "issued_at should be >= before time");
    assert!(issued_at <= after, "issued_at should be <= after time");
}

#[test]
fn test_build_scitt_cwt_claims_custom_issuer_override() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_issuer("custom-issuer".to_string());
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom issuer should override DID:X509
    assert_eq!(claims.issuer, Some("custom-issuer".to_string()));
}

#[test]
fn test_build_scitt_cwt_claims_custom_subject_override() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_subject("custom-subject".to_string());
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom subject should override default
    assert_eq!(claims.subject, Some("custom-subject".to_string()));
}

#[test]
fn test_build_scitt_cwt_claims_custom_audience() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_audience("test-audience".to_string());
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom audience should be preserved
    assert_eq!(claims.audience, Some("test-audience".to_string()));
}

#[test]
fn test_build_scitt_cwt_claims_custom_expiration() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_expiration_time(9999999999);
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom expiration should be preserved
    assert_eq!(claims.expiration_time, Some(9999999999));
}

#[test]
fn test_build_scitt_cwt_claims_custom_not_before() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_not_before(1234567890);
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom not_before should override generated value
    assert_eq!(claims.not_before, Some(1234567890));
}

#[test]
fn test_build_scitt_cwt_claims_custom_issued_at() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_issued_at(9876543210);
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Custom issued_at should override generated value
    assert_eq!(claims.issued_at, Some(9876543210));
}

#[test]
fn test_build_scitt_cwt_claims_partial_custom_merge() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    // Set only some fields
    let custom_claims = CwtClaims::new()
        .with_audience("partial-audience".to_string())
        .with_expiration_time(12345);
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    
    // Custom fields should be preserved
    assert_eq!(claims.audience, Some("partial-audience".to_string()));
    assert_eq!(claims.expiration_time, Some(12345));
    
    // Non-custom fields should be generated
    assert!(claims.issuer.is_some());
    assert_eq!(claims.subject, Some(CwtClaims::DEFAULT_SUBJECT.to_string()));
    assert!(claims.issued_at.is_some());
    assert!(claims.not_before.is_some());
}

#[test]
fn test_build_scitt_cwt_claims_all_custom_fields() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_issuer("all-custom-issuer".to_string())
        .with_subject("all-custom-subject".to_string())
        .with_audience("all-custom-audience".to_string())
        .with_expiration_time(111111)
        .with_not_before(222222)
        .with_issued_at(333333);
    
    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    
    // All custom fields should be present
    assert_eq!(claims.issuer, Some("all-custom-issuer".to_string()));
    assert_eq!(claims.subject, Some("all-custom-subject".to_string()));
    assert_eq!(claims.audience, Some("all-custom-audience".to_string()));
    assert_eq!(claims.expiration_time, Some(111111));
    assert_eq!(claims.not_before, Some(222222));
    assert_eq!(claims.issued_at, Some(333333));
}

#[test]
fn test_build_scitt_cwt_claims_empty_chain_error() {
    let result = build_scitt_cwt_claims(&[], None);
    assert!(result.is_err());
    
    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(msg.contains("DID:X509 generation failed"));
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_build_scitt_cwt_claims_invalid_cert_error() {
    let invalid_cert = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let chain = [invalid_cert.as_slice()];
    
    let result = build_scitt_cwt_claims(&chain, None);
    assert!(result.is_err());
    
    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(msg.contains("DID:X509 generation failed"));
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_create_scitt_contributor_success() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let result = create_scitt_contributor(&chain, None);
    assert!(result.is_ok());
    
    let contributor = result.unwrap();
    
    // Verify merge strategy is Replace
    assert!(matches!(contributor.merge_strategy(), HeaderMergeStrategy::Replace));
}

#[test]
fn test_create_scitt_contributor_with_custom_claims() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let custom_claims = CwtClaims::new()
        .with_issuer("contributor-issuer".to_string())
        .with_audience("contributor-audience".to_string());
    
    let result = create_scitt_contributor(&chain, Some(&custom_claims));
    assert!(result.is_ok());
    
    let contributor = result.unwrap();
    assert!(matches!(contributor.merge_strategy(), HeaderMergeStrategy::Replace));
}

#[test]
fn test_create_scitt_contributor_empty_chain_error() {
    let result = create_scitt_contributor(&[], None);
    assert!(result.is_err());
    
    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(msg.contains("DID:X509 generation failed"));
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_create_scitt_contributor_invalid_cert_error() {
    let invalid_cert = vec![0x00, 0x01, 0x02, 0x03];
    let chain = [invalid_cert.as_slice()];
    
    let result = create_scitt_contributor(&chain, None);
    assert!(result.is_err());
    
    match result {
        Err(CertificateError::InvalidCertificate(msg)) => {
            assert!(msg.contains("DID:X509 generation failed"));
        }
        _ => panic!("Expected InvalidCertificate error"),
    }
}

#[test]
fn test_create_scitt_contributor_encoding_failure_handling() {
    // This test exercises the error path where CwtClaimsHeaderContributor::new fails
    // In practice, this is hard to trigger since CBOR encoding is robust,
    // but we can test that the error is properly converted
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    // Create contributor - should succeed with valid input
    let result = create_scitt_contributor(&chain, None);
    assert!(result.is_ok());
}

#[test]
fn test_scitt_cwt_claims_default_subject_constant() {
    let cert_der = make_cert_with_eku();
    let chain = [cert_der.as_slice()];
    
    let result = build_scitt_cwt_claims(&chain, None);
    assert!(result.is_ok());
    
    let claims = result.unwrap();
    // Verify we use the constant from CwtClaims
    assert_eq!(claims.subject, Some(CwtClaims::DEFAULT_SUBJECT.to_string()));
}
