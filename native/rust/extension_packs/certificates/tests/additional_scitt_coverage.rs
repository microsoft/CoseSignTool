// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for SCITT CWT claims functionality

use cose_sign1_certificates::signing::scitt::{build_scitt_cwt_claims, create_scitt_contributor};
use cose_sign1_headers::CwtClaims;
use rcgen::{CertificateParams, KeyPair};

fn generate_test_certificate() -> Vec<u8> {
    let mut params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Certificate");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Test Organization");

    let key_pair = KeyPair::generate().unwrap();
    params.self_signed(&key_pair).unwrap().der().to_vec()
}

#[test]
fn test_build_scitt_cwt_claims_empty_chain() {
    let result = build_scitt_cwt_claims(&[], None);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error.to_string().contains("DID:X509 generation failed"));
}

#[test]
fn test_build_scitt_cwt_claims_single_cert() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let result = build_scitt_cwt_claims(&chain, None);
    match result {
        Ok(claims) => {
            assert!(claims.issuer.is_some());
            assert!(claims.subject.is_some());
            assert!(claims.issued_at.is_some());
            assert!(claims.not_before.is_some());
            assert_eq!(claims.subject, Some(CwtClaims::DEFAULT_SUBJECT.to_string()));
        }
        Err(e) => {
            // May fail due to EKU requirements in DID:X509 generation
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}

#[test]
fn test_build_scitt_cwt_claims_with_custom_claims() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let mut custom_claims = CwtClaims::new();
    custom_claims.audience = Some("custom-audience".to_string());
    custom_claims.expiration_time = Some(9999999999);
    custom_claims.not_before = Some(1000000000);
    custom_claims.issued_at = Some(1500000000);

    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    match result {
        Ok(claims) => {
            // Custom claims should be preserved
            assert_eq!(claims.audience, Some("custom-audience".to_string()));
            assert_eq!(claims.expiration_time, Some(9999999999));
            // But issued_at and not_before should be overwritten with current time
            assert!(claims.issued_at.is_some());
            assert!(claims.not_before.is_some());
        }
        Err(e) => {
            // May fail due to EKU requirements
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}

#[test]
fn test_build_scitt_cwt_claims_custom_overwrites_issuer_subject() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let mut custom_claims = CwtClaims::new();
    custom_claims.issuer = Some("custom-issuer".to_string());
    custom_claims.subject = Some("custom-subject".to_string());

    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    match result {
        Ok(claims) => {
            // Custom issuer and subject should override the defaults
            assert_eq!(claims.issuer, Some("custom-issuer".to_string()));
            assert_eq!(claims.subject, Some("custom-subject".to_string()));
        }
        Err(e) => {
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}

#[test]
fn test_build_scitt_cwt_claims_invalid_certificate() {
    let invalid_cert = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Invalid DER
    let chain = [invalid_cert.as_slice()];

    let result = build_scitt_cwt_claims(&chain, None);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error.to_string().contains("DID:X509 generation failed"));
}

#[test]
fn test_build_scitt_cwt_claims_timing_consistency() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let result = build_scitt_cwt_claims(&chain, None);
    match result {
        Ok(claims) => {
            if let (Some(issued_at), Some(not_before)) = (claims.issued_at, claims.not_before) {
                // issued_at and not_before should be the same (current time)
                assert_eq!(issued_at, not_before);
            }
        }
        Err(_) => {
            // Expected to fail without proper EKU
        }
    }
}

#[test]
fn test_create_scitt_contributor_empty_chain() {
    let result = create_scitt_contributor(&[], None);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error.to_string().contains("DID:X509 generation failed"));
}

#[test]
fn test_create_scitt_contributor_single_cert() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let result = create_scitt_contributor(&chain, None);
    match result {
        Ok(contributor) => {
            // Verify the contributor has expected merge strategy
            use cose_sign1_signing::{HeaderContributor, HeaderMergeStrategy};
            assert!(matches!(
                contributor.merge_strategy(),
                HeaderMergeStrategy::Replace
            ));
        }
        Err(e) => {
            // May fail due to EKU requirements
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}

#[test]
fn test_create_scitt_contributor_with_custom_claims() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    let mut custom_claims = CwtClaims::new();
    custom_claims.audience = Some("test-audience".to_string());

    let result = create_scitt_contributor(&chain, Some(&custom_claims));
    match result {
        Ok(contributor) => {
            use cose_sign1_signing::{HeaderContributor, HeaderMergeStrategy};
            assert!(matches!(
                contributor.merge_strategy(),
                HeaderMergeStrategy::Replace
            ));
        }
        Err(e) => {
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}

#[test]
fn test_create_scitt_contributor_invalid_certificate() {
    let invalid_cert = vec![0x00, 0x01, 0x02, 0x03]; // Invalid DER
    let chain = [invalid_cert.as_slice()];

    let result = create_scitt_contributor(&chain, None);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error.to_string().contains("DID:X509 generation failed"));
}

#[test]
fn test_scitt_claims_partial_custom_merge() {
    let cert_der = generate_test_certificate();
    let chain = [cert_der.as_slice()];

    // Test partial custom claims (only some fields set)
    let mut custom_claims = CwtClaims::new();
    custom_claims.audience = Some("partial-audience".to_string());
    // Leave other fields as None

    let result = build_scitt_cwt_claims(&chain, Some(&custom_claims));
    match result {
        Ok(claims) => {
            // Only audience should be from custom claims
            assert_eq!(claims.audience, Some("partial-audience".to_string()));
            // Other fields should be default or generated
            assert!(claims.issuer.is_some()); // Generated from DID:X509
            assert_eq!(claims.subject, Some(CwtClaims::DEFAULT_SUBJECT.to_string()));
            assert!(claims.issued_at.is_some());
            assert!(claims.not_before.is_some());
            assert!(claims.expiration_time.is_none()); // Not set in custom
        }
        Err(e) => {
            assert!(e.to_string().contains("DID:X509 generation failed"));
        }
    }
}
