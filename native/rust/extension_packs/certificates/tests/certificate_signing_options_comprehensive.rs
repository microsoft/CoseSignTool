// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for CertificateSigningOptions.

use cose_sign1_certificates::signing::certificate_signing_options::CertificateSigningOptions;
use cose_sign1_headers::CwtClaims;

#[test]
fn test_default_options() {
    let options = CertificateSigningOptions::default();
    assert_eq!(options.enable_scitt_compliance, true, "SCITT compliance should be enabled by default");
    assert!(options.custom_cwt_claims.is_none(), "Custom CWT claims should be None by default");
}

#[test]
fn test_new_options() {
    let options = CertificateSigningOptions::new();
    assert_eq!(options.enable_scitt_compliance, true, "new() should match default()");
    assert!(options.custom_cwt_claims.is_none(), "new() should match default()");
}

#[test]
fn test_new_equals_default() {
    let new_opts = CertificateSigningOptions::new();
    let default_opts = CertificateSigningOptions::default();
    
    assert_eq!(new_opts.enable_scitt_compliance, default_opts.enable_scitt_compliance);
    assert_eq!(new_opts.custom_cwt_claims.is_none(), default_opts.custom_cwt_claims.is_none());
}

#[test]
fn test_disable_scitt_compliance() {
    let mut options = CertificateSigningOptions::new();
    options.enable_scitt_compliance = false;
    
    assert_eq!(options.enable_scitt_compliance, false, "Should allow disabling SCITT compliance");
}

#[test]
fn test_enable_scitt_compliance() {
    let mut options = CertificateSigningOptions::new();
    options.enable_scitt_compliance = false;
    options.enable_scitt_compliance = true;
    
    assert_eq!(options.enable_scitt_compliance, true, "Should allow re-enabling SCITT compliance");
}

#[test]
fn test_set_custom_cwt_claims() {
    let mut options = CertificateSigningOptions::new();
    let claims = CwtClaims::new().with_issuer("test-issuer".to_string());
    
    options.custom_cwt_claims = Some(claims);
    
    assert!(options.custom_cwt_claims.is_some(), "Should allow setting custom CWT claims");
    assert_eq!(
        options.custom_cwt_claims.as_ref().unwrap().issuer,
        Some("test-issuer".to_string())
    );
}

#[test]
fn test_clear_custom_cwt_claims() {
    let mut options = CertificateSigningOptions::new();
    let claims = CwtClaims::new().with_issuer("test".to_string());
    options.custom_cwt_claims = Some(claims);
    
    options.custom_cwt_claims = None;
    
    assert!(options.custom_cwt_claims.is_none(), "Should allow clearing custom CWT claims");
}

#[test]
fn test_custom_cwt_claims_with_all_fields() {
    let mut options = CertificateSigningOptions::new();
    let claims = CwtClaims::new()
        .with_issuer("issuer".to_string())
        .with_subject("subject".to_string())
        .with_audience("audience".to_string())
        .with_expiration_time(12345)
        .with_not_before(67890)
        .with_issued_at(11111);
    
    options.custom_cwt_claims = Some(claims.clone());
    
    let stored_claims = options.custom_cwt_claims.as_ref().unwrap();
    assert_eq!(stored_claims.issuer, Some("issuer".to_string()));
    assert_eq!(stored_claims.subject, Some("subject".to_string()));
    assert_eq!(stored_claims.audience, Some("audience".to_string()));
    assert_eq!(stored_claims.expiration_time, Some(12345));
    assert_eq!(stored_claims.not_before, Some(67890));
    assert_eq!(stored_claims.issued_at, Some(11111));
}

#[test]
fn test_custom_cwt_claims_with_partial_fields() {
    let mut options = CertificateSigningOptions::new();
    let claims = CwtClaims::new()
        .with_issuer("partial-issuer".to_string())
        .with_expiration_time(99999);
    
    options.custom_cwt_claims = Some(claims);
    
    let stored_claims = options.custom_cwt_claims.as_ref().unwrap();
    assert_eq!(stored_claims.issuer, Some("partial-issuer".to_string()));
    assert_eq!(stored_claims.expiration_time, Some(99999));
    assert!(stored_claims.subject.is_none());
    assert!(stored_claims.audience.is_none());
}

#[test]
fn test_scitt_enabled_with_custom_claims() {
    let mut options = CertificateSigningOptions::new();
    options.enable_scitt_compliance = true;
    options.custom_cwt_claims = Some(CwtClaims::new().with_issuer("test".to_string()));
    
    assert_eq!(options.enable_scitt_compliance, true);
    assert!(options.custom_cwt_claims.is_some());
}

#[test]
fn test_scitt_disabled_with_custom_claims() {
    let mut options = CertificateSigningOptions::new();
    options.enable_scitt_compliance = false;
    options.custom_cwt_claims = Some(CwtClaims::new().with_subject("test".to_string()));
    
    assert_eq!(options.enable_scitt_compliance, false);
    assert!(options.custom_cwt_claims.is_some());
}

#[test]
fn test_scitt_disabled_without_custom_claims() {
    let mut options = CertificateSigningOptions::new();
    options.enable_scitt_compliance = false;
    
    assert_eq!(options.enable_scitt_compliance, false);
    assert!(options.custom_cwt_claims.is_none());
}

#[test]
fn test_multiple_option_mutations() {
    let mut options = CertificateSigningOptions::new();
    
    // Mutation 1
    options.enable_scitt_compliance = false;
    assert_eq!(options.enable_scitt_compliance, false);
    
    // Mutation 2
    options.custom_cwt_claims = Some(CwtClaims::new().with_issuer("first".to_string()));
    assert!(options.custom_cwt_claims.is_some());
    
    // Mutation 3
    options.enable_scitt_compliance = true;
    assert_eq!(options.enable_scitt_compliance, true);
    
    // Mutation 4
    options.custom_cwt_claims = Some(CwtClaims::new().with_issuer("second".to_string()));
    assert_eq!(
        options.custom_cwt_claims.as_ref().unwrap().issuer,
        Some("second".to_string())
    );
}

#[test]
fn test_empty_custom_cwt_claims() {
    let mut options = CertificateSigningOptions::new();
    options.custom_cwt_claims = Some(CwtClaims::new());
    
    let claims = options.custom_cwt_claims.as_ref().unwrap();
    assert!(claims.issuer.is_none());
    assert!(claims.subject.is_none());
    assert!(claims.audience.is_none());
    assert!(claims.expiration_time.is_none());
    assert!(claims.not_before.is_none());
    assert!(claims.issued_at.is_none());
}
