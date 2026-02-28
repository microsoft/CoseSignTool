// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for DID:x509 library to achieve 90% line coverage.
//!
//! These tests focus on:
//! 1. resolver.rs - EC JWK conversion paths, edge cases
//! 2. x509_extensions.rs - EKU extraction, CA detection
//! 3. Base64 encoding edge cases

use did_x509::resolver::DidX509Resolver;
use did_x509::x509_extensions::{
    extract_extended_key_usage, extract_eku_oids, is_ca_certificate, extract_fulcio_issuer
};
use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use did_x509::error::DidX509Error;
use rcgen::{
    CertificateParams, DnType, KeyPair, ExtendedKeyUsagePurpose, 
    IsCa, BasicConstraints as RcgenBasicConstraints, SanType as RcgenSanType, Ia5String
};
use x509_parser::prelude::*;

/// Generate an EC certificate with code signing EKU
fn generate_ec_cert_with_eku(ekus: Vec<ExtendedKeyUsagePurpose>) -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test Certificate");
    params.extended_key_usages = ekus;
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate a CA certificate with BasicConstraints(CA:true)
fn generate_ca_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test CA Certificate");
    params.is_ca = IsCa::Ca(RcgenBasicConstraints::Unconstrained);
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate a non-CA certificate
fn generate_non_ca_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test Non-CA Certificate");
    params.is_ca = IsCa::NoCa;
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate a certificate with multiple EKU extensions
fn generate_multi_eku_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Multi EKU Certificate");
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::EmailProtection,
        ExtendedKeyUsagePurpose::TimeStamping,
        ExtendedKeyUsagePurpose::OcspSigning,
    ];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with no extensions
fn generate_plain_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Plain Certificate");
    // No extended_key_usages, no is_ca, no SAN
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

// ============================================================================
// Resolver tests - covering EC JWK conversion and base64url encoding
// ============================================================================

#[test]
fn test_resolver_ec_p256_jwk() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    
    let result = DidX509Resolver::resolve(&did, &[&cert_der]);
    assert!(result.is_ok(), "Should resolve EC P-256 cert: {:?}", result.err());
    
    let doc = result.unwrap();
    let jwk = &doc.verification_method[0].public_key_jwk;
    
    // Verify EC JWK structure
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-256");
    assert!(jwk.contains_key("x"));
    assert!(jwk.contains_key("y"));
}

#[test]
fn test_resolver_did_document_structure() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    
    let result = DidX509Resolver::resolve(&did, &[&cert_der]).unwrap();
    
    // Verify DID Document structure
    assert_eq!(result.id, did);
    assert!(!result.context.is_empty());
    assert!(result.context.contains(&"https://www.w3.org/ns/did/v1".to_string()));
    assert_eq!(result.verification_method.len(), 1);
    assert_eq!(result.assertion_method.len(), 1);
    
    // Verify verification method structure
    let vm = &result.verification_method[0];
    assert!(vm.id.starts_with(&did));
    assert!(vm.id.ends_with("#key-1"));
    assert_eq!(vm.type_, "JsonWebKey2020");
    assert_eq!(vm.controller, did);
}

#[test]
fn test_resolver_validation_failure() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::ServerAuth]);
    // Create DID requiring Code Signing EKU, but cert only has Server Auth
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]); // Code Signing
    
    // Use a correct fingerprint but wrong policy
    use sha2::{Sha256, Digest};
    let fingerprint = Sha256::digest(&cert_der);
    let fingerprint_hex = hex::encode(fingerprint);
    let did = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", fingerprint_hex);
    
    let result = DidX509Resolver::resolve(&did, &[&cert_der]);
    assert!(result.is_err(), "Should fail - cert doesn't have required EKU");
}

// ============================================================================
// x509_extensions tests - covering all standard EKU OIDs
// ============================================================================

#[test]
fn test_extract_all_standard_ekus() {
    let cert_der = generate_multi_eku_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let ekus = extract_extended_key_usage(&cert);
    
    // Should contain all 6 standard EKU OIDs
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.1".to_string()), "Missing ServerAuth");
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.2".to_string()), "Missing ClientAuth");
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.3".to_string()), "Missing CodeSigning");
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.4".to_string()), "Missing EmailProtection");
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.8".to_string()), "Missing TimeStamping");
    assert!(ekus.contains(&"1.3.6.1.5.5.7.3.9".to_string()), "Missing OcspSigning");
}

#[test]
fn test_extract_single_eku_code_signing() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let ekus = extract_extended_key_usage(&cert);
    assert_eq!(ekus.len(), 1);
    assert_eq!(ekus[0], "1.3.6.1.5.5.7.3.3");
}

#[test]
fn test_extract_eku_oids_wrapper_success() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::ServerAuth]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let result = extract_eku_oids(&cert);
    assert!(result.is_ok());
    
    let oids = result.unwrap();
    assert!(oids.contains(&"1.3.6.1.5.5.7.3.1".to_string()));
}

#[test]
fn test_extract_eku_no_extension() {
    let cert_der = generate_plain_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let ekus = extract_extended_key_usage(&cert);
    assert!(ekus.is_empty(), "Cert without EKU extension should return empty vec");
    
    let result = extract_eku_oids(&cert);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ============================================================================
// CA certificate detection tests
// ============================================================================

#[test]
fn test_is_ca_certificate_true() {
    let cert_der = generate_ca_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let is_ca = is_ca_certificate(&cert);
    assert!(is_ca, "CA certificate should be detected as CA");
}

#[test]
fn test_is_ca_certificate_false() {
    let cert_der = generate_non_ca_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let is_ca = is_ca_certificate(&cert);
    assert!(!is_ca, "Non-CA certificate should not be detected as CA");
}

#[test]
fn test_is_ca_certificate_no_basic_constraints() {
    // Plain cert has no basic constraints extension at all
    let cert_der = generate_plain_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let is_ca = is_ca_certificate(&cert);
    assert!(!is_ca, "Cert without BasicConstraints should not be CA");
}

// ============================================================================
// Fulcio issuer extraction tests
// ============================================================================

#[test]
fn test_extract_fulcio_issuer_none() {
    let cert_der = generate_plain_cert();
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let issuer = extract_fulcio_issuer(&cert);
    assert!(issuer.is_none(), "Regular cert should not have Fulcio issuer");
}

#[test]
fn test_extract_fulcio_issuer_not_present() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let (_, cert) = X509Certificate::from_der(&cert_der).unwrap();
    
    let issuer = extract_fulcio_issuer(&cert);
    assert!(issuer.is_none());
}

// ============================================================================
// Base64url encoding edge cases (via resolver)
// ============================================================================

#[test]
fn test_base64url_no_padding() {
    let cert_der = generate_ec_cert_with_eku(vec![ExtendedKeyUsagePurpose::CodeSigning]);
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    
    let doc = DidX509Resolver::resolve(&did, &[&cert_der]).unwrap();
    let jwk = &doc.verification_method[0].public_key_jwk;
    
    // base64url encoding should NOT have padding characters
    let x = jwk.get("x").unwrap();
    let y = jwk.get("y").unwrap();
    
    assert!(!x.contains('='), "x should not have padding");
    assert!(!y.contains('='), "y should not have padding");
    assert!(!x.contains('+'), "x should use URL-safe alphabet");
    assert!(!y.contains('+'), "y should use URL-safe alphabet");
    assert!(!x.contains('/'), "x should use URL-safe alphabet");
    assert!(!y.contains('/'), "y should use URL-safe alphabet");
}

// ============================================================================
// Error path coverage
// ============================================================================

#[test]
fn test_resolver_empty_chain() {
    let did = "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::eku:1.3.6.1.5.5.7.3.3";
    
    let result = DidX509Resolver::resolve(did, &[]);
    assert!(result.is_err(), "Should fail with empty chain");
}

#[test]
fn test_resolver_invalid_did_format() {
    let cert_der = generate_plain_cert();
    let invalid_did = "not:a:valid:did";
    
    let result = DidX509Resolver::resolve(invalid_did, &[&cert_der]);
    assert!(result.is_err(), "Should fail with invalid DID format");
}
