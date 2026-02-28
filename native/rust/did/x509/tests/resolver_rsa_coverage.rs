// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for RSA key paths in DidX509Resolver.
//!
//! These tests use openssl to generate RSA and various EC certificates.

use did_x509::resolver::DidX509Resolver;
use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::x509::{X509Builder, X509NameBuilder};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;

/// Generate a self-signed RSA certificate for testing.
fn generate_rsa_cert() -> Vec<u8> {
    // Generate RSA key pair
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    
    // Build certificate
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    
    // Set serial number
    let serial = BigNum::from_u32(1).unwrap();
    builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    
    // Set subject and issuer
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "Test RSA Certificate").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    
    // Set validity
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    
    // Set public key
    builder.set_pubkey(&pkey).unwrap();
    
    // Add Code Signing EKU
    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build().unwrap();
    builder.append_extension(eku).unwrap();
    
    // Sign
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    
    let cert = builder.build();
    cert.to_der().unwrap()
}

#[test]
fn test_resolver_with_rsa_certificate() {
    let cert_der = generate_rsa_cert();
    
    // Build DID using the builder
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy])
        .expect("Should build DID from RSA cert");
    
    // Resolve DID to document
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der]);
    
    assert!(result.is_ok(), "Resolution should succeed: {:?}", result.err());
    let doc = result.unwrap();
    
    // Verify RSA JWK structure
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").unwrap(), "RSA", "Key type should be RSA");
    assert!(jwk.contains_key("n"), "RSA JWK should have modulus 'n'");
    assert!(jwk.contains_key("e"), "RSA JWK should have exponent 'e'");
    
    // Verify document structure
    assert_eq!(doc.id, did_string);
    assert_eq!(doc.verification_method.len(), 1);
    assert_eq!(doc.verification_method[0].type_, "JsonWebKey2020");
}

#[test]
fn test_resolver_rsa_jwk_base64url_encoding() {
    let cert_der = generate_rsa_cert();
    
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let doc = DidX509Resolver::resolve(&did_string, &[&cert_der]).unwrap();
    
    let jwk = &doc.verification_method[0].public_key_jwk;
    
    // Verify RSA parameters are properly base64url encoded
    let n = jwk.get("n").expect("Should have modulus");
    let e = jwk.get("e").expect("Should have exponent");
    
    // Base64url should not contain standard base64 chars or padding
    assert!(!n.contains('='), "modulus should not have padding");
    assert!(!n.contains('+'), "modulus should not contain '+'");
    assert!(!n.contains('/'), "modulus should not contain '/'");
    
    assert!(!e.contains('='), "exponent should not have padding");
    assert!(!e.contains('+'), "exponent should not contain '+'");
    assert!(!e.contains('/'), "exponent should not contain '/'");
}

#[test]
fn test_resolver_validation_fails_with_mismatched_chain() {
    // Generate two different RSA certificates
    let cert1 = generate_rsa_cert();
    let cert2 = generate_rsa_cert();
    
    // Build DID for cert2
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_for_cert2 = DidX509Builder::build_sha256(&cert2, &[policy]).unwrap();
    
    // Try to resolve with cert1 (wrong chain)
    let result = DidX509Resolver::resolve(&did_for_cert2, &[&cert1]);
    
    // Should fail because fingerprint doesn't match
    assert!(result.is_err(), "Should fail with mismatched chain");
}

/// Generate a P-384 EC certificate for testing.
fn generate_p384_cert() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    
    let serial = BigNum::from_u32(3).unwrap();
    builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "Test P-384 Certificate").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    
    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build().unwrap();
    builder.append_extension(eku).unwrap();
    
    builder.sign(&pkey, MessageDigest::sha384()).unwrap();
    builder.build().to_der().unwrap()
}

/// Generate a P-521 EC certificate for testing.
fn generate_p521_cert() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    
    let serial = BigNum::from_u32(4).unwrap();
    builder.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", "Test P-521 Certificate").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    
    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build().unwrap();
    builder.append_extension(eku).unwrap();
    
    builder.sign(&pkey, MessageDigest::sha512()).unwrap();
    builder.build().to_der().unwrap()
}

#[test]
fn test_resolver_with_p384_certificate() {
    let cert_der = generate_p384_cert();
    
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy])
        .expect("Should build DID from P-384 cert");
    
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der]);
    
    assert!(result.is_ok(), "Resolution should succeed: {:?}", result.err());
    let doc = result.unwrap();
    
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").unwrap(), "EC", "Key type should be EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-384", "Curve should be P-384");
    assert!(jwk.contains_key("x"), "EC JWK should have x coordinate");
    assert!(jwk.contains_key("y"), "EC JWK should have y coordinate");
}

#[test]
fn test_resolver_with_p521_certificate() {
    let cert_der = generate_p521_cert();
    
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy])
        .expect("Should build DID from P-521 cert");
    
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der]);
    
    assert!(result.is_ok(), "Resolution should succeed: {:?}", result.err());
    let doc = result.unwrap();
    
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").unwrap(), "EC", "Key type should be EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-521", "Curve should be P-521");
    assert!(jwk.contains_key("x"), "EC JWK should have x coordinate");
    assert!(jwk.contains_key("y"), "EC JWK should have y coordinate");
}
