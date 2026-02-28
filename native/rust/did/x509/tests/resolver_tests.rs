// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::*;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedKey, 
    DnType, IsCa, KeyPair,
};
use sha2::{Sha256, Digest};

// Inline base64url utilities for tests
const BASE64_URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    let mut i = 0;
    while i + 2 < input.len() {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8 | input[i + 2] as u32;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        out.push(alphabet[(n & 0x3F) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        if pad { out.push_str("=="); }
    } else if rem == 2 {
        let n = (input[i] as u32) << 16 | (input[i + 1] as u32) << 8;
        out.push(alphabet[((n >> 18) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3F) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3F) as usize] as char);
        if pad { out.push('='); }
    }
    out
}

fn base64url_encode(input: &[u8]) -> String {
    base64_encode(input, BASE64_URL_SAFE, false)
}

/// Generate a simple CA certificate (default key type, typically EC)
fn generate_ca_cert() -> (Vec<u8>, CertifiedKey) {
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
    ca_params.distinguished_name.push(DnType::OrganizationName, "Test Org");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_der = ca_cert.der().to_vec();
    
    (ca_der, CertifiedKey { cert: ca_cert, key_pair: ca_key })
}

/// Generate a leaf certificate signed by CA
fn generate_leaf_cert(ca: &CertifiedKey, cn: &str) -> Vec<u8> {
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name.push(DnType::CommonName, cn);
    leaf_params.distinguished_name.push(DnType::OrganizationName, "Test Org");
    
    let leaf_key = KeyPair::generate().unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca.cert, &ca.key_pair).unwrap();
    
    leaf_cert.der().to_vec()
}

/// Generate a leaf certificate with explicit P-256 EC key
fn generate_leaf_cert_ec_p256(ca: &CertifiedKey, cn: &str) -> Vec<u8> {
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name.push(DnType::CommonName, cn);
    leaf_params.distinguished_name.push(DnType::OrganizationName, "Test Org");
    
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca.cert, &ca.key_pair).unwrap();
    
    leaf_cert.der().to_vec()
}

/// Build a DID:x509 for the given CA certificate
fn build_did_for_ca(ca_cert_der: &[u8], cn: &str) -> String {
    let fingerprint = Sha256::digest(ca_cert_der);
    let fingerprint_b64 = base64url_encode(&fingerprint);
    
    format!(
        "did:x509:0:sha256:{}::subject:CN:{}",
        fingerprint_b64,
        cn
    )
}

#[test]
fn test_resolve_valid_did() {
    // Generate CA and leaf certificates (default algorithm, typically EC)
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert(&ca, "Test Leaf");
    
    // Build DID
    let did = build_did_for_ca(&ca_cert_der, "Test Leaf");
    
    // Resolve
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let result = DidX509Resolver::resolve(&did, &chain);
    
    assert!(result.is_ok(), "Resolution failed: {:?}", result.err());
    let doc = result.unwrap();
    
    // Verify DID Document structure
    assert_eq!(doc.id, did);
    assert_eq!(doc.context, vec!["https://www.w3.org/ns/did/v1"]);
    assert_eq!(doc.verification_method.len(), 1);
    assert_eq!(doc.assertion_method.len(), 1);
    
    // Verify verification method
    let vm = &doc.verification_method[0];
    assert_eq!(vm.id, format!("{}#key-1", did));
    assert_eq!(vm.type_, "JsonWebKey2020");
    assert_eq!(vm.controller, did);
    
    // Verify JWK has key type field
    assert!(vm.public_key_jwk.contains_key("kty"));
}

#[test]
fn test_resolve_valid_did_with_ec_p256() {
    // Generate CA and leaf certificates with explicit P-256
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert_ec_p256(&ca, "Test EC Leaf");
    
    // Build DID
    let did = build_did_for_ca(&ca_cert_der, "Test EC Leaf");
    
    // Resolve
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let result = DidX509Resolver::resolve(&did, &chain);
    
    assert!(result.is_ok());
    let doc = result.unwrap();
    
    // Verify DID Document structure
    assert_eq!(doc.id, did);
    assert_eq!(doc.verification_method.len(), 1);
    
    // Verify JWK has EC fields
    let vm = &doc.verification_method[0];
    assert_eq!(vm.public_key_jwk.get("kty"), Some(&"EC".to_string()));
    assert!(vm.public_key_jwk.contains_key("crv"));
    assert!(vm.public_key_jwk.contains_key("x"));
    assert!(vm.public_key_jwk.contains_key("y"));
    
    // Verify curve is P-256
    let crv = vm.public_key_jwk.get("crv").unwrap();
    assert_eq!(crv, "P-256");
}

#[test]
fn test_resolve_with_invalid_chain() {
    let did = "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::subject:CN:Test";
    
    // Empty chain should fail
    let chain: Vec<&[u8]> = vec![];
    let result = DidX509Resolver::resolve(did, &chain);
    
    assert!(result.is_err());
}

#[test]
fn test_resolve_with_validation_failure() {
    // Generate CA and leaf with mismatched CN
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert(&ca, "Wrong CN");
    
    // Build DID expecting different CN
    let did = build_did_for_ca(&ca_cert_der, "Expected CN");
    
    // Should fail validation
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let result = DidX509Resolver::resolve(&did, &chain);
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DidX509Error::PolicyValidationFailed(_)));
}

#[test]
fn test_did_document_context() {
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert(&ca, "Test");
    let did = build_did_for_ca(&ca_cert_der, "Test");
    
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    
    // Verify W3C DID v1 context
    assert_eq!(doc.context, vec!["https://www.w3.org/ns/did/v1"]);
}

#[test]
fn test_assertion_method_references_verification_method() {
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert(&ca, "Test");
    let did = build_did_for_ca(&ca_cert_der, "Test");
    
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    
    // Assertion method should reference the verification method
    assert_eq!(doc.assertion_method.len(), 1);
    assert_eq!(doc.assertion_method[0], doc.verification_method[0].id);
}

#[test]
fn test_did_document_json_serialization() {
    let (ca_cert_der, ca) = generate_ca_cert();
    let leaf_cert_der = generate_leaf_cert(&ca, "Test");
    let did = build_did_for_ca(&ca_cert_der, "Test");
    
    let chain: Vec<&[u8]> = vec![&leaf_cert_der, &ca_cert_der];
    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    
    // Test JSON serialization
    let json = doc.to_json(false).unwrap();
    assert!(json.contains("@context"));
    assert!(json.contains("verificationMethod"));
    assert!(json.contains("assertionMethod"));
    assert!(json.contains("publicKeyJwk"));
    
    // Test indented JSON
    let json_indented = doc.to_json(true).unwrap();
    assert!(json_indented.contains('\n'));
}

#[test]
fn test_verification_method_contains_jwk_fields() {
    let (ca_cert_der, ca) = generate_ca_cert();
    
    // Test with default key (typically EC)
    let leaf_der = generate_leaf_cert(&ca, "Test Default");
    let did = build_did_for_ca(&ca_cert_der, "Test Default");
    let chain: Vec<&[u8]> = vec![&leaf_der, &ca_cert_der];
    let doc = DidX509Resolver::resolve(&did, &chain).unwrap();
    
    // Should have kty field at minimum
    assert!(doc.verification_method[0].public_key_jwk.contains_key("kty"));
    
    // Test with explicit P-256 EC key
    let leaf_ec_der = generate_leaf_cert_ec_p256(&ca, "Test EC");
    let did_ec = build_did_for_ca(&ca_cert_der, "Test EC");
    let chain_ec: Vec<&[u8]> = vec![&leaf_ec_der, &ca_cert_der];
    let doc_ec = DidX509Resolver::resolve(&did_ec, &chain_ec).unwrap();
    assert_eq!(doc_ec.verification_method[0].public_key_jwk.get("kty"), Some(&"EC".to_string()));
}
