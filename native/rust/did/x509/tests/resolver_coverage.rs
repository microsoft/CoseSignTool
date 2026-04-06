// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for DidX509Resolver to cover uncovered lines in resolver.rs.
//!
//! These tests target specific uncovered paths in the resolver implementation.

use did_x509::error::DidX509Error;
use did_x509::resolver::DidX509Resolver;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair};
use std::borrow::Cow;

/// Generate a self-signed X.509 certificate with EC key for testing JWK conversion.
fn generate_ec_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test EC Certificate");

    // Add Extended Key Usage for Code Signing
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    // Use EC key (rcgen defaults to P-256)
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();

    cert.der().to_vec()
}

/// Generate an invalid certificate chain for testing error paths.
fn generate_invalid_cert() -> Vec<u8> {
    vec![0x30, 0x82, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF] // Invalid DER
}

#[test]
fn test_resolver_with_valid_ec_chain() {
    // Generate EC certificate (rcgen uses P-256 by default)
    let cert_der = generate_ec_cert();

    // Use the builder to create the DID (proper fingerprint calculation)
    use did_x509::builder::DidX509Builder;
    use did_x509::models::policy::DidX509Policy;

    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string().into()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).expect("Should build DID");

    // Resolve DID to document
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der]);

    // Verify success and EC JWK structure
    assert!(
        result.is_ok(),
        "Resolution should succeed: {:?}",
        result.err()
    );
    let doc = result.unwrap();

    assert_eq!(doc.id, did_string);
    assert_eq!(doc.verification_method.len(), 1);

    // Verify EC JWK fields are present
    let jwk = &doc.verification_method[0].public_key_jwk;
    assert_eq!(jwk.get("kty").unwrap(), "EC");
    assert_eq!(jwk.get("crv").unwrap(), "P-256"); // rcgen default
    assert!(jwk.contains_key("x")); // x coordinate
    assert!(jwk.contains_key("y")); // y coordinate
}

#[test]
fn test_resolver_chain_mismatch() {
    // Generate one certificate
    let cert_der1 = generate_ec_cert();

    // Calculate fingerprint for a different certificate
    let cert_der2 = generate_ec_cert();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&cert_der2);
    let fingerprint = hasher.finalize();
    let fingerprint_hex = hex::encode(&fingerprint[..]);

    // Build DID for cert2 but validate against cert1
    let did_string = format!(
        "did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3",
        fingerprint_hex
    );

    // Try to resolve with mismatched chain
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der1]);

    // Should fail due to validation failure
    assert!(
        result.is_err(),
        "Resolution should fail with mismatched chain"
    );

    let error = result.unwrap_err();
    match error {
        DidX509Error::PolicyValidationFailed(_)
        | DidX509Error::FingerprintLengthMismatch(_, _, _)
        | DidX509Error::ValidationFailed(_) => {
            // Any of these errors indicate the chain doesn't match the DID
        }
        _ => panic!("Expected validation failure, got {:?}", error),
    }
}

#[test]
fn test_resolver_invalid_certificate_parsing() {
    // Use invalid certificate data
    let invalid_cert = generate_invalid_cert();
    let fingerprint_hex = hex::encode(&[0x00; 32]); // dummy fingerprint

    // Build a DID string
    let did_string = format!(
        "did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3",
        fingerprint_hex
    );

    // Try to resolve with invalid certificate
    let result = DidX509Resolver::resolve(&did_string, &[&invalid_cert]);

    // Should fail due to certificate parsing error or validation error
    assert!(
        result.is_err(),
        "Resolution should fail with invalid certificate"
    );
}

#[test]
fn test_resolver_mismatched_fingerprint() {
    // Generate a certificate
    let cert_der = generate_ec_cert();

    // Use a wrong fingerprint hex (not matching the certificate)
    let wrong_fingerprint_hex = hex::encode(&[0xFF; 32]);
    let wrong_did_string = format!(
        "did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3",
        wrong_fingerprint_hex
    );

    let result = DidX509Resolver::resolve(&wrong_did_string, &[&cert_der]);
    assert!(result.is_err(), "Should fail with fingerprint mismatch");
}

// Test base64url encoding coverage by testing different certificate types
#[test]
fn test_resolver_jwk_base64url_encoding() {
    let cert_der = generate_ec_cert();

    // Use the builder to create the DID (proper fingerprint calculation)
    use did_x509::builder::DidX509Builder;
    use did_x509::models::policy::DidX509Policy;

    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string().into()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).expect("Should build DID");
    let result = DidX509Resolver::resolve(&did_string, &[&cert_der]);

    assert!(result.is_ok(), "Resolution should succeed");
    let doc = result.unwrap();
    let jwk = &doc.verification_method[0].public_key_jwk;

    // Verify EC coordinates are base64url encoded (no padding, no +/=)
    if let (Some(x), Some(y)) = (jwk.get("x"), jwk.get("y")) {
        assert!(!x.is_empty(), "x coordinate should not be empty");
        assert!(!y.is_empty(), "y coordinate should not be empty");

        // Should not contain standard base64 chars or padding
        assert!(!x.contains('='), "base64url should not contain padding");
        assert!(!x.contains('+'), "base64url should not contain '+'");
        assert!(!x.contains('/'), "base64url should not contain '/'");

        assert!(!y.contains('='), "base64url should not contain padding");
        assert!(!y.contains('+'), "base64url should not contain '+'");
        assert!(!y.contains('/'), "base64url should not contain '/'");
    }
}
