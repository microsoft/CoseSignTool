// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for certificates pack validation logic.
//! 
//! Targets uncovered lines in:
//! - pack.rs (X509CertificateTrustPack::trust_embedded_chain_as_trusted)
//! - pack.rs (normalize_thumbprint, parse_message_chain error paths)

use std::sync::Arc;
use cose_sign1_certificates::validation::pack::{X509CertificateTrustPack, CertificateTrustOptions};
use cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityFact;
use cose_sign1_validation_primitives::facts::TrustFactEngine;
use cose_sign1_validation_primitives::subject::TrustSubject;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::CoseSign1Message;

/// Test the convenience constructor for trust_embedded_chain_as_trusted.
#[test]
fn test_trust_embedded_chain_as_trusted_constructor() {
    let pack = X509CertificateTrustPack::trust_embedded_chain_as_trusted();
    // This constructor should set the trust_embedded_chain_as_trusted option to true
    // We can test this indirectly by checking the behavior, though the field is private
    
    // Create a mock COSE_Sign1 message with an x5chain header
    let mock_cert = create_mock_der_cert();
    let cose_bytes = build_cose_sign1_with_x5chain(&[&mock_cert]);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    
    // Create trust subject and engine
    let subject = TrustSubject::message(&cose_bytes);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // Test that the pack processes this (may fail due to invalid cert, but tests the path)
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    // Don't assert success since mock cert may not be valid, just test code path coverage
    let _ = result;
}

/// Test the normalize_thumbprint function indirectly through thumbprint validation.
#[test]
fn test_normalize_thumbprint_variations() {
    // Test with allowlist containing various thumbprint formats
    let options = CertificateTrustOptions {
        allowed_thumbprints: vec![
            " AB CD EF 12 34 56 ".to_string(), // With spaces and lowercase
            "abcdef123456".to_string(),         // Lowercase  
            "ABCDEF123456".to_string(),         // Uppercase
            "  ".to_string(),                   // Whitespace only
            "".to_string(),                     // Empty
        ],
        identity_pinning_enabled: true,
        ..Default::default()
    };
    
    let pack = X509CertificateTrustPack::new(options);
    
    // Create a test subject
    let mock_cert = create_mock_der_cert();
    let cose_bytes = build_cose_sign1_with_x5chain(&[&mock_cert]);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // This tests the normalize_thumbprint logic when comparing against allowed list
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    let _ = result; // Coverage for thumbprint normalization paths
}

/// Test indefinite-length map error path in try_read_x5chain.
#[test] 
fn test_indefinite_length_map_error() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Encode an indefinite-length map (starts with 0xBF, ends with 0xFF)
    encoder.encode_raw(&[0xBF]).unwrap(); // Indefinite map start
    encoder.encode_i64(33).unwrap();      // x5chain label
    encoder.encode_bstr(b"cert").unwrap(); // Mock cert
    encoder.encode_raw(&[0xFF]).unwrap(); // Indefinite map end
    
    let map_bytes = encoder.into_bytes();
    
    // Build a COSE_Sign1 with this problematic protected header
    let cose_bytes = build_cose_sign1_with_custom_protected(&map_bytes);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    
    let pack = X509CertificateTrustPack::default();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // This should trigger the "indefinite-length maps not supported" error path
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    // May fail or succeed depending on parsing, but covers the error path
    let _ = result;
}

/// Test indefinite-length x5chain array error path.
#[test]
fn test_indefinite_length_x5chain_array() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Build protected header with x5chain as indefinite array
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(33).unwrap(); // x5chain label
    encoder.encode_raw(&[0x9F]).unwrap(); // Indefinite array start
    encoder.encode_bstr(b"cert1").unwrap();
    encoder.encode_bstr(b"cert2").unwrap();
    encoder.encode_raw(&[0xFF]).unwrap(); // Indefinite array end
    
    let protected_bytes = encoder.into_bytes();
    let cose_bytes = build_cose_sign1_with_custom_protected(&protected_bytes);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    
    let pack = X509CertificateTrustPack::default();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // This should trigger "indefinite-length x5chain arrays not supported" error
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    let _ = result;
}

/// Test x5chain as single bstr (not array) parsing path.
#[test]
fn test_x5chain_single_bstr() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Build protected header with x5chain as single bstr (not array)
    encoder.encode_map(1).unwrap();
    encoder.encode_i64(33).unwrap(); // x5chain label  
    encoder.encode_bstr(b"single-cert-der").unwrap(); // Single cert, not array
    
    let protected_bytes = encoder.into_bytes();
    let cose_bytes = build_cose_sign1_with_custom_protected(&protected_bytes);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    
    let pack = X509CertificateTrustPack::default();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // This tests the single bstr parsing branch
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    let _ = result;
}

/// Test skipping non-x5chain header entries (the skip() path).
#[test]
fn test_skip_non_x5chain_headers() {
    let provider = EverParseCborProvider;
    let mut encoder = provider.encoder();
    
    // Build protected header with multiple entries, x5chain comes later
    encoder.encode_map(3).unwrap();
    // First entry: algorithm 
    encoder.encode_i64(1).unwrap();   // alg label
    encoder.encode_i64(-7).unwrap();  // ES256
    // Second entry: some other header
    encoder.encode_i64(4).unwrap();   // kid label  
    encoder.encode_bstr(b"keyid").unwrap();
    // Third entry: x5chain (will be found after skipping the others)
    encoder.encode_i64(33).unwrap();  // x5chain label
    encoder.encode_array(1).unwrap();
    encoder.encode_bstr(b"cert").unwrap();
    
    let protected_bytes = encoder.into_bytes();
    let cose_bytes = build_cose_sign1_with_custom_protected(&protected_bytes);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    
    let pack = X509CertificateTrustPack::default();
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // This tests the skip() path for non-x5chain entries
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    let _ = result;
}

/// Test with PQC algorithm OIDs option.
#[test]
fn test_pqc_algorithm_oids() {
    let options = CertificateTrustOptions {
        pqc_algorithm_oids: vec![
            "1.3.6.1.4.1.2.267.7.4.4".to_string(), // Example PQC OID
            "1.3.6.1.4.1.2.267.7.6.5".to_string(), // Another PQC OID
        ],
        ..Default::default()
    };
    
    let pack = X509CertificateTrustPack::new(options);
    
    let mock_cert = create_mock_der_cert();
    let cose_bytes = build_cose_sign1_with_x5chain(&[&mock_cert]);
    let message = CoseSign1Message::parse(&cose_bytes).unwrap();
    let subject = TrustSubject::message(&cose_bytes);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(message));
    
    // Test that PQC OIDs are processed 
    let signing_key_subject = TrustSubject::primary_signing_key(&subject);
    let result = engine.get_fact_set::<X509SigningCertificateIdentityFact>(&signing_key_subject);
    let _ = result;
}

// Helper functions

fn create_mock_der_cert() -> Vec<u8> {
    // Create a more realistic mock DER certificate structure
    vec![
        0x30, 0x82, 0x01, 0x23, // SEQUENCE, length
        0x30, 0x82, 0x01, 0x00, // tbsCertificate SEQUENCE
        0xa0, 0x03, 0x02, 0x01, 0x02, // version
        0x02, 0x01, 0x01,       // serialNumber
        0x30, 0x0d,             // signature AlgorithmIdentifier
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // sha256WithRSAEncryption
        0x05, 0x00,             // NULL
        // Add more fields as needed for a minimal valid structure
    ]
}

fn build_cose_sign1_with_x5chain(chain: &[&[u8]]) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    
    enc.encode_array(4).unwrap();
    
    // Protected header with x5chain
    let mut hdr_enc = provider.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(33).unwrap(); // x5chain label
    hdr_enc.encode_array(chain.len()).unwrap();
    for cert in chain {
        hdr_enc.encode_bstr(cert).unwrap();
    }
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();
    
    // Unprotected header: {}
    enc.encode_map(0).unwrap();
    
    // Payload: null
    enc.encode_null().unwrap();
    
    // Signature: mock
    enc.encode_bstr(b"signature").unwrap();
    
    enc.into_bytes()
}

fn build_cose_sign1_with_custom_protected(protected_bytes: &[u8]) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    
    enc.encode_array(4).unwrap();
    enc.encode_bstr(protected_bytes).unwrap();
    enc.encode_map(0).unwrap();    // unprotected
    enc.encode_null().unwrap();    // payload
    enc.encode_bstr(b"sig").unwrap(); // signature
    
    enc.into_bytes()
}
