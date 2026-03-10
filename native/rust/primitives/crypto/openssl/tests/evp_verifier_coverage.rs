// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for EvpVerifier - basic, streaming, and edge cases.

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier};
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier, VerifyingContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Test helper to generate EC P-256 keypair
fn generate_ec_p256_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Test helper to generate RSA 2048 keypair
fn generate_rsa_2048_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Test helper to generate Ed25519 keypair
fn generate_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let private_key = PKey::generate_ed25519().unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Helper to create a signer and sign some data
fn sign_data(private_der: &[u8], algorithm: i64, data: &[u8]) -> Vec<u8> {
    let signer = EvpSigner::from_der(private_der, algorithm).unwrap();
    signer.sign(data).unwrap()
}

#[test]
fn test_evp_verifier_from_der_ec_p256() {
    let (_, public_der) = generate_ec_p256_key();

    let verifier = EvpVerifier::from_der(&public_der, -7); // ES256
    assert!(verifier.is_ok());

    let verifier = verifier.unwrap();
    assert_eq!(verifier.algorithm(), -7);
}

#[test]
fn test_evp_verifier_from_der_rsa() {
    let (_, public_der) = generate_rsa_2048_key();

    let verifier = EvpVerifier::from_der(&public_der, -257); // RS256
    assert!(verifier.is_ok());

    let verifier = verifier.unwrap();
    assert_eq!(verifier.algorithm(), -257);
}

#[test]
fn test_evp_verifier_from_der_ed25519() {
    let (_, public_der) = generate_ed25519_key();

    let verifier = EvpVerifier::from_der(&public_der, -8); // EdDSA
    assert!(verifier.is_ok());

    let verifier = verifier.unwrap();
    assert_eq!(verifier.algorithm(), -8);
}

#[test]
fn test_evp_verifier_from_invalid_der() {
    let invalid_der = vec![0xFF, 0xFE, 0xFD, 0xFC];

    let result = EvpVerifier::from_der(&invalid_der, -7);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CryptoError::InvalidKey(_)));
    }
}

#[test]
fn test_evp_verifier_from_empty_der() {
    let empty_der: Vec<u8> = vec![];

    let result = EvpVerifier::from_der(&empty_der, -7);
    assert!(result.is_err());
}

#[test]
fn test_evp_verifier_valid_signature_ec_p256() {
    let (private_der, public_der) = generate_ec_p256_key();
    let data = b"test data for verification";

    let signature = sign_data(&private_der, -7, data);
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let result = verifier.verify(data, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evp_verifier_valid_signature_rsa() {
    let (private_der, public_der) = generate_rsa_2048_key();
    let data = b"RSA test data for verification";

    let signature = sign_data(&private_der, -257, data); // RS256
    let verifier = EvpVerifier::from_der(&public_der, -257).unwrap();

    let result = verifier.verify(data, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evp_verifier_valid_signature_ed25519() {
    let (private_der, public_der) = generate_ed25519_key();
    let data = b"Ed25519 test data";

    let signature = sign_data(&private_der, -8, data); // EdDSA
    let verifier = EvpVerifier::from_der(&public_der, -8).unwrap();

    let result = verifier.verify(data, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evp_verifier_wrong_data() {
    let (private_der, public_der) = generate_ec_p256_key();
    let original_data = b"original data";
    let wrong_data = b"wrong data";

    let signature = sign_data(&private_der, -7, original_data);
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let result = verifier.verify(wrong_data, &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Verification should fail
}

#[test]
fn test_evp_verifier_cross_key_verification() {
    let (private_der1, _) = generate_ec_p256_key();
    let (_, public_der2) = generate_ec_p256_key(); // Different key pair

    let data = b"cross key test";
    let signature = sign_data(&private_der1, -7, data);
    let verifier = EvpVerifier::from_der(&public_der2, -7).unwrap(); // Wrong public key

    let result = verifier.verify(data, &signature);
    assert!(result.is_ok());
    assert!(!result.unwrap()); // Should fail - wrong key
}

#[test]
fn test_evp_verifier_empty_data() {
    let (private_der, public_der) = generate_ec_p256_key();
    let empty_data = b"";

    let signature = sign_data(&private_der, -7, empty_data);
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let result = verifier.verify(empty_data, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evp_verifier_large_data() {
    let (private_der, public_der) = generate_ec_p256_key();
    let large_data = vec![0x42u8; 100000]; // 100KB

    let signature = sign_data(&private_der, -7, &large_data);
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let result = verifier.verify(&large_data, &signature);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn test_evp_verifier_supports_streaming() {
    let (_, public_der) = generate_ec_p256_key();
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    assert!(verifier.supports_streaming());
}

#[test]
fn test_evp_verifier_streaming_context() {
    let (private_der, public_der) = generate_ec_p256_key();
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let data = b"streaming verification test";
    let signature = sign_data(&private_der, -7, data);

    let mut verify_context = verifier.verify_init(&signature).unwrap();
    verify_context.update(data).unwrap();
    let result = verify_context.finalize().unwrap();

    assert!(result);
}

#[test]
fn test_evp_verifier_streaming_chunked() {
    let (private_der, public_der) = generate_ec_p256_key();
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let full_data = b"abcdefghijklmnopqrstuvwxyz";
    let signature = sign_data(&private_der, -7, full_data);

    let mut verify_context = verifier.verify_init(&signature).unwrap();
    verify_context.update(b"abcde").unwrap();
    verify_context.update(b"fghijk").unwrap();
    verify_context.update(b"lmnopqrstuvwxyz").unwrap();
    let result = verify_context.finalize().unwrap();

    assert!(result);
}

#[test]
fn test_evp_verifier_streaming_empty_updates() {
    let (private_der, public_der) = generate_ec_p256_key();
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let data = b"test with empty updates";
    let signature = sign_data(&private_der, -7, data);

    let mut verify_context = verifier.verify_init(&signature).unwrap();
    verify_context.update(b"").unwrap(); // Empty update
    verify_context.update(data).unwrap();
    verify_context.update(b"").unwrap(); // Empty update
    let result = verify_context.finalize().unwrap();

    assert!(result);
}

#[test]
fn test_evp_verifier_streaming_wrong_data() {
    let (private_der, public_der) = generate_ec_p256_key();
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let data = b"original data";
    let signature = sign_data(&private_der, -7, data);

    let mut verify_context = verifier.verify_init(&signature).unwrap();
    verify_context.update(b"wrong data").unwrap();
    let result = verify_context.finalize().unwrap();

    assert!(!result);
}

#[test]
fn test_evp_verifier_rsa_pss_algorithm() {
    let (private_der, public_der) = generate_rsa_2048_key();
    let data = b"RSA PSS test data";

    // Test PS256
    let signature = sign_data(&private_der, -37, data);
    let verifier = EvpVerifier::from_der(&public_der, -37).unwrap();
    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_evp_verifier_ed25519_deterministic() {
    let (private_der, public_der) = generate_ed25519_key();
    let verifier = EvpVerifier::from_der(&public_der, -8).unwrap();

    let data = b"deterministic signature test";

    // Ed25519 signatures are deterministic
    let sig1 = sign_data(&private_der, -8, data);
    let sig2 = sign_data(&private_der, -8, data);

    assert_eq!(sig1, sig2); // Should be identical

    // Both should verify successfully
    assert!(verifier.verify(data, &sig1).unwrap());
    assert!(verifier.verify(data, &sig2).unwrap());
}

#[test]
fn test_evp_verifier_rsa_streaming() {
    let (private_der, public_der) = generate_rsa_2048_key();
    let verifier = EvpVerifier::from_der(&public_der, -257).unwrap();

    let data = b"RSA streaming verification test";
    let signature = sign_data(&private_der, -257, data);

    let mut verify_context = verifier.verify_init(&signature).unwrap();
    verify_context.update(data).unwrap();
    let result = verify_context.finalize().unwrap();

    assert!(result);
}
