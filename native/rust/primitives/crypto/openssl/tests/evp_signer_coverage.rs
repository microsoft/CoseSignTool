// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage tests for EvpSigner - basic, streaming, and edge cases.

use cose_sign1_crypto_openssl::EvpSigner;
use crypto_primitives::{CryptoError, CryptoSigner, SigningContext};
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

#[test]
fn test_evp_signer_from_der_ec_p256() {
    let (private_der, _) = generate_ec_p256_key();

    let signer = EvpSigner::from_der(&private_der, -7); // ES256
    assert!(signer.is_ok());

    let signer = signer.unwrap();
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC2");
}

#[test]
fn test_evp_signer_from_der_rsa_2048() {
    let (private_der, _) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -257); // RS256
    assert!(signer.is_ok());

    let signer = signer.unwrap();
    assert_eq!(signer.algorithm(), -257);
    assert_eq!(signer.key_type(), "RSA");
}

#[test]
fn test_evp_signer_from_der_ed25519() {
    let (private_der, _) = generate_ed25519_key();

    let signer = EvpSigner::from_der(&private_der, -8); // EdDSA
    assert!(signer.is_ok());

    let signer = signer.unwrap();
    assert_eq!(signer.algorithm(), -8);
    assert_eq!(signer.key_type(), "OKP");
}

#[test]
fn test_evp_signer_from_invalid_der() {
    let invalid_der = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Invalid DER

    let result = EvpSigner::from_der(&invalid_der, -7);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CryptoError::InvalidKey(_)));
    }
}

#[test]
fn test_evp_signer_from_empty_der() {
    let empty_der: Vec<u8> = vec![];

    let result = EvpSigner::from_der(&empty_der, -7);
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, CryptoError::InvalidKey(_)));
    }
}

#[test]
fn test_evp_signer_sign_small_data() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let small_data = b"small";
    let signature = signer.sign(small_data);
    assert!(signature.is_ok());

    let sig = signature.unwrap();
    assert!(!sig.is_empty());
    assert_eq!(sig.len(), 64); // P-256 signature should be exactly 64 bytes
}

#[test]
fn test_evp_signer_sign_large_data() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let large_data = vec![0x42u8; 100000]; // 100KB
    let signature = signer.sign(&large_data);
    assert!(signature.is_ok());

    let sig = signature.unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn test_evp_signer_sign_empty_data() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let empty_data = b"";
    let signature = signer.sign(empty_data);
    assert!(signature.is_ok());

    let sig = signature.unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn test_evp_signer_key_id() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    // EvpSigner doesn't provide key_id by default
    assert_eq!(signer.key_id(), None);
}

#[test]
fn test_evp_signer_supports_streaming() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    assert!(signer.supports_streaming());
}

#[test]
fn test_evp_signer_streaming_context() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let mut context = signer.sign_init().unwrap();

    // Stream data in chunks
    context.update(b"chunk1").unwrap();
    context.update(b"chunk2").unwrap();
    context.update(b"chunk3").unwrap();

    let signature = context.finalize().unwrap();
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 64); // P-256 signature
}

#[test]
fn test_evp_signer_streaming_empty_updates() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let mut context = signer.sign_init().unwrap();

    // Update with empty data
    context.update(b"").unwrap();
    context.update(b"actual_data").unwrap();
    context.update(b"").unwrap();

    let signature = context.finalize().unwrap();
    assert!(!signature.is_empty());
}

#[test]
fn test_evp_signer_streaming_no_updates() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let context = signer.sign_init().unwrap();
    let signature = context.finalize().unwrap();
    assert!(!signature.is_empty());
}

#[test]
fn test_evp_signer_rsa_pss_algorithms() {
    let (private_der, _) = generate_rsa_2048_key();

    // Test PS256
    let signer = EvpSigner::from_der(&private_der, -37).unwrap();
    assert_eq!(signer.algorithm(), -37);

    let data = b"PSS test data";
    let sig = signer.sign(data).unwrap();
    assert!(!sig.is_empty());
    assert!(sig.len() >= 256); // RSA 2048 signature should be 256 bytes
}

#[test]
fn test_evp_signer_ed25519_deterministic() {
    let (private_der, _) = generate_ed25519_key();
    let signer = EvpSigner::from_der(&private_der, -8).unwrap();

    let test_data = b"deterministic test data";

    let sig1 = signer.sign(test_data).unwrap();
    let sig2 = signer.sign(test_data).unwrap();

    // Ed25519 should produce identical signatures for same data and key
    assert_eq!(sig1, sig2);
    assert_eq!(sig1.len(), 64); // Ed25519 signatures are always 64 bytes
}

#[test]
fn test_evp_signer_ecdsa_randomized() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    let data = b"randomized test data";
    let sig1 = signer.sign(data).unwrap();
    let sig2 = signer.sign(data).unwrap();

    // ECDSA signatures should be different even for same data (randomized)
    assert_ne!(sig1, sig2);
}

#[test]
fn test_evp_signer_rsa_streaming() {
    let (private_der, _) = generate_rsa_2048_key();
    let signer = EvpSigner::from_der(&private_der, -257).unwrap(); // RS256

    let mut context = signer.sign_init().unwrap();
    context.update(b"RSA streaming test data").unwrap();
    let signature = context.finalize().unwrap();

    assert!(!signature.is_empty());
    assert!(signature.len() >= 256); // RSA 2048 signature should be 256 bytes
}
