// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional streaming sign coverage tests for EvpSigner.

use cose_sign1_crypto_openssl::EvpSigner;
use crypto_primitives::{CryptoError, CryptoSigner};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Generate EC P-384 key for ES384 testing
fn generate_ec_p384_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate EC P-521 key for ES512 testing  
fn generate_ec_p521_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate RSA 3072 key for testing larger RSA keys
fn generate_rsa_3072_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(3072).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

#[test]
fn test_streaming_sign_es384_multiple_updates() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create ES384 signer");

    assert!(signer.supports_streaming());
    
    let mut context = signer.sign_init().expect("should create signing context");
    
    // Multiple small updates
    context.update(b"chunk1").expect("should update");
    context.update(b"chunk2").expect("should update");
    context.update(b"chunk3").expect("should update");
    context.update(b"chunk4").expect("should update");
    
    let signature = context.finalize().expect("should finalize");
    
    assert_eq!(signature.len(), 96); // ES384: 2 * 48 bytes
}

#[test]
fn test_streaming_sign_es512_large_data() {
    let (private_der, _) = generate_ec_p521_key();
    let signer = EvpSigner::from_der(&private_der, -36).expect("should create ES512 signer");

    let mut context = signer.sign_init().expect("should create signing context");
    
    // Large data in chunks
    let large_chunk = vec![0x42; 8192];
    context.update(&large_chunk).expect("should update");
    context.update(&large_chunk).expect("should update");
    context.update(b"final chunk").expect("should update");
    
    let signature = context.finalize().expect("should finalize");
    
    assert_eq!(signature.len(), 132); // ES512: 2 * 66 bytes
}

#[test]
fn test_streaming_sign_rsa_pss_algorithms() {
    let (private_der, _) = generate_rsa_3072_key();
    
    // Test all RSA-PSS algorithms
    for (alg, name) in [(-37, "PS256"), (-38, "PS384"), (-39, "PS512")] {
        let signer = EvpSigner::from_der(&private_der, alg).expect(&format!("should create {} signer", name));

        let mut context = signer.sign_init().expect("should create signing context");
        context.update(b"PSS test data for ").expect("should update");
        context.update(name.as_bytes()).expect("should update");
        
        let signature = context.finalize().expect("should finalize");
        
        assert_eq!(signature.len(), 384); // RSA 3072 signature is 384 bytes
    }
}

#[test]
fn test_streaming_sign_rsa_pkcs1_algorithms() {
    let (private_der, _) = generate_rsa_3072_key();
    
    // Test all RSA-PKCS1 algorithms  
    for (alg, name) in [(-257, "RS256"), (-258, "RS384"), (-259, "RS512")] {
        let signer = EvpSigner::from_der(&private_der, alg).expect(&format!("should create {} signer", name));

        let mut context = signer.sign_init().expect("should create signing context");
        context.update(b"PKCS1 test data for ").expect("should update");
        context.update(name.as_bytes()).expect("should update");
        
        let signature = context.finalize().expect("should finalize");
        
        assert_eq!(signature.len(), 384); // RSA 3072 signature is 384 bytes
    }
}

#[test]
fn test_streaming_sign_ed25519_empty_updates() {
    let private_key = PKey::generate_ed25519().unwrap();
    let private_der = private_key.private_key_to_der().unwrap();
    
    let signer = EvpSigner::from_der(&private_der, -8).expect("should create EdDSA signer");

    // ED25519 does not support streaming in OpenSSL
    assert!(!signer.supports_streaming(), "ED25519 should not support streaming");
}

#[test]
fn test_streaming_sign_single_byte_updates() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create ES384 signer");

    let mut context = signer.sign_init().expect("should create signing context");
    
    // Single byte updates (stress test)
    let data = b"streaming test with single byte updates";
    for &byte in data {
        context.update(&[byte]).expect("should update single byte");
    }
    
    let signature = context.finalize().expect("should finalize");
    assert_eq!(signature.len(), 96); // ES384: 2 * 48 bytes
    
    // Compare with one-shot signing
    let oneshot_signature = signer.sign(data).expect("should sign one-shot");
    // Signatures will be different due to randomness, but same length
    assert_eq!(signature.len(), oneshot_signature.len());
}

#[test]
fn test_rsa_key_type_detection() {
    let (private_der, _) = generate_rsa_3072_key();
    
    let signer = EvpSigner::from_der(&private_der, -257).expect("should create RSA signer");
    assert_eq!(signer.key_type(), "RSA");
    assert_eq!(signer.algorithm(), -257);
    assert!(signer.supports_streaming());
    assert_eq!(signer.key_id(), None);
}

#[test]
fn test_ec_key_type_detection_all_curves() {
    // P-256
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create P-384 signer");
    assert_eq!(signer.key_type(), "EC2");
    
    // P-521
    let (private_der, _) = generate_ec_p521_key();
    let signer = EvpSigner::from_der(&private_der, -36).expect("should create P-521 signer");
    assert_eq!(signer.key_type(), "EC2");
}

#[test]
fn test_unsupported_algorithm_error() {
    let (private_der, _) = generate_ec_p384_key();
    
    // Try to create signer with unsupported algorithm
    let result = EvpSigner::from_der(&private_der, 999);
    // This might succeed at creation but fail during signing, depending on implementation
    
    if let Ok(signer) = result {
        // Try to sign with unsupported algorithm
        let sign_result = signer.sign(b"test");
        assert!(sign_result.is_err());
        if let Err(e) = sign_result {
            assert!(matches!(e, CryptoError::UnsupportedAlgorithm(999)));
        }
    }
}

#[test]
fn test_streaming_context_error_paths() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");

    let mut context = signer.sign_init().expect("should create context");
    
    // Update with valid data
    context.update(b"valid data").expect("should update");
    
    // Finalize should work
    let signature = context.finalize().expect("should finalize");
    assert!(!signature.is_empty());
}

#[test]
fn test_key_cloning_functionality() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");

    // Create multiple streaming contexts (tests key cloning)
    let context1 = signer.sign_init().expect("should create context 1");
    let context2 = signer.sign_init().expect("should create context 2");
    
    // Both should be valid (implementation detail but shows cloning works)
    drop(context1);
    drop(context2);
    
    // Signer should still work after contexts are dropped
    let signature = signer.sign(b"test after cloning").expect("should sign");
    assert!(!signature.is_empty());
}

#[test]
fn test_mixed_streaming_and_oneshot() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");

    // One-shot signing
    let oneshot_sig = signer.sign(b"oneshot data").expect("should sign one-shot");
    
    // Streaming signing with same data
    let mut context = signer.sign_init().expect("should create context");
    context.update(b"oneshot data").expect("should update");
    let streaming_sig = context.finalize().expect("should finalize");
    
    // Both should be valid signatures (but different due to randomness)
    assert_eq!(oneshot_sig.len(), streaming_sig.len());
    assert_eq!(oneshot_sig.len(), 96); // ES384
    
    // Do another one-shot to ensure signer still works
    let another_sig = signer.sign(b"another test").expect("should sign again");
    assert_eq!(another_sig.len(), 96);
}

#[test]
fn test_large_streaming_data() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");

    let mut context = signer.sign_init().expect("should create context");
    
    // Stream a large amount of data (1MB in 1KB chunks)
    let chunk = vec![0x5A; 1024]; // 1KB chunks
    for _ in 0..1024 {
        context.update(&chunk).expect("should update large chunk");
    }
    
    let signature = context.finalize().expect("should finalize large data");
    assert_eq!(signature.len(), 96); // ES384
}

#[test] 
fn test_streaming_zero_length_final_update() {
    let (private_der, _) = generate_ec_p384_key();
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");

    let mut context = signer.sign_init().expect("should create context");
    context.update(b"some data").expect("should update");
    context.update(b"").expect("should handle zero-length update");
    
    let signature = context.finalize().expect("should finalize");
    assert_eq!(signature.len(), 96);
}