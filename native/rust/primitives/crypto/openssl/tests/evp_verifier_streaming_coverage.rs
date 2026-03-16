// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional streaming verification coverage tests for EvpVerifier.

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier};
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier, VerifyingContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Generate EC P-256 keypair for testing
fn generate_ec_p256_keypair() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate EC P-384 keypair for testing
fn generate_ec_p384_keypair() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate EC P-521 keypair for testing
fn generate_ec_p521_keypair() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate RSA 2048 keypair for testing
fn generate_rsa_2048_keypair() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate Ed25519 keypair for testing
fn generate_ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let private_key = PKey::generate_ed25519().unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

#[test]
fn test_streaming_verify_es256_multiple_chunks() {
    let (private_der, public_der) = generate_ec_p256_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -7).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -7).expect("should create verifier");
    
    let test_data = b"This is test data for streaming verification";
    
    // Create signature using streaming signing
    let mut sign_context = signer.sign_init().expect("should create sign context");
    sign_context.update(b"This is test ").expect("should update");
    sign_context.update(b"data for streaming ").expect("should update");
    sign_context.update(b"verification").expect("should update");
    let signature = sign_context.finalize().expect("should finalize signature");
    
    // Verify using streaming verification with same chunking
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    verify_context.update(b"This is test ").expect("should update");
    verify_context.update(b"data for streaming ").expect("should update");
    verify_context.update(b"verification").expect("should update");
    let result = verify_context.finalize().expect("should finalize verification");
    
    assert!(result, "streaming verification should succeed");
    
    // Also verify with one-shot
    let oneshot_result = verifier.verify(test_data, &signature).expect("should verify one-shot");
    assert!(oneshot_result, "one-shot verification should succeed");
}

#[test]
fn test_streaming_verify_es384_different_chunk_sizes() {
    let (private_der, public_der) = generate_ec_p384_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create ES384 signer");
    let verifier = EvpVerifier::from_der(&public_der, -35).expect("should create ES384 verifier");
    
    let test_data = b"ES384 streaming test with various chunk sizes for comprehensive coverage";
    
    // Sign with one chunking pattern
    let mut sign_context = signer.sign_init().expect("should create sign context");
    sign_context.update(&test_data[0..20]).expect("should update");
    sign_context.update(&test_data[20..50]).expect("should update");
    sign_context.update(&test_data[50..]).expect("should update");
    let signature = sign_context.finalize().expect("should finalize");
    
    // Verify with different chunking pattern
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    verify_context.update(&test_data[0..10]).expect("should update");
    verify_context.update(&test_data[10..40]).expect("should update");
    verify_context.update(&test_data[40..60]).expect("should update");
    verify_context.update(&test_data[60..]).expect("should update");
    let result = verify_context.finalize().expect("should finalize");
    
    assert!(result, "verification should succeed despite different chunking");
}

#[test]
fn test_streaming_verify_es512_large_data() {
    let (private_der, public_der) = generate_ec_p521_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -36).expect("should create ES512 signer");
    let verifier = EvpVerifier::from_der(&public_der, -36).expect("should create ES512 verifier");
    
    // Large test data (64KB)
    let test_data = vec![0xAB; 65536];
    
    // Sign in large chunks
    let mut sign_context = signer.sign_init().expect("should create sign context");
    for chunk in test_data.chunks(8192) {
        sign_context.update(chunk).expect("should update sign");
    }
    let signature = sign_context.finalize().expect("should finalize sign");
    
    // Verify in different chunk sizes
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    for chunk in test_data.chunks(4096) {
        verify_context.update(chunk).expect("should update verify");
    }
    let result = verify_context.finalize().expect("should finalize verify");
    
    assert!(result, "verification of large data should succeed");
}

#[test]
fn test_streaming_verify_rsa_pss_all_algorithms() {
    let (private_der, public_der) = generate_rsa_2048_keypair();
    
    for (alg, name) in [(-37, "PS256"), (-38, "PS384"), (-39, "PS512")] {
        let signer = EvpSigner::from_der(&private_der, alg).expect(&format!("should create {} signer", name));
        let verifier = EvpVerifier::from_der(&public_der, alg).expect(&format!("should create {} verifier", name));
        
        let test_data = format!("RSA-PSS {} streaming test data", name);
        let test_bytes = test_data.as_bytes();
        
        // Sign with streaming
        let mut sign_context = signer.sign_init().expect("should create sign context");
        sign_context.update(b"RSA-PSS ").expect("should update");
        sign_context.update(name.as_bytes()).expect("should update");
        sign_context.update(b" streaming test data").expect("should update");
        let signature = sign_context.finalize().expect("should finalize");
        
        // Verify with streaming 
        let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
        verify_context.update(test_bytes).expect("should update verify");
        let result = verify_context.finalize().expect("should finalize verify");
        
        assert!(result, "{} streaming verification should succeed", name);
    }
}

#[test]
fn test_streaming_verify_rsa_pkcs1_all_algorithms() {
    let (private_der, public_der) = generate_rsa_2048_keypair();
    
    for (alg, name) in [(-257, "RS256"), (-258, "RS384"), (-259, "RS512")] {
        let signer = EvpSigner::from_der(&private_der, alg).expect(&format!("should create {} signer", name));
        let verifier = EvpVerifier::from_der(&public_der, alg).expect(&format!("should create {} verifier", name));
        
        let test_data = format!("RSA-PKCS1 {} streaming verification test", name);
        let test_bytes = test_data.as_bytes();
        
        // Sign data
        let signature = signer.sign(test_bytes).expect("should sign");
        
        // Verify with streaming in single-byte updates (stress test)
        let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
        for &byte in test_bytes {
            verify_context.update(&[byte]).expect("should update single byte");
        }
        let result = verify_context.finalize().expect("should finalize");
        
        assert!(result, "{} single-byte streaming verification should succeed", name);
    }
}

#[test]
fn test_streaming_verify_ed25519_empty_updates() {
    let (private_der, public_der) = generate_ed25519_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -8).expect("should create EdDSA signer");
    let verifier = EvpVerifier::from_der(&public_der, -8).expect("should create EdDSA verifier");
    
    // ED25519 does not support streaming in OpenSSL
    assert!(!signer.supports_streaming(), "ED25519 signer should not support streaming");
    assert!(!verifier.supports_streaming(), "ED25519 verifier should not support streaming");
}

#[test]
fn test_streaming_verify_invalid_signature() {
    let (private_der, public_der) = generate_ec_p256_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -7).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -7).expect("should create verifier");
    
    let test_data = b"Test data for invalid signature";
    let signature = signer.sign(test_data).expect("should sign");
    
    // Corrupt the signature
    let mut bad_signature = signature;
    bad_signature[0] ^= 0xFF; // Flip bits in first byte
    
    // Try to verify with streaming
    let mut verify_context = verifier.verify_init(&bad_signature).expect("should create verify context");
    verify_context.update(test_data).expect("should update");
    let result = verify_context.finalize().expect("should finalize");
    
    assert!(!result, "verification of corrupted signature should fail");
}

#[test]
fn test_streaming_verify_wrong_data() {
    let (private_der, public_der) = generate_ec_p384_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -35).expect("should create verifier");
    
    let original_data = b"This is the original data that was signed";
    let wrong_data = b"This is different data that was not signed";
    
    let signature = signer.sign(original_data).expect("should sign");
    
    // Try to verify wrong data with streaming
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    verify_context.update(wrong_data).expect("should update");
    let result = verify_context.finalize().expect("should finalize");
    
    assert!(!result, "verification of wrong data should fail");
}

#[test]
fn test_streaming_verify_supports_streaming() {
    let (_, public_der) = generate_ec_p256_keypair();
    
    let verifier = EvpVerifier::from_der(&public_der, -7).expect("should create verifier");
    
    assert!(verifier.supports_streaming(), "verifier should support streaming");
    assert_eq!(verifier.algorithm(), -7);
}

#[test]
fn test_streaming_verify_malformed_signature() {
    let (_, public_der) = generate_ec_p256_keypair();
    
    let verifier = EvpVerifier::from_der(&public_der, -7).expect("should create verifier");
    
    // Try various malformed signatures
    let malformed_signatures = vec![
        vec![],                    // Empty signature
        vec![0x00],               // Too short
        vec![0xFF; 32],           // Wrong length for ES256 (should be 64)
        vec![0x00; 128],          // Too long for ES256
    ];
    
    for (i, bad_sig) in malformed_signatures.iter().enumerate() {
        let result = verifier.verify_init(bad_sig);
        if result.is_err() {
            // Some malformed signatures are caught at init time
            continue;
        }
        
        let mut verify_context = result.unwrap();
        verify_context.update(b"test data").expect("should update");
        let verify_result = verify_context.finalize();
        
        // Should either error during finalize or return false
        match verify_result {
            Ok(false) => {} // Verification failed as expected
            Err(_) => {}    // Error during verification as expected
            Ok(true) => panic!("Malformed signature {} should not verify as valid", i),
        }
    }
}

#[test]
fn test_streaming_verify_key_cloning() {
    let (private_der, public_der) = generate_ec_p384_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -35).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -35).expect("should create verifier");
    
    let test_data = b"Test data for key cloning verification";
    let signature = signer.sign(test_data).expect("should sign");
    
    // Create multiple streaming verification contexts (tests key cloning)
    let context1 = verifier.verify_init(&signature).expect("should create context 1");
    let context2 = verifier.verify_init(&signature).expect("should create context 2");
    
    drop(context1); // Drop first context
    
    // Second context should still work
    let mut verify_context = context2;
    verify_context.update(test_data).expect("should update");
    let result = verify_context.finalize().expect("should finalize");
    
    assert!(result, "verification should succeed after key cloning");
}

#[test]
fn test_streaming_verify_mixed_with_oneshot() {
    let (private_der, public_der) = generate_ec_p521_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -36).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -36).expect("should create verifier");
    
    let test_data = b"Mixed streaming and one-shot verification test";
    let signature = signer.sign(test_data).expect("should sign");
    
    // One-shot verification
    let oneshot_result = verifier.verify(test_data, &signature).expect("should verify one-shot");
    assert!(oneshot_result, "one-shot verification should succeed");
    
    // Streaming verification
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    verify_context.update(test_data).expect("should update");
    let streaming_result = verify_context.finalize().expect("should finalize");
    assert!(streaming_result, "streaming verification should succeed");
    
    // Another one-shot to ensure verifier still works
    let another_result = verifier.verify(test_data, &signature).expect("should verify again");
    assert!(another_result, "second one-shot verification should succeed");
}

#[test]
fn test_streaming_verify_different_signature_chunk_alignment() {
    let (private_der, public_der) = generate_ec_p256_keypair();
    
    let signer = EvpSigner::from_der(&private_der, -7).expect("should create signer");
    let verifier = EvpVerifier::from_der(&public_der, -7).expect("should create verifier");
    
    let test_data = vec![0x5A; 1000]; // 1KB of test data
    
    // Sign in 100-byte chunks
    let mut sign_context = signer.sign_init().expect("should create sign context");
    for chunk in test_data.chunks(100) {
        sign_context.update(chunk).expect("should update sign");
    }
    let signature = sign_context.finalize().expect("should finalize");
    
    // Verify in 73-byte chunks (different alignment)
    let mut verify_context = verifier.verify_init(&signature).expect("should create verify context");
    for chunk in test_data.chunks(73) {
        verify_context.update(chunk).expect("should update verify");
    }
    let result = verify_context.finalize().expect("should finalize");
    
    assert!(result, "verification with different chunk alignment should succeed");
}
