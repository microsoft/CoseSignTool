// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional RSA and edge case coverage for crypto OpenSSL.

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier};
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Generate RSA 2048 key for PS256/PS384/PS512 testing
fn generate_rsa_2048_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate RSA 4096 key for testing larger RSA
fn generate_rsa_4096_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(4096).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate EC P-256 key for completeness
fn generate_ec_p256_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Generate ED25519 key for testing
fn generate_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let private_key = PKey::generate_ed25519().unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

#[test]
fn test_rsa_ps256_basic_sign_verify() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -37).unwrap(); // PS256
    let verifier = EvpVerifier::from_der(&public_der, -37).unwrap();

    assert_eq!(signer.algorithm(), -37);
    assert_eq!(signer.key_type(), "RSA");
    assert!(signer.supports_streaming());

    let data = b"test message for PS256";
    let signature = signer.sign(data).unwrap();

    assert!(signature.len() >= 256); // RSA 2048 = 256 bytes
    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_ps384_basic_sign_verify() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -38).unwrap(); // PS384
    let verifier = EvpVerifier::from_der(&public_der, -38).unwrap();

    assert_eq!(signer.algorithm(), -38);
    assert_eq!(verifier.algorithm(), -38);

    let data = b"test message for PS384 with longer content to ensure proper hashing";
    let signature = signer.sign(data).unwrap();

    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_ps512_basic_sign_verify() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -39).unwrap(); // PS512
    let verifier = EvpVerifier::from_der(&public_der, -39).unwrap();

    assert_eq!(signer.algorithm(), -39);

    let data = b"test message for PS512 with even longer content to test the SHA-512 hash function properly";
    let signature = signer.sign(data).unwrap();

    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_4096_ps256() {
    let (private_der, public_der) = generate_rsa_4096_key();

    let signer = EvpSigner::from_der(&private_der, -37).unwrap(); // PS256
    let verifier = EvpVerifier::from_der(&public_der, -37).unwrap();

    let data = b"test message with larger RSA 4096 key";
    let signature = signer.sign(data).unwrap();

    assert!(signature.len() >= 512); // RSA 4096 = 512 bytes
    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_streaming_ps256_large_message() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -37).unwrap(); // PS256
    let verifier = EvpVerifier::from_der(&public_der, -37).unwrap();

    // Create a large message to test streaming
    let chunk1 = b"This is the first chunk of a very long message. ";
    let chunk2 = b"This is the second chunk with more data to process. ";
    let chunk3 = b"And this is the final chunk to complete the test.";
    let full_message = [&chunk1[..], &chunk2[..], &chunk3[..]].concat();

    // Sign using streaming
    let mut signing_ctx = signer.sign_init().unwrap();
    signing_ctx.update(chunk1).unwrap();
    signing_ctx.update(chunk2).unwrap();
    signing_ctx.update(chunk3).unwrap();
    let signature = signing_ctx.finalize().unwrap();

    // Verify
    let result = verifier.verify(&full_message, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_streaming_ps384_chunked() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -38).unwrap(); // PS384
    let verifier = EvpVerifier::from_der(&public_der, -38).unwrap();

    // Test with many small chunks
    let mut signing_ctx = signer.sign_init().unwrap();
    let base_data = b"chunk";
    let mut full_data = Vec::new();

    for i in 0..20 {
        let chunk_data = format!("{}_{:02}", std::str::from_utf8(base_data).unwrap(), i);
        let chunk = chunk_data.as_bytes();
        signing_ctx.update(chunk).unwrap();
        full_data.extend_from_slice(chunk);
    }

    let signature = signing_ctx.finalize().unwrap();
    let result = verifier.verify(&full_data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_rsa_streaming_ps512_empty_chunks() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -39).unwrap(); // PS512

    // Test streaming with some empty chunks
    let mut signing_ctx = signer.sign_init().unwrap();
    signing_ctx.update(b"start").unwrap();
    signing_ctx.update(b"").unwrap(); // Empty chunk
    signing_ctx.update(b"middle").unwrap();
    signing_ctx.update(b"").unwrap(); // Another empty chunk
    signing_ctx.update(b"end").unwrap();

    let signature = signing_ctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&public_der, -39).unwrap();
    let full_data = b"startmiddleend";
    let result = verifier.verify(full_data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_unsupported_rsa_algorithm() {
    let (private_der, _) = generate_rsa_2048_key();

    // Unsupported algorithm -999 might be accepted during construction
    // but will fail during actual signing
    let result = EvpSigner::from_der(&private_der, -999);

    if result.is_ok() {
        // If construction succeeds, signing should fail
        let signer = result.unwrap();
        let sign_result = signer.sign(b"test data");
        assert!(
            sign_result.is_err(),
            "Signing with unsupported algorithm should fail"
        );
    } else {
        // If construction fails, that's also acceptable
        if let Err(CryptoError::UnsupportedAlgorithm(-999)) = result {
            // Expected
        } else {
            panic!("Expected UnsupportedAlgorithm error or successful construction");
        }
    }
}

#[test]
fn test_ecdsa_signature_format_conversion() {
    // Test that ECDSA signatures are properly converted from DER to fixed-length
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = EvpSigner::from_der(&private_der, -7).unwrap(); // ES256
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let data = b"test ECDSA signature format";
    let signature = signer.sign(data).unwrap();

    // ES256 should produce 64-byte signatures (32 bytes r + 32 bytes s)
    assert_eq!(signature.len(), 64);

    let result = verifier.verify(data, &signature).unwrap();
    assert!(result);
}

#[test]
fn test_streaming_context_key_type_reporting() {
    let (ec_der, _) = generate_ec_p256_key();
    let (rsa_der, _) = generate_rsa_2048_key();

    let ec_signer = EvpSigner::from_der(&ec_der, -7).unwrap(); // ES256
    let rsa_signer = EvpSigner::from_der(&rsa_der, -37).unwrap(); // PS256

    assert_eq!(ec_signer.key_type(), "EC2");
    assert_eq!(rsa_signer.key_type(), "RSA");

    // Test that both support streaming
    assert!(ec_signer.supports_streaming());
    assert!(rsa_signer.supports_streaming());
}

#[test]
fn test_invalid_der_key() {
    let invalid_der = b"not_a_valid_key";

    let result = EvpSigner::from_der(invalid_der, -7);
    assert!(result.is_err());
    if let Err(CryptoError::InvalidKey(_)) = result {
        // Expected
    } else {
        panic!("Expected InvalidKey error");
    }

    let result = EvpVerifier::from_der(invalid_der, -7);
    assert!(result.is_err());
    if let Err(CryptoError::InvalidKey(_)) = result {
        // Expected
    } else {
        panic!("Expected InvalidKey error");
    }
}

#[test]
fn test_signer_key_id_none() {
    let (private_der, _) = generate_ec_p256_key();
    let signer = EvpSigner::from_der(&private_der, -7).unwrap();

    // EvpSigner should return None for key_id
    assert_eq!(signer.key_id(), None);
}

#[test]
fn test_verifier_streaming_not_supported() {
    let (_, public_der) = generate_ed25519_key();
    let verifier = EvpVerifier::from_der(&public_der, -8).unwrap();

    // ED25519 verifier should not support streaming in OpenSSL
    assert!(!verifier.supports_streaming());
}

#[test]
fn test_wrong_signature_length_verification() {
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = EvpSigner::from_der(&private_der, -7).unwrap(); // ES256
    let verifier = EvpVerifier::from_der(&public_der, -7).unwrap();

    let data = b"test message";
    let mut signature = signer.sign(data).unwrap();

    // Corrupt the signature by changing length
    signature.truncate(32); // Should be 64 bytes for ES256

    let result = verifier.verify(data, &signature);
    // Should either fail or return false
    match result {
        Ok(false) => {} // Verification failed
        Err(_) => {}    // Error during verification
        Ok(true) => panic!("Verification should not succeed with corrupted signature"),
    }
}

#[test]
fn test_rsa_signature_wrong_data() {
    let (private_der, public_der) = generate_rsa_2048_key();

    let signer = EvpSigner::from_der(&private_der, -37).unwrap(); // PS256
    let verifier = EvpVerifier::from_der(&public_der, -37).unwrap();

    let original_data = b"original message";
    let wrong_data = b"wrong message";

    let signature = signer.sign(original_data).unwrap();

    // Verify with wrong data should fail
    let result = verifier.verify(wrong_data, &signature).unwrap();
    assert!(!result);
}
