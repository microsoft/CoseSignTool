// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for OpenSSL crypto provider.

use cose_sign1_crypto_openssl::{
    EvpPrivateKey, EvpPublicKey, EvpSigner, EvpVerifier, OpenSslCryptoProvider,
};
use crypto_primitives::{
    CryptoProvider, CryptoSigner, CryptoVerifier, SigningContext, VerifyingContext,
};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

/// Test helper to generate EC P-256 keypair.
fn generate_ec_p256_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Test helper to generate RSA keypair.
fn generate_rsa_key() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Test helper to generate Ed25519 keypair.
fn generate_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let private_key = PKey::generate_ed25519().unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

#[test]
fn test_provider_name() {
    let provider = OpenSslCryptoProvider;
    assert_eq!(provider.name(), "OpenSSL");
}

#[test]
fn test_signer_from_der_ec_p256() {
    let provider = OpenSslCryptoProvider;
    let (private_der, _public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.algorithm(), -7); // ES256
    assert_eq!(signer.key_type(), "EC2");
    assert!(signer.supports_streaming());
    assert_eq!(signer.key_id(), None);
}

#[test]
fn test_signer_from_der_rsa() {
    let provider = OpenSslCryptoProvider;
    let (private_der, _public_der) = generate_rsa_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.algorithm(), -257); // RS256
    assert_eq!(signer.key_type(), "RSA");
    assert!(signer.supports_streaming());
}

#[test]
fn test_signer_from_der_ed25519() {
    let provider = OpenSslCryptoProvider;
    let (private_der, _public_der) = generate_ed25519_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.algorithm(), -8); // EdDSA
    assert_eq!(signer.key_type(), "OKP");
    assert!(!signer.supports_streaming()); // ED25519 does not support streaming in OpenSSL
}

#[test]
fn test_verifier_from_der_ec_p256() {
    let provider = OpenSslCryptoProvider;
    let (_private_der, public_der) = generate_ec_p256_key();

    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");
    assert_eq!(verifier.algorithm(), -7); // ES256
    assert!(verifier.supports_streaming());
}

#[test]
fn test_verifier_from_der_rsa() {
    let provider = OpenSslCryptoProvider;
    let (_private_der, public_der) = generate_rsa_key();

    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");
    assert_eq!(verifier.algorithm(), -257); // RS256
    assert!(verifier.supports_streaming());
}

#[test]
fn test_verifier_from_der_ed25519() {
    let provider = OpenSslCryptoProvider;
    let (_private_der, public_der) = generate_ed25519_key();

    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");
    assert_eq!(verifier.algorithm(), -8); // EdDSA
    assert!(!verifier.supports_streaming()); // ED25519 does not support streaming in OpenSSL
}

#[test]
fn test_sign_verify_roundtrip_ec_p256() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    let data = b"test message for signing";
    let signature = signer.sign(data).expect("signing should succeed");

    let is_valid = verifier
        .verify(data, &signature)
        .expect("verification should succeed");
    assert!(is_valid, "signature should be valid");

    // Test with wrong data
    let wrong_data = b"wrong message";
    let is_valid = verifier
        .verify(wrong_data, &signature)
        .expect("verification should succeed");
    assert!(!is_valid, "signature should be invalid for wrong data");
}

#[test]
fn test_sign_verify_roundtrip_rsa() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_rsa_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    let data = b"test message for RSA signing";
    let signature = signer.sign(data).expect("signing should succeed");

    let is_valid = verifier
        .verify(data, &signature)
        .expect("verification should succeed");
    assert!(is_valid, "RSA signature should be valid");
}

#[test]
fn test_sign_verify_roundtrip_ed25519() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ed25519_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    let data = b"test message for Ed25519 signing";
    let signature = signer.sign(data).expect("signing should succeed");

    let is_valid = verifier
        .verify(data, &signature)
        .expect("verification should succeed");
    assert!(is_valid, "Ed25519 signature should be valid");
}

#[test]
fn test_streaming_signer_ec_p256() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    // Create streaming context
    let mut ctx = signer.sign_init().expect("sign_init should succeed");
    ctx.update(b"hello ").expect("update should succeed");
    ctx.update(b"world").expect("update should succeed");

    let signature = ctx.finalize().expect("finalize should succeed");

    // Verify using regular verifier
    let is_valid = verifier
        .verify(b"hello world", &signature)
        .expect("verification should succeed");
    assert!(is_valid, "streaming signature should be valid");
}

#[test]
fn test_streaming_verifier_ec_p256() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    let data = b"test streaming verification";
    let signature = signer.sign(data).expect("signing should succeed");

    // Create streaming verification context
    let mut ctx = verifier
        .verify_init(&signature)
        .expect("verify_init should succeed");
    ctx.update(b"test streaming ")
        .expect("update should succeed");
    ctx.update(b"verification").expect("update should succeed");

    let is_valid = ctx.finalize().expect("finalize should succeed");
    assert!(is_valid, "streaming verification should succeed");
}

#[test]
fn test_invalid_private_key() {
    let provider = OpenSslCryptoProvider;
    let invalid_der = b"not a valid DER key";

    let result = provider.signer_from_der(invalid_der);
    assert!(result.is_err(), "invalid key should cause error");

    if let Err(crypto_primitives::CryptoError::InvalidKey(msg)) = result {
        assert!(
            msg.contains("Failed to parse private key"),
            "error message should mention parsing failure"
        );
    } else {
        panic!("expected InvalidKey error");
    }
}

#[test]
fn test_invalid_public_key() {
    let provider = OpenSslCryptoProvider;
    let invalid_der = b"not a valid DER key";

    let result = provider.verifier_from_der(invalid_der);
    assert!(result.is_err(), "invalid key should cause error");

    if let Err(crypto_primitives::CryptoError::InvalidKey(msg)) = result {
        assert!(
            msg.contains("Failed to parse public key"),
            "error message should mention parsing failure"
        );
    } else {
        panic!("expected InvalidKey error");
    }
}

#[test]
fn test_evp_signer_direct_creation() {
    let (private_der, _public_der) = generate_ec_p256_key();

    // Test direct EvpSigner creation
    let signer = EvpSigner::from_der(&private_der, -7).expect("signer creation should succeed");
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC2");

    let data = b"direct signer test";
    let signature = signer.sign(data).expect("signing should succeed");
    assert!(!signature.is_empty(), "signature should not be empty");
}

#[test]
fn test_evp_verifier_direct_creation() {
    let (_private_der, public_der) = generate_ec_p256_key();

    // Test direct EvpVerifier creation
    let verifier =
        EvpVerifier::from_der(&public_der, -7).expect("verifier creation should succeed");
    assert_eq!(verifier.algorithm(), -7);
    assert!(verifier.supports_streaming());
}

#[test]
fn test_evp_private_key_from_ec() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();

    let evp_key = EvpPrivateKey::from_ec(ec_key).expect("key creation should succeed");
    assert_eq!(evp_key.key_type(), cose_sign1_crypto_openssl::KeyType::Ec);

    // Test public key extraction
    let public_key = evp_key
        .public_key()
        .expect("public key extraction should succeed");
    assert_eq!(
        public_key.key_type(),
        cose_sign1_crypto_openssl::KeyType::Ec
    );
}

#[test]
fn test_evp_private_key_from_rsa() {
    let rsa = Rsa::generate(2048).unwrap();

    let evp_key = EvpPrivateKey::from_rsa(rsa).expect("key creation should succeed");
    assert_eq!(evp_key.key_type(), cose_sign1_crypto_openssl::KeyType::Rsa);

    // Test public key extraction
    let public_key = evp_key
        .public_key()
        .expect("public key extraction should succeed");
    assert_eq!(
        public_key.key_type(),
        cose_sign1_crypto_openssl::KeyType::Rsa
    );
}

#[test]
fn test_evp_public_key_from_ec() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let public_ec = ec_key.public_key().clone();

    // Extract public key portion
    let ec_public = EcKey::from_public_key(&group, &public_ec).unwrap();

    let evp_key = EvpPublicKey::from_ec(ec_public).expect("key creation should succeed");
    assert_eq!(evp_key.key_type(), cose_sign1_crypto_openssl::KeyType::Ec);
}

#[test]
fn test_evp_public_key_from_rsa() {
    let rsa = Rsa::generate(2048).unwrap();
    let public_rsa =
        Rsa::from_public_components(rsa.n().to_owned().unwrap(), rsa.e().to_owned().unwrap())
            .unwrap();

    let evp_key = EvpPublicKey::from_rsa(public_rsa).expect("key creation should succeed");
    assert_eq!(evp_key.key_type(), cose_sign1_crypto_openssl::KeyType::Rsa);
}

#[test]
fn test_unsupported_key_type() {
    // Create a DSA key (unsupported)
    let dsa = openssl::dsa::Dsa::generate(2048).unwrap();
    let dsa_key = PKey::from_dsa(dsa).unwrap();

    let private_der = dsa_key.private_key_to_der().unwrap();
    let public_der = dsa_key.public_key_to_der().unwrap();

    let provider = OpenSslCryptoProvider;

    // Should fail for unsupported key type
    let signer_result = provider.signer_from_der(&private_der);
    assert!(signer_result.is_err());

    let verifier_result = provider.verifier_from_der(&public_der);
    assert!(verifier_result.is_err());
}

#[test]
fn test_signature_format_edge_cases() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    // Test with empty data
    let empty_data = b"";
    let signature = signer
        .sign(empty_data)
        .expect("signing empty data should succeed");
    let is_valid = verifier
        .verify(empty_data, &signature)
        .expect("verification should succeed");
    assert!(is_valid, "signature of empty data should be valid");

    // Test with large data
    let large_data = vec![0x42; 10000];
    let signature = signer
        .sign(&large_data)
        .expect("signing large data should succeed");
    let is_valid = verifier
        .verify(&large_data, &signature)
        .expect("verification should succeed");
    assert!(is_valid, "signature of large data should be valid");
}

#[test]
fn test_streaming_context_error_handling() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    // Test streaming signer
    let mut sign_ctx = signer.sign_init().expect("sign_init should succeed");
    sign_ctx
        .update(b"test data")
        .expect("update should succeed");
    let signature = sign_ctx.finalize().expect("finalize should succeed");

    // Test streaming verifier with wrong signature
    let wrong_signature = vec![0; signature.len()];
    let mut verify_ctx = verifier
        .verify_init(&wrong_signature)
        .expect("verify_init should succeed");
    verify_ctx
        .update(b"test data")
        .expect("update should succeed");
    let is_valid = verify_ctx.finalize().expect("finalize should succeed");
    assert!(!is_valid, "wrong signature should be invalid");
}

#[test]
fn test_algorithm_detection_coverage() {
    let provider = OpenSslCryptoProvider;

    // Test all supported key types
    let test_cases = vec![
        ("EC P-256", generate_ec_p256_key(), -7),
        ("RSA 2048", generate_rsa_key(), -257),
        ("Ed25519", generate_ed25519_key(), -8),
    ];

    for (name, (private_der, public_der), expected_alg) in test_cases {
        let signer = provider
            .signer_from_der(&private_der)
            .expect(&format!("signer creation should succeed for {}", name));
        let verifier = provider
            .verifier_from_der(&public_der)
            .expect(&format!("verifier creation should succeed for {}", name));

        assert_eq!(
            signer.algorithm(),
            expected_alg,
            "algorithm mismatch for {}",
            name
        );
        assert_eq!(
            verifier.algorithm(),
            expected_alg,
            "algorithm mismatch for {}",
            name
        );
    }
}

#[test]
fn test_key_type_strings() {
    let provider = OpenSslCryptoProvider;

    let (private_der, _) = generate_ec_p256_key();
    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.key_type(), "EC2");

    let (private_der, _) = generate_rsa_key();
    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.key_type(), "RSA");

    let (private_der, _) = generate_ed25519_key();
    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    assert_eq!(signer.key_type(), "OKP");
}

/// Test helper to generate EC P-384 keypair.
fn generate_ec_p384_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

/// Test helper to generate EC P-521 keypair.
fn generate_ec_p521_key() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = PKey::from_ec_key(ec_key).unwrap();

    let private_der = private_key.private_key_to_der().unwrap();
    let public_der = private_key.public_key_to_der().unwrap();

    (private_der, public_der)
}

#[test]
fn test_eddsa_one_shot() {
    let provider = OpenSslCryptoProvider;

    // Ed25519 one-shot support (streaming not supported for EdDSA)
    let (private_der, public_der) = generate_ed25519_key();
    let signer = provider
        .signer_from_der(&private_der)
        .expect("Ed25519 signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("Ed25519 verifier creation should succeed");

    assert_eq!(signer.algorithm(), -8); // EdDSA
    assert_eq!(verifier.algorithm(), -8); // EdDSA
    assert_eq!(signer.key_type(), "OKP");

    let data = b"test data for EdDSA";
    let signature = signer.sign(data).expect("EdDSA signing should succeed");
    let is_valid = verifier
        .verify(data, &signature)
        .expect("EdDSA verification should succeed");
    assert!(is_valid, "EdDSA signature should be valid");
}

#[test]
fn test_invalid_key_data_error_paths() {
    let provider = OpenSslCryptoProvider;

    // Test with completely invalid DER
    let invalid_der = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let signer_result = provider.signer_from_der(&invalid_der);
    assert!(signer_result.is_err());

    let verifier_result = provider.verifier_from_der(&invalid_der);
    assert!(verifier_result.is_err());

    // Test with empty DER
    let empty_der = vec![];
    let signer_result = provider.signer_from_der(&empty_der);
    assert!(signer_result.is_err());

    let verifier_result = provider.verifier_from_der(&empty_der);
    assert!(verifier_result.is_err());
}

#[test]
fn test_streaming_signature_edge_cases() {
    let provider = OpenSslCryptoProvider;
    let (private_der, public_der) = generate_ec_p256_key();

    let signer = provider
        .signer_from_der(&private_der)
        .expect("signer creation should succeed");
    let verifier = provider
        .verifier_from_der(&public_der)
        .expect("verifier creation should succeed");

    // Test signing with no updates
    let mut sign_ctx = signer.sign_init().expect("sign_init should succeed");
    let signature = sign_ctx
        .finalize()
        .expect("finalize with no updates should succeed");

    // Verify empty signature
    let mut verify_ctx = verifier
        .verify_init(&signature)
        .expect("verify_init should succeed");
    let is_valid = verify_ctx
        .finalize()
        .expect("verify finalize should succeed");
    assert!(is_valid, "signature of empty data should be valid");

    // Test multiple small updates
    let mut sign_ctx = signer.sign_init().expect("sign_init should succeed");
    for i in 0..100 {
        sign_ctx.update(&[i as u8]).expect("update should succeed");
    }
    let signature = sign_ctx.finalize().expect("finalize should succeed");

    let mut verify_ctx = verifier
        .verify_init(&signature)
        .expect("verify_init should succeed");
    for i in 0..100 {
        verify_ctx
            .update(&[i as u8])
            .expect("update should succeed");
    }
    let is_valid = verify_ctx
        .finalize()
        .expect("verify finalize should succeed");
    assert!(is_valid, "multi-update signature should be valid");
}
