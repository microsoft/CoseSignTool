// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for PEM-based key loading in EvpSigner, EvpVerifier, and
//! OpenSslCryptoProvider.

use cose_sign1_crypto_openssl::evp_signer::EvpSigner;
use cose_sign1_crypto_openssl::evp_verifier::EvpVerifier;
use cose_sign1_crypto_openssl::provider::OpenSslCryptoProvider;
use crypto_primitives::{CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;

/// COSE algorithm identifier for ES256 (ECDSA w/ SHA-256).
const ES256: i64 = -7;

// ---------------------------------------------------------------------------
// EvpSigner::from_pem
// ---------------------------------------------------------------------------

#[test]
fn signer_from_pem_ec_p256_signs_data() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let pem = pkey.private_key_to_pem_pkcs8().unwrap();

    let signer = EvpSigner::from_pem(&pem, ES256).expect("from_pem should succeed");
    assert_eq!(signer.algorithm(), ES256);

    let data = b"hello world";
    let signature = signer.sign(data).expect("sign should succeed");
    assert!(!signature.is_empty(), "signature must not be empty");
}

#[test]
fn signer_from_pem_invalid_pem_returns_error() {
    let bad_pem = b"not a valid PEM at all";
    let result = EvpSigner::from_pem(bad_pem, ES256);
    assert!(result.is_err(), "invalid PEM should produce an error");

    let err_msg = format!("{}", result.err().expect("should be error"));
    assert!(
        err_msg.contains("PEM") || err_msg.contains("parse") || err_msg.contains("key"),
        "error message should mention PEM/parse/key, got: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// EvpVerifier::from_pem
// ---------------------------------------------------------------------------

#[test]
fn verifier_from_pem_ec_p256_verifies_signature() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    // Sign with private key
    let private_pem = pkey.private_key_to_pem_pkcs8().unwrap();
    let signer = EvpSigner::from_pem(&private_pem, ES256).unwrap();
    let data = b"test payload for verification";
    let signature = signer.sign(data).unwrap();

    // Verify with public key PEM
    let public_pem = pkey.public_key_to_pem().unwrap();
    let verifier = EvpVerifier::from_pem(&public_pem, ES256).expect("from_pem should succeed");
    assert_eq!(verifier.algorithm(), ES256);

    let valid = verifier.verify(data, &signature).expect("verify should succeed");
    assert!(valid, "signature should verify successfully");
}

#[test]
fn verifier_from_pem_rejects_wrong_data() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let private_pem = pkey.private_key_to_pem_pkcs8().unwrap();
    let signer = EvpSigner::from_pem(&private_pem, ES256).unwrap();
    let signature = signer.sign(b"original data").unwrap();

    let public_pem = pkey.public_key_to_pem().unwrap();
    let verifier = EvpVerifier::from_pem(&public_pem, ES256).unwrap();
    let valid = verifier.verify(b"tampered data", &signature).unwrap();
    assert!(!valid, "signature should NOT verify against tampered data");
}

#[test]
fn verifier_from_pem_invalid_pem_returns_error() {
    let bad_pem = b"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----\n";
    let result = EvpVerifier::from_pem(bad_pem, ES256);
    assert!(result.is_err(), "invalid PEM should produce an error");
}

// ---------------------------------------------------------------------------
// OpenSslCryptoProvider::signer_from_pem / verifier_from_pem
// ---------------------------------------------------------------------------

#[test]
fn provider_signer_from_pem_auto_detects_es256() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let pem = pkey.private_key_to_pem_pkcs8().unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider
        .signer_from_pem(&pem)
        .expect("signer_from_pem should succeed");

    assert_eq!(signer.algorithm(), ES256);

    let data = b"provider signer test";
    let signature = signer.sign(data).expect("sign should succeed");
    assert!(!signature.is_empty());
}

#[test]
fn provider_verifier_from_pem_auto_detects_es256() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let public_pem = pkey.public_key_to_pem().unwrap();

    let provider = OpenSslCryptoProvider;
    let verifier = provider
        .verifier_from_pem(&public_pem)
        .expect("verifier_from_pem should succeed");

    assert_eq!(verifier.algorithm(), ES256);
}

#[test]
fn provider_roundtrip_sign_verify_via_pem() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let private_pem = pkey.private_key_to_pem_pkcs8().unwrap();
    let public_pem = pkey.public_key_to_pem().unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_pem(&private_pem).unwrap();
    let verifier = provider.verifier_from_pem(&public_pem).unwrap();

    let payload = b"roundtrip via provider PEM";
    let signature = signer.sign(payload).unwrap();
    let valid = verifier.verify(payload, &signature).unwrap();
    assert!(valid, "provider PEM roundtrip must verify");
}

#[test]
fn provider_signer_from_pem_invalid_returns_error() {
    let provider = OpenSslCryptoProvider;
    let result = provider.signer_from_pem(b"junk");
    assert!(result.is_err());
}

#[test]
fn provider_verifier_from_pem_invalid_returns_error() {
    let provider = OpenSslCryptoProvider;
    let result = provider.verifier_from_pem(b"junk");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// RSA PEM support via provider (covers detect_algorithm for RSA keys)
// ---------------------------------------------------------------------------

#[test]
fn provider_rsa_pem_roundtrip() {
    let rsa_key = openssl::rsa::Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa_key).unwrap();

    let private_pem = pkey.private_key_to_pem_pkcs8().unwrap();
    let public_pem = pkey.public_key_to_pem().unwrap();

    let provider = OpenSslCryptoProvider;
    let signer = provider
        .signer_from_pem(&private_pem)
        .expect("RSA signer_from_pem should succeed");
    let verifier = provider
        .verifier_from_pem(&public_pem)
        .expect("RSA verifier_from_pem should succeed");

    let data = b"rsa pem roundtrip test";
    let signature = signer.sign(data).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid, "RSA PEM roundtrip must verify");
}
