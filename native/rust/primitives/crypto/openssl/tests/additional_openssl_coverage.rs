// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for OpenSSL crypto: error paths, algorithm dispatch,
//! key type mismatches, Display/Debug traits, and ecdsa_format edge cases.

use cose_sign1_crypto_openssl::ecdsa_format::{der_to_fixed, fixed_to_der};
use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier, KeyType, OpenSslCryptoProvider, ES256};
use crypto_primitives::{CryptoError, CryptoProvider, CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

fn ec_p256_der() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    (pkey.private_key_to_der().unwrap(), pkey.public_key_to_der().unwrap())
}

fn rsa_2048_der() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    (pkey.private_key_to_der().unwrap(), pkey.public_key_to_der().unwrap())
}

#[test]
fn key_type_debug_and_clone() {
    let kt = KeyType::Ec;
    let debug_str = format!("{:?}", kt);
    assert!(debug_str.contains("Ec"));

    let kt2 = kt;
    assert_eq!(kt, kt2);

    assert_ne!(KeyType::Ec, KeyType::Rsa);
    assert_ne!(KeyType::Rsa, KeyType::Ed25519);

    assert_eq!(format!("{:?}", KeyType::Rsa), "Rsa");
    assert_eq!(format!("{:?}", KeyType::Ed25519), "Ed25519");
}

#[test]
fn crypto_error_display_variants() {
    let e1 = CryptoError::UnsupportedAlgorithm(999);
    assert!(e1.to_string().contains("999"));

    let e2 = CryptoError::InvalidKey("bad key".into());
    assert!(e2.to_string().contains("bad key"));

    let e3 = CryptoError::SigningFailed("oops".into());
    assert!(e3.to_string().contains("oops"));

    let e4 = CryptoError::VerificationFailed("nope".into());
    assert!(e4.to_string().contains("nope"));

    let e5 = CryptoError::UnsupportedOperation("nah".into());
    assert!(e5.to_string().contains("nah"));
}

#[test]
fn ec_key_with_rsa_algorithm_fails_signing() {
    let (priv_der, _) = ec_p256_der();
    // Construct signer with RSA algorithm constant on an EC key
    let signer = EvpSigner::from_der(&priv_der, -257); // RS256

    if let Ok(s) = signer {
        // Signing should fail because the key type doesn't match the algorithm
        let result = s.sign(b"payload");
        assert!(result.is_err());
    }
    // If construction itself fails, that's also acceptable
}

#[test]
fn unsupported_algorithm_error() {
    let (priv_der, _) = ec_p256_der();
    let result = EvpSigner::from_der(&priv_der, 999);
    // Construction may succeed but signing will fail with UnsupportedAlgorithm
    if let Ok(s) = result {
        let sign_result = s.sign(b"data");
        assert!(sign_result.is_err());
        if let Err(CryptoError::UnsupportedAlgorithm(alg)) = sign_result {
            assert_eq!(alg, 999);
        }
    }
}

#[test]
fn provider_name_is_openssl() {
    let provider = OpenSslCryptoProvider;
    assert_eq!(provider.name(), "OpenSSL");
}

#[test]
fn ed25519_does_not_support_streaming() {
    let pkey = PKey::generate_ed25519().unwrap();
    let priv_der = pkey.private_key_to_der().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    assert!(!signer.supports_streaming());

    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    assert!(!verifier.supports_streaming());
}

#[test]
fn ec_signer_supports_streaming() {
    let (priv_der, _) = ec_p256_der();
    let signer = EvpSigner::from_der(&priv_der, ES256).unwrap();
    assert!(signer.supports_streaming());
}

#[test]
fn der_to_fixed_single_byte_input() {
    // Minimal input that starts with SEQUENCE tag but is too short
    let result = der_to_fixed(&[0x30], 64);
    assert!(result.is_err());
}

#[test]
fn fixed_to_der_empty_input() {
    let result = fixed_to_der(&[]);
    // Empty is even-length (0), but has no components — implementation decides
    // Just verify it doesn't panic
    let _ = result;
}

#[test]
fn fixed_to_der_two_byte_minimum() {
    // Smallest even-length input: 2 bytes → 1 byte r, 1 byte s
    let result = fixed_to_der(&[0x01, 0x02]);
    assert!(result.is_ok());
    let der = result.unwrap();
    // Round-trip
    let back = der_to_fixed(&der, 2).unwrap();
    assert_eq!(back, vec![0x01, 0x02]);
}

#[test]
fn verify_with_wrong_signature_returns_false() {
    let (priv_der, pub_der) = ec_p256_der();
    let signer = EvpSigner::from_der(&priv_der, ES256).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, ES256).unwrap();

    let sig = signer.sign(b"hello").unwrap();
    // Corrupt signature
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0xFF;
    bad_sig[32] ^= 0xFF;

    let result = verifier.verify(b"hello", &bad_sig);
    match result {
        Ok(valid) => assert!(!valid),
        Err(_) => {} // verification error is also acceptable
    }
}

#[test]
fn sign_then_verify_roundtrip_rsa_rs384() {
    let (priv_der, pub_der) = rsa_2048_der();
    let signer = EvpSigner::from_der(&priv_der, -258).unwrap(); // RS384
    let verifier = EvpVerifier::from_der(&pub_der, -258).unwrap();

    let data = b"RS384 round-trip test";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}
