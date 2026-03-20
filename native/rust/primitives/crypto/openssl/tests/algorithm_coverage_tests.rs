// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for cose_sign1_crypto_openssl targeting uncovered
//! lines: algorithm error paths, streaming edge cases, key type detection.

use cose_sign1_crypto_openssl::ecdsa_format;
use cose_sign1_crypto_openssl::evp_signer::EvpSigner;
use cose_sign1_crypto_openssl::evp_verifier::EvpVerifier;
use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
use crypto_primitives::{CryptoProvider, CryptoSigner, CryptoVerifier};

use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

// ============================================================================
// Helper: generate keys
// ============================================================================

fn generate_ec_key(nid: Nid) -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(nid).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let private_der = pkey.private_key_to_der().unwrap();
    let public_der = pkey.public_key_to_der().unwrap();
    (private_der, public_der)
}

fn generate_rsa_key(bits: u32) -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(bits).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let private_der = pkey.private_key_to_der().unwrap();
    let public_der = pkey.public_key_to_der().unwrap();
    (private_der, public_der)
}

fn generate_ed25519_key() -> (Vec<u8>, Vec<u8>) {
    let pkey = PKey::generate_ed25519().unwrap();
    let private_der = pkey.private_key_to_der().unwrap();
    let public_der = pkey.public_key_to_der().unwrap();
    (private_der, public_der)
}

// ============================================================================
// All algorithm sign + verify roundtrip
// ============================================================================

#[test]
fn es256_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    let verifier = provider.verifier_from_der(&pub_der).unwrap();

    assert_eq!(signer.algorithm(), -7);
    let data = b"test data for ES256";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn es384_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_ec_key(Nid::SECP384R1);
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();

    assert_eq!(signer.algorithm(), -35);
    let data = b"test data for ES384";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn es512_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_ec_key(Nid::SECP521R1);
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();

    assert_eq!(signer.algorithm(), -36);
    let data = b"test data for ES512";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn ps256_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();

    assert_eq!(signer.algorithm(), -37);
    let data = b"test data for PS256";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn ps384_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -38).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();

    assert_eq!(signer.algorithm(), -38);
    let data = b"PS384 test data";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn ps512_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -39).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();

    assert_eq!(signer.algorithm(), -39);
    let data = b"PS512 test data";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn rs256_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();

    assert_eq!(signer.algorithm(), -257);
    let data = b"RS256 test data";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn rs384_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -258).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -258).unwrap();

    assert_eq!(signer.algorithm(), -258);
    let data = b"RS384 test data";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn rs512_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -259).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -259).unwrap();

    assert_eq!(signer.algorithm(), -259);
    let data = b"RS512 test data";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn eddsa_sign_verify_roundtrip() {
    let (priv_der, pub_der) = generate_ed25519_key();
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    let verifier = provider.verifier_from_der(&pub_der).unwrap();

    assert_eq!(signer.algorithm(), -8);
    let data = b"test data for EdDSA";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

// ============================================================================
// Error paths
// ============================================================================

#[test]
fn invalid_der_private_key() {
    let provider = OpenSslCryptoProvider;
    let result = provider.signer_from_der(b"not a valid DER key");
    assert!(result.is_err());
}

#[test]
fn invalid_der_public_key() {
    let provider = OpenSslCryptoProvider;
    let result = provider.verifier_from_der(b"not a valid DER key");
    assert!(result.is_err());
}

#[test]
fn corrupt_signature_verification_fails() {
    let (priv_der, pub_der) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    let verifier = provider.verifier_from_der(&pub_der).unwrap();

    let data = b"test data";
    let mut sig = signer.sign(data).unwrap();
    // Corrupt the signature
    if let Some(byte) = sig.last_mut() {
        *byte ^= 0xFF;
    }
    let result = verifier.verify(data, &sig).unwrap();
    assert!(!result);
}

#[test]
fn wrong_data_verification_fails() {
    let (priv_der, pub_der) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    let verifier = provider.verifier_from_der(&pub_der).unwrap();

    let data = b"original data";
    let sig = signer.sign(data).unwrap();
    let result = verifier.verify(b"different data", &sig).unwrap();
    assert!(!result);
}

// ============================================================================
// Streaming sign/verify
// ============================================================================

#[test]
fn es256_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    let verifier = provider.verifier_from_der(&pub_der).unwrap();

    assert!(signer.supports_streaming());
    assert!(verifier.supports_streaming());

    // Sign via streaming
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"hello ").unwrap();
    ctx.update(b"world").unwrap();
    let sig = ctx.finalize().unwrap();

    // Verify via streaming
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"hello ").unwrap();
    vctx.update(b"world").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

#[test]
fn ps256_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();

    assert!(signer.supports_streaming());

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming ").unwrap();
    ctx.update(b"rsa pss").unwrap();
    let sig = ctx.finalize().unwrap();

    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming ").unwrap();
    vctx.update(b"rsa pss").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

#[test]
fn eddsa_does_not_support_streaming() {
    let (priv_der, _) = generate_ed25519_key();
    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    assert!(!signer.supports_streaming());
}

// ============================================================================
// ECDSA format conversions
// ============================================================================

#[test]
fn der_to_fixed_and_back_p256() {
    let (priv_der, _) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();

    let data = b"ecdsa format test";
    let fixed_sig = signer.sign(data).unwrap();
    assert_eq!(fixed_sig.len(), 64); // ES256 → 32 + 32

    // Convert fixed→DER and back
    let der = ecdsa_format::fixed_to_der(&fixed_sig).unwrap();
    let back = ecdsa_format::der_to_fixed(&der, 64).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn der_to_fixed_and_back_p384() {
    let (priv_der, _) = generate_ec_key(Nid::SECP384R1);
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();

    let data = b"ecdsa format test p384";
    let fixed_sig = signer.sign(data).unwrap();
    assert_eq!(fixed_sig.len(), 96); // ES384 → 48 + 48

    let der = ecdsa_format::fixed_to_der(&fixed_sig).unwrap();
    let back = ecdsa_format::der_to_fixed(&der, 96).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn der_to_fixed_and_back_p521() {
    let (priv_der, _) = generate_ec_key(Nid::SECP521R1);
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();

    let data = b"ecdsa format test p521";
    let fixed_sig = signer.sign(data).unwrap();
    assert_eq!(fixed_sig.len(), 132); // ES512 → 66 + 66

    let der = ecdsa_format::fixed_to_der(&fixed_sig).unwrap();
    let back = ecdsa_format::der_to_fixed(&der, 132).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn fixed_to_der_odd_length() {
    // Signature must be even length (r and s halves)
    let result = ecdsa_format::fixed_to_der(&[0u8; 63]);
    assert!(result.is_err());
}

#[test]
fn der_to_fixed_invalid_der() {
    let result = ecdsa_format::der_to_fixed(&[0xFF, 0xFF, 0xFF], 64);
    assert!(result.is_err());
}

// ============================================================================
// Key type detection
// ============================================================================

#[test]
fn ec_key_type() {
    let (priv_der, _) = generate_ec_key(Nid::X9_62_PRIME256V1);
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    assert_eq!(signer.key_type(), "EC2");
}

#[test]
fn rsa_key_type() {
    let (priv_der, _) = generate_rsa_key(2048);
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    assert_eq!(signer.key_type(), "RSA");
}

#[test]
fn ed25519_key_type() {
    let (priv_der, _) = generate_ed25519_key();
    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    assert_eq!(signer.key_type(), "OKP");
}

// ============================================================================
// Provider name
// ============================================================================

#[test]
fn provider_name() {
    let provider = OpenSslCryptoProvider;
    assert_eq!(provider.name(), "OpenSSL");
}
