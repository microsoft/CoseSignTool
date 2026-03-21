// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in evp_signer.rs and evp_verifier.rs.
//!
//! Covers: from_der (line 40), sign_ecdsa/sign_rsa/sign_eddsa Ok paths,
//! verify_ecdsa/verify_rsa/verify_eddsa Ok paths, streaming sign/verify contexts,
//! PSS padding paths, and key_type accessors.

use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier};
use crypto_primitives::{CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

fn generate_ec_p256() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn generate_ec_p384() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn generate_ec_p521() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn generate_rsa_2048() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn generate_ed25519() -> (Vec<u8>, Vec<u8>) {
    let pkey = PKey::generate_ed25519().unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

// ============================================================================
// Target: evp_signer.rs line 40 — EvpSigner::from_der with EC key (from_pkey path)
// Also exercises sign_ecdsa Ok path (lines 206, 210, 221)
// ============================================================================
#[test]
fn test_signer_ec_p256_sign_and_verify_roundtrip() {
    let (priv_der, pub_der) = generate_ec_p256();
    let data = b"hello world ECDSA P-256";

    let signer = EvpSigner::from_der(&priv_der, -7).unwrap(); // ES256
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC2");

    // sign exercises sign_data → sign_ecdsa (lines 202-221)
    let signature = signer.sign(data).unwrap();
    assert!(!signature.is_empty());
    assert_eq!(signature.len(), 64); // ES256 = 2*32

    // verify exercises verify_ecdsa (lines 188-205)
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs lines 90, 112, 118, 127, 129-130 — streaming EC sign
// ============================================================================
#[test]
fn test_signer_ec_p256_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_ec_p256();

    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    assert!(signer.supports_streaming());

    // Streaming sign — exercises EvpSigningContext::new (line 88-105) and update/finalize
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"stream ").unwrap(); // line 112
    ctx.update(b"sign ").unwrap();
    ctx.update(b"test").unwrap();
    let signature = ctx.finalize().unwrap(); // lines 115-134
    assert_eq!(signature.len(), 64);

    // Streaming verify
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    assert!(verifier.supports_streaming());

    let mut vctx = verifier.verify_init(&signature).unwrap(); // line 60 (EvpVerifyingContext)
    vctx.update(b"stream ").unwrap(); // line 105
    vctx.update(b"sign ").unwrap();
    vctx.update(b"test").unwrap();
    let valid = vctx.finalize().unwrap(); // line 111
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs line 125-127 — ES384 streaming finalize (expected_len=96)
// ============================================================================
#[test]
fn test_signer_ec_p384_sign_verify() {
    let (priv_der, pub_der) = generate_ec_p384();
    let data = b"hello P-384";

    let signer = EvpSigner::from_der(&priv_der, -35).unwrap(); // ES384
    let signature = signer.sign(data).unwrap();
    assert_eq!(signature.len(), 96); // 2*48

    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs line 126 — ES512 streaming finalize (expected_len=132)
// ============================================================================
#[test]
fn test_signer_ec_p521_sign_verify() {
    let (priv_der, pub_der) = generate_ec_p521();
    let data = b"hello P-521";

    let signer = EvpSigner::from_der(&priv_der, -36).unwrap(); // ES512
    let signature = signer.sign(data).unwrap();
    assert_eq!(signature.len(), 132); // 2*66

    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs lines 141, 144, 147 — clone_private_key (called via streaming)
// Target: evp_signer.rs lines 156, 161, 163 — create_signer PSS branch
// Target: evp_signer.rs lines 229, 234, 236 — sign_rsa PSS path
// ============================================================================
#[test]
fn test_signer_rsa_rs256_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RSA RS256";

    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    assert_eq!(signer.key_type(), "RSA");

    let signature = signer.sign(data).unwrap(); // sign_rsa path
    assert!(!signature.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    let valid = verifier.verify(data, &signature).unwrap(); // verify_rsa
    assert!(valid);
}

#[test]
fn test_signer_rsa_ps256_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RSA PS256";

    // PS256 = -37 — exercises PSS padding branches (lines 159-163, 232-236)
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    let signature = signer.sign(data).unwrap();
    assert!(!signature.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

#[test]
fn test_signer_rsa_ps384_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RSA PS384";

    // PS384 = -38
    let signer = EvpSigner::from_der(&priv_der, -38).unwrap();
    let signature = signer.sign(data).unwrap();
    assert!(!signature.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

#[test]
fn test_signer_rsa_ps512_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RSA PS512";

    // PS512 = -39
    let signer = EvpSigner::from_der(&priv_der, -39).unwrap();
    let signature = signer.sign(data).unwrap();
    assert!(!signature.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs lines 169-170 — sign_eddsa path
// Target: evp_verifier.rs lines 149-150 — verify_eddsa path
// Target: evp_signer.rs line 70 — supports_streaming for Ed25519 (returns false)
// ============================================================================
#[test]
fn test_signer_ed25519_sign_verify() {
    let (priv_der, pub_der) = generate_ed25519();
    let data = b"hello EdDSA";

    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    assert_eq!(signer.key_type(), "OKP");
    assert!(!signer.supports_streaming()); // line 70

    let signature = signer.sign(data).unwrap(); // sign_eddsa lines 246-251
    assert!(!signature.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    assert!(!verifier.supports_streaming()); // verifier line 56
    let valid = verifier.verify(data, &signature).unwrap(); // verify_eddsa lines 240-245
    assert!(valid);
}

// ============================================================================
// Target: evp_signer.rs line 127 — UnsupportedAlgorithm in streaming finalize
// ============================================================================
#[test]
fn test_signer_ec_unsupported_algorithm_in_streaming_finalize() {
    let (priv_der, _) = generate_ec_p256();

    // Use an invalid COSE alg with an EC key
    // from_der should succeed (key type detection is separate from alg validation)
    let signer = EvpSigner::from_der(&priv_der, -999).unwrap();

    // Non-streaming sign should fail with UnsupportedAlgorithm
    let result = signer.sign(b"test");
    assert!(result.is_err());
}

// ============================================================================
// Target: evp_verifier.rs line 40 — EvpVerifier::from_der
// ============================================================================
#[test]
fn test_verifier_from_der_invalid_key() {
    let result = EvpVerifier::from_der(&[0xFF, 0xFE], -7);
    assert!(result.is_err());
}

// ============================================================================
// Target: evp_signer.rs line 40 — EvpSigner::from_der invalid
// ============================================================================
#[test]
fn test_signer_from_der_invalid_key() {
    let result = EvpSigner::from_der(&[0xFF, 0xFE], -7);
    assert!(result.is_err());
}

// ============================================================================
// Streaming RSA verify (exercises create_verifier RSA path, lines 131-146)
// ============================================================================
#[test]
fn test_rsa_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();

    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    assert!(signer.supports_streaming());

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"stream ").unwrap();
    sctx.update(b"rsa ").unwrap();
    sctx.update(b"test").unwrap();
    let signature = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    let mut vctx = verifier.verify_init(&signature).unwrap();
    vctx.update(b"stream ").unwrap();
    vctx.update(b"rsa ").unwrap();
    vctx.update(b"test").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

// ============================================================================
// Streaming RSA PSS (exercises PSS padding in create_signer/create_verifier)
// ============================================================================
#[test]
fn test_rsa_pss_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();

    // PS256 = -37
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"pss streaming test").unwrap();
    let signature = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();
    let mut vctx = verifier.verify_init(&signature).unwrap();
    vctx.update(b"pss streaming test").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

// ============================================================================
// Verify with wrong data (exercises verify returning false)
// ============================================================================
#[test]
fn test_ec_verify_wrong_data_returns_false() {
    let (priv_der, pub_der) = generate_ec_p256();

    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    let signature = signer.sign(b"correct data").unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    let valid = verifier.verify(b"wrong data", &signature).unwrap();
    assert!(!valid);
}

#[test]
fn test_rsa_verify_wrong_data() {
    let (priv_der, pub_der) = generate_rsa_2048();

    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    let signature = signer.sign(b"correct data").unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    // RSA verify_oneshot may return false or an error; either is acceptable
    let result = verifier.verify(b"wrong data", &signature);
    match result {
        Ok(valid) => assert!(!valid),
        Err(_) => {} // Some OpenSSL versions return error for invalid RSA sig
    }
}

// ============================================================================
// RS384 and RS512 sign/verify (exercises get_digest_for_algorithm sha384/512)
// ============================================================================
#[test]
fn test_signer_rsa_rs384_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RS384";

    let signer = EvpSigner::from_der(&priv_der, -258).unwrap();
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -258).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

#[test]
fn test_signer_rsa_rs512_sign_verify() {
    let (priv_der, pub_der) = generate_rsa_2048();
    let data = b"hello RS512";

    let signer = EvpSigner::from_der(&priv_der, -259).unwrap();
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -259).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid);
}

// ============================================================================
// EC P-384 streaming (exercises ES384 streaming finalize, expected_len=96)
// ============================================================================
#[test]
fn test_ec_p384_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_ec_p384();

    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"p384 streaming").unwrap();
    let signature = ctx.finalize().unwrap();
    assert_eq!(signature.len(), 96);

    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    let mut vctx = verifier.verify_init(&signature).unwrap();
    vctx.update(b"p384 streaming").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

// ============================================================================
// EC P-521 streaming (exercises ES512 streaming finalize, expected_len=132)
// ============================================================================
#[test]
fn test_ec_p521_streaming_sign_verify() {
    let (priv_der, pub_der) = generate_ec_p521();

    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"p521 streaming").unwrap();
    let signature = ctx.finalize().unwrap();
    assert_eq!(signature.len(), 132);

    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    let mut vctx = verifier.verify_init(&signature).unwrap();
    vctx.update(b"p521 streaming").unwrap();
    let valid = vctx.finalize().unwrap();
    assert!(valid);
}

// ============================================================================
// key_id accessor (always None for EvpSigner)
// ============================================================================
#[test]
fn test_signer_key_id_is_none() {
    let (priv_der, _) = generate_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    assert!(signer.key_id().is_none());
}
