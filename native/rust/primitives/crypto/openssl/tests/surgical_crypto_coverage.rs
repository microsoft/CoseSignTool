// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical coverage tests for cose_sign1_crypto_openssl crate.
//!
//! Targets uncovered lines in:
//! - evp_signer.rs: from_der error path, sign_ecdsa/sign_rsa/sign_eddsa dispatch,
//!   streaming context for EC/RSA/Ed25519, key_type() for all types,
//!   supports_streaming() for Ed25519 (false), unsupported algorithm errors
//! - evp_verifier.rs: from_der, verify dispatch for all key types,
//!   streaming verify for EC/RSA/Ed25519, unsupported algorithm errors
//! - ecdsa_format.rs: long-form DER lengths, empty integers, large signatures,
//!   fixed_to_der long-form sequence lengths, integer_to_der edge cases
//! - evp_key.rs: from_ec, from_rsa, public_key(), detect unsupported key type error

use cose_sign1_crypto_openssl::ecdsa_format::{der_to_fixed, fixed_to_der};
use cose_sign1_crypto_openssl::evp_key::{EvpPrivateKey, EvpPublicKey, KeyType};
use cose_sign1_crypto_openssl::{EvpSigner, EvpVerifier, OpenSslCryptoProvider};
use crypto_primitives::{CryptoProvider, CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

// ============================================================================
// Key generation helpers
// ============================================================================

fn gen_ec_p256() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn gen_ec_p384() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn gen_ec_p521() -> (Vec<u8>, Vec<u8>) {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn gen_rsa_2048() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

fn gen_ed25519() -> (Vec<u8>, Vec<u8>) {
    let pkey = PKey::generate_ed25519().unwrap();
    (
        pkey.private_key_to_der().unwrap(),
        pkey.public_key_to_der().unwrap(),
    )
}

// ============================================================================
// evp_signer.rs — from_der, sign dispatch, key_type, supports_streaming
// Lines 40, 74, 90-93, 95, 112, 118-120, 127-131, 141-145, 147
// ============================================================================

#[test]
fn signer_from_der_ec_p256_sign_and_verify() {
    let (priv_der, pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap(); // ES256
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC2");
    assert!(signer.supports_streaming());
    assert!(signer.key_id().is_none());

    let data = b"hello world";
    let sig = signer.sign(data).unwrap();
    assert!(!sig.is_empty());

    // Verify with EvpVerifier
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_ec_p384_sign_and_verify() {
    let (priv_der, pub_der) = gen_ec_p384();
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap(); // ES384
    assert_eq!(signer.algorithm(), -35);
    assert_eq!(signer.key_type(), "EC2");

    let data = b"test data for P-384";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 96); // P-384: 2 * 48

    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_ec_p521_sign_and_verify() {
    let (priv_der, pub_der) = gen_ec_p521();
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap(); // ES512
    assert_eq!(signer.algorithm(), -36);
    assert_eq!(signer.key_type(), "EC2");

    let data = b"test data for P-521";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 132); // P-521: 2 * 66

    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_rs256_sign_and_verify() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap(); // RS256
    assert_eq!(signer.algorithm(), -257);
    assert_eq!(signer.key_type(), "RSA");
    assert!(signer.supports_streaming());

    let data = b"RSA test data";
    let sig = signer.sign(data).unwrap();
    assert!(!sig.is_empty());

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_rs384_sign_and_verify() {
    // Exercises sign_rsa with RS384 → get_digest_for_algorithm(-258) → SHA384
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -258).unwrap(); // RS384
    assert_eq!(signer.algorithm(), -258);

    let data = b"RSA-384 test data";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -258).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_rs512_sign_and_verify() {
    // Exercises sign_rsa with RS512 → get_digest_for_algorithm(-259) → SHA512
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -259).unwrap(); // RS512
    assert_eq!(signer.algorithm(), -259);

    let data = b"RSA-512 test data";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -259).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_ps256_sign_and_verify() {
    // Exercises sign_rsa PSS padding path → lines 232-236 in evp_signer
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap(); // PS256
    assert_eq!(signer.algorithm(), -37);

    let data = b"PS256 test data";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_ps384_sign_and_verify() {
    // Exercises PSS padding with PS384
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -38).unwrap(); // PS384

    let data = b"PS384 test data";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_rsa_ps512_sign_and_verify() {
    // Exercises PSS padding with PS512
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -39).unwrap(); // PS512

    let data = b"PS512 test data";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_ed25519_sign_and_verify() {
    // Exercises sign_eddsa path → lines 245-252
    let (priv_der, pub_der) = gen_ed25519();
    let signer = EvpSigner::from_der(&priv_der, -8).unwrap(); // EdDSA
    assert_eq!(signer.algorithm(), -8);
    assert_eq!(signer.key_type(), "OKP");
    assert!(!signer.supports_streaming()); // Ed25519 doesn't support streaming

    let data = b"Ed25519 test data";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 64); // Ed25519 signatures are 64 bytes

    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_from_der_invalid_key_returns_error() {
    // Exercises from_der error path → line 38 map_err
    let result = EvpSigner::from_der(&[0xDE, 0xAD, 0xBE, 0xEF], -7);
    assert!(result.is_err());
}

#[test]
fn signer_ec_unsupported_algorithm() {
    // Exercises sign_ecdsa unsupported algorithm → line 217
    let (priv_der, _) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -999).unwrap();
    let result = signer.sign(b"data");
    assert!(result.is_err());
}

// ============================================================================
// evp_signer.rs — streaming signing context
// Lines 90-93 (EvpSigningContext::new), 112, 118-131 (finalize for EC, unsupported alg)
// ============================================================================

#[test]
fn signer_streaming_ec_p256() {
    // Exercises EvpSigningContext for EC key: new, update, finalize
    let (priv_der, _pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"part1").unwrap();
    ctx.update(b"part2").unwrap();
    let sig = ctx.finalize().unwrap();
    assert!(!sig.is_empty());
    assert_eq!(sig.len(), 64); // ES256 fixed-length
}

#[test]
fn signer_streaming_ec_p384() {
    let (priv_der, _) = gen_ec_p384();
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming p384 data").unwrap();
    let sig = ctx.finalize().unwrap();
    assert_eq!(sig.len(), 96);
}

#[test]
fn signer_streaming_ec_p521() {
    let (priv_der, _) = gen_ec_p521();
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming p521 data").unwrap();
    let sig = ctx.finalize().unwrap();
    assert_eq!(sig.len(), 132);
}

#[test]
fn signer_streaming_rsa_rs256() {
    // Exercises streaming RSA path through create_signer
    let (priv_der, _) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming rsa data part 1").unwrap();
    ctx.update(b"streaming rsa data part 2").unwrap();
    let sig = ctx.finalize().unwrap();
    assert!(!sig.is_empty());
}

#[test]
fn signer_streaming_rsa_ps256() {
    // Exercises create_signer PSS padding branch → lines 159-164
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming ps256 data").unwrap();
    let sig = ctx.finalize().unwrap();
    assert!(!sig.is_empty());

    // Verify too
    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming ps256 data").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn signer_streaming_rsa_ps384() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -38).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming ps384 data").unwrap();
    let sig = ctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming ps384 data").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn signer_streaming_rsa_ps512() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -39).unwrap();

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"streaming ps512 data").unwrap();
    let sig = ctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming ps512 data").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn signer_streaming_ec_unsupported_algorithm_in_finalize() {
    // Exercises EvpSigningContext::finalize EC branch with unsupported alg → line 127
    // We create a signer with a valid EC key but an unsupported cose_algorithm
    // The create_signer will fail for unsupported alg, so sign_init will fail
    let (priv_der, _) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -999).unwrap();
    // sign_init calls create_signer which calls get_digest_for_algorithm(-999) → error
    let result = signer.sign_init();
    assert!(result.is_err());
}

// ============================================================================
// evp_verifier.rs — from_der, verify dispatch, streaming verify
// Lines 40, 84-87, 89, 105, 111, 119-120, 122-123, 125, 132-136, 139-143
// ============================================================================

#[test]
fn verifier_from_der_invalid_key_returns_error() {
    let result = EvpVerifier::from_der(&[0xDE, 0xAD], -7);
    assert!(result.is_err());
}

#[test]
fn verifier_ec_p256_properties() {
    let (_, pub_der) = gen_ec_p256();
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    assert_eq!(verifier.algorithm(), -7);
    assert!(verifier.supports_streaming());
}

#[test]
fn verifier_ed25519_properties() {
    let (_, pub_der) = gen_ed25519();
    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    assert_eq!(verifier.algorithm(), -8);
    assert!(!verifier.supports_streaming()); // Ed25519 doesn't support streaming
}

#[test]
fn verifier_verify_with_wrong_signature_returns_false() {
    let (_, pub_der) = gen_ec_p256();
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    // Wrong signature (right length for ES256)
    let bad_sig = vec![0u8; 64];
    let result = verifier.verify(b"some data", &bad_sig);
    // Should return Ok(false) or Err depending on OpenSSL
    match result {
        Ok(valid) => assert!(!valid, "Expected verification to fail"),
        Err(_) => {} // Also acceptable
    }
}

#[test]
fn verifier_rsa_unsupported_algorithm() {
    let (_, pub_der) = gen_rsa_2048();
    let verifier = EvpVerifier::from_der(&pub_der, -999).unwrap();
    let result = verifier.verify(b"data", b"sig");
    assert!(result.is_err());
}

#[test]
fn verifier_streaming_ec_p256() {
    // Exercises EvpVerifyingContext for EC: ECDSA fixed_to_der conversion
    let (priv_der, pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify ec data").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify ec data").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn verifier_streaming_ec_p384() {
    let (priv_der, pub_der) = gen_ec_p384();
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify ec384").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify ec384").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn verifier_streaming_ec_p521() {
    let (priv_der, pub_der) = gen_ec_p521();
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify ec521").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify ec521").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn verifier_streaming_rsa_rs256() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify rsa256").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify rsa256").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn verifier_streaming_rsa_rs384() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -258).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify rsa384").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -258).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify rsa384").unwrap();
    assert!(vctx.finalize().unwrap());
}

#[test]
fn verifier_streaming_rsa_rs512() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -259).unwrap();

    let mut sctx = signer.sign_init().unwrap();
    sctx.update(b"streaming verify rsa512").unwrap();
    let sig = sctx.finalize().unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -259).unwrap();
    let mut vctx = verifier.verify_init(&sig).unwrap();
    vctx.update(b"streaming verify rsa512").unwrap();
    assert!(vctx.finalize().unwrap());
}

// ============================================================================
// evp_verifier.rs — verify_ecdsa, verify_rsa, verify_eddsa direct paths
// Lines 194-196, 201-202, 205, 215-216, 218-220, 223-224, 226, 231, 241-242, 245
// ============================================================================

#[test]
fn verify_ecdsa_p256_direct() {
    let (priv_der, pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    let data = b"direct ecdsa verify";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_ecdsa_p384_direct() {
    let (priv_der, pub_der) = gen_ec_p384();
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();
    let data = b"direct ecdsa p384 verify";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_ecdsa_p521_direct() {
    let (priv_der, pub_der) = gen_ec_p521();
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();
    let data = b"direct ecdsa p521 verify";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_rsa_ps256_direct() {
    // Exercises verify_rsa PSS padding path → lines 221-226
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -37).unwrap();
    let data = b"direct rsa ps256 verify";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -37).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_rsa_ps384_direct() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -38).unwrap();
    let data = b"direct rsa ps384";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -38).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_rsa_ps512_direct() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -39).unwrap();
    let data = b"direct rsa ps512";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -39).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_eddsa_direct() {
    let (priv_der, pub_der) = gen_ed25519();
    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    let data = b"direct eddsa verify";
    let sig = signer.sign(data).unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verify_ecdsa_wrong_data_returns_false() {
    let (priv_der, pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    let sig = signer.sign(b"original data").unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    let result = verifier.verify(b"tampered data", &sig);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn verify_rsa_wrong_data_returns_false() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    let sig = signer.sign(b"original").unwrap();

    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    let result = verifier.verify(b"tampered", &sig);
    // RSA verify with wrong data: OpenSSL returns Ok(false) or Err
    match result {
        Ok(valid) => assert!(!valid, "Expected verification to fail"),
        Err(_) => {} // Also acceptable
    }
}

// ============================================================================
// ecdsa_format.rs — edge cases
// Lines 14, 29, 81, 93, 107-111, 149-154, 171-175, 210-218
// ============================================================================

#[test]
fn ecdsa_der_to_fixed_too_short() {
    // Exercises line 56: DER signature too short
    let result = der_to_fixed(&[0x30, 0x01, 0x02], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too short"));
}

#[test]
fn ecdsa_der_to_fixed_bad_sequence_tag() {
    // Exercises line 60: missing SEQUENCE tag
    let result = der_to_fixed(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("SEQUENCE"));
}

#[test]
fn ecdsa_der_to_fixed_length_mismatch() {
    // Exercises line 68: DER signature length mismatch
    let result = der_to_fixed(&[0x30, 0xFF, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_der_to_fixed_missing_r_integer_tag() {
    // Exercises line 73: missing INTEGER tag for r
    let result = der_to_fixed(&[0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("INTEGER tag for r"));
}

#[test]
fn ecdsa_der_to_fixed_r_out_of_bounds() {
    // Exercises line 81: r value out of bounds
    let result = der_to_fixed(&[0x30, 0x06, 0x02, 0xFF, 0x01, 0x02, 0x01, 0x02], 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_der_to_fixed_missing_s_integer_tag() {
    // Exercises line 89: missing INTEGER tag for s
    let result = der_to_fixed(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02], 64);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("INTEGER tag for s"));
}

#[test]
fn ecdsa_der_to_fixed_s_out_of_bounds() {
    // Exercises line 97: s value out of bounds
    let data = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0xFF, 0x02];
    let result = der_to_fixed(&data, 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_der_to_fixed_with_leading_zero_on_r() {
    // Exercises copy_integer_to_fixed with leading 0x00 byte (DER positive padding)
    // Build a DER signature where r has a leading 0x00
    let mut der = vec![
        0x30, 0x45, // SEQUENCE, length 69
        0x02, 0x21, // INTEGER, length 33 (32 + 1 leading zero)
        0x00, // leading zero
    ];
    der.extend_from_slice(&[0x01; 32]); // 32 bytes of r
    der.push(0x02); // INTEGER tag
    der.push(0x20); // length 32
    der.extend_from_slice(&[0x02; 32]); // 32 bytes of s
    let result = der_to_fixed(&der, 64);
    assert!(result.is_ok());
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 64);
}

#[test]
fn ecdsa_der_to_fixed_integer_too_large() {
    // Exercises copy_integer_to_fixed line 171: integer too large for fixed field
    // Build a DER where r has 33 non-zero bytes (no leading 0x00 to strip)
    // Since the first byte is 0x7F (not high-bit set), there's no leading zero to strip,
    // so 33 bytes won't fit in 32-byte field.
    let r_bytes: Vec<u8> = vec![0x7F; 33]; // 33 bytes, positive (no 0x00 prefix)
    let s_bytes: Vec<u8> = vec![0x01]; // 1 byte for s
    let inner_len = 2 + r_bytes.len() + 2 + s_bytes.len(); // tag+len + r + tag+len + s
    let mut der = vec![0x30, inner_len as u8];
    der.push(0x02);
    der.push(r_bytes.len() as u8);
    der.extend_from_slice(&r_bytes);
    der.push(0x02);
    der.push(s_bytes.len() as u8);
    der.extend_from_slice(&s_bytes);

    let result = der_to_fixed(&der, 64); // 32 bytes per component
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
}

#[test]
fn ecdsa_fixed_to_der_odd_length() {
    // Exercises fixed_to_der line 126: odd length
    let result = fixed_to_der(&[0x01, 0x02, 0x03]);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("even"));
}

#[test]
fn ecdsa_fixed_to_der_and_back_p256() {
    // Round-trip test: fixed → DER → fixed
    let fixed_sig = vec![0x01; 64]; // 32 + 32 for P-256
    let der = fixed_to_der(&fixed_sig).unwrap();
    assert!(der[0] == 0x30); // SEQUENCE tag
    let back = der_to_fixed(&der, 64).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn ecdsa_fixed_to_der_and_back_p384() {
    let fixed_sig = vec![0x01; 96]; // 48 + 48 for P-384
    let der = fixed_to_der(&fixed_sig).unwrap();
    let back = der_to_fixed(&der, 96).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn ecdsa_fixed_to_der_and_back_p521() {
    let fixed_sig = vec![0x01; 132]; // 66 + 66 for P-521
    let der = fixed_to_der(&fixed_sig).unwrap();
    let back = der_to_fixed(&der, 132).unwrap();
    assert_eq!(back, fixed_sig);
}

#[test]
fn ecdsa_fixed_to_der_high_bit_set() {
    // Exercises integer_to_der with needs_padding=true: high bit set
    let mut fixed = vec![0x00; 64];
    fixed[0] = 0x80; // High bit set on r → needs leading 0x00 in DER
    fixed[32] = 0x80; // High bit set on s too
    let der = fixed_to_der(&fixed).unwrap();
    // Verify the DER has 0x00 padding for both integers
    assert!(der.len() > 64 + 4); // extra bytes for tags + padding
}

#[test]
fn ecdsa_fixed_to_der_with_leading_zeros() {
    // Exercises integer_to_der leading zero trimming
    let mut fixed = vec![0x00; 64];
    fixed[31] = 0x01; // r = 1 (31 leading zeros)
    fixed[63] = 0x01; // s = 1 (31 leading zeros)
    let der = fixed_to_der(&fixed).unwrap();
    let back = der_to_fixed(&der, 64).unwrap();
    assert_eq!(back, fixed);
}

#[test]
fn ecdsa_integer_to_der_all_zeros() {
    // Exercises integer_to_der where input is all zeros → should produce DER INTEGER for 0
    let fixed = vec![0x00; 64];
    let der = fixed_to_der(&fixed).unwrap();
    // Both r and s are 0; DER should encode as small integers
    assert!(der.len() < 64 + 10);
}

#[test]
fn ecdsa_der_long_form_length() {
    // Exercises parse_der_length long form: first byte & 0x7F > 0
    // P-521 can produce signatures with >127 byte total length
    // Build a real DER with long-form sequence length
    let mut der = vec![0x30, 0x81]; // SEQUENCE, long form: 1 byte follows
    let inner_len: u8 = 136; // 2 * 66 + tag/len overhead
    der.push(inner_len);
    // r INTEGER with 66 bytes
    der.push(0x02);
    der.push(0x42); // 66
    der.extend_from_slice(&[0x01; 66]);
    // s INTEGER with 66 bytes
    der.push(0x02);
    der.push(0x42); // 66
    der.extend_from_slice(&[0x02; 66]);
    let result = der_to_fixed(&der, 132);
    assert!(result.is_ok());
    let fixed = result.unwrap();
    assert_eq!(fixed.len(), 132);
}

#[test]
fn ecdsa_der_length_field_empty() {
    // Exercises parse_der_length line 13: empty data
    let result = der_to_fixed(&[0x30], 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_der_long_form_invalid_num_bytes() {
    // Exercises parse_der_length line 24: num_len_bytes == 0 → invalid
    let result = der_to_fixed(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02], 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_der_long_form_truncated() {
    // Exercises parse_der_length line 29: long-form length field truncated
    // 0x82 means 2 length bytes follow, but we only have 1
    let result = der_to_fixed(&[0x30, 0x82, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01], 64);
    assert!(result.is_err());
}

#[test]
fn ecdsa_fixed_to_der_large_components() {
    // Exercises fixed_to_der long-form sequence length (total_len >= 128)
    // P-521: 66 bytes per component → when high bits set, DER integers may be 67 bytes each
    let fixed = vec![0xFF; 132]; // All 0xFF → high bits set → each needs padding
    let der = fixed_to_der(&fixed).unwrap();
    // Sequence total will be > 128, triggering long-form length
    assert!(der[1] == 0x81 || der[1] >= 0x80); // long form indicator
}

// ============================================================================
// evp_key.rs — from_ec, from_rsa, public_key, detect error paths
// Lines 59, 66, 76, 98-100, 102-103, 117, 124, 134, 168-169, 188-189
// ============================================================================

#[test]
fn evp_private_key_from_ec() {
    // Exercises EvpPrivateKey::from_ec → line 64-70
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let key = EvpPrivateKey::from_ec(ec).unwrap();
    assert_eq!(key.key_type(), KeyType::Ec);
}

#[test]
fn evp_private_key_from_rsa() {
    // Exercises EvpPrivateKey::from_rsa → lines 74-80
    let rsa = Rsa::generate(2048).unwrap();
    let key = EvpPrivateKey::from_rsa(rsa).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa);
}

#[test]
fn evp_private_key_from_pkey_ec() {
    // Exercises EvpPrivateKey::from_pkey → detect_key_type_private → EC branch
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    let key = EvpPrivateKey::from_pkey(pkey).unwrap();
    assert_eq!(key.key_type(), KeyType::Ec);
}

#[test]
fn evp_private_key_from_pkey_rsa() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let key = EvpPrivateKey::from_pkey(pkey).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa);
}

#[test]
fn evp_private_key_from_pkey_ed25519() {
    // Exercises detect_key_type_private Ed25519 branch → line 158-159
    let pkey = PKey::generate_ed25519().unwrap();
    let key = EvpPrivateKey::from_pkey(pkey).unwrap();
    assert_eq!(key.key_type(), KeyType::Ed25519);
}

#[test]
fn evp_private_key_public_key_extraction() {
    // Exercises EvpPrivateKey::public_key → lines 96-105
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let key = EvpPrivateKey::from_ec(ec).unwrap();
    let pub_key = key.public_key().unwrap();
    assert_eq!(pub_key.key_type(), KeyType::Ec);
}

#[test]
fn evp_private_key_public_key_rsa() {
    let rsa = Rsa::generate(2048).unwrap();
    let key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let pub_key = key.public_key().unwrap();
    assert_eq!(pub_key.key_type(), KeyType::Rsa);
}

#[test]
fn evp_private_key_public_key_ed25519() {
    let pkey = PKey::generate_ed25519().unwrap();
    let key = EvpPrivateKey::from_pkey(pkey).unwrap();
    let pub_key = key.public_key().unwrap();
    assert_eq!(pub_key.key_type(), KeyType::Ed25519);
}

#[test]
fn evp_public_key_from_ec() {
    // Exercises EvpPublicKey::from_ec → lines 122-129
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_private = EcKey::generate(&group).unwrap();
    let ec_public = EcKey::from_public_key(ec_private.group(), ec_private.public_key()).unwrap();
    let key = EvpPublicKey::from_ec(ec_public).unwrap();
    assert_eq!(key.key_type(), KeyType::Ec);
}

#[test]
fn evp_public_key_from_rsa() {
    // Exercises EvpPublicKey::from_rsa → lines 132-138
    let rsa_private = Rsa::generate(2048).unwrap();
    let rsa_public = Rsa::from_public_components(
        rsa_private.n().to_owned().unwrap(),
        rsa_private.e().to_owned().unwrap(),
    )
    .unwrap();
    let key = EvpPublicKey::from_rsa(rsa_public).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa);
}

#[test]
fn evp_public_key_from_pkey_ed25519() {
    // Exercises detect_key_type_public Ed25519 branch → line 178-179
    let pkey = PKey::generate_ed25519().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    let key = EvpPublicKey::from_pkey(pub_pkey).unwrap();
    assert_eq!(key.key_type(), KeyType::Ed25519);
}

#[test]
fn evp_key_pkey_accessor() {
    // Exercises pkey() accessors
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let key = EvpPrivateKey::from_ec(ec).unwrap();
    let _pkey = key.pkey(); // Should not panic
    let pub_key = key.public_key().unwrap();
    let _pub_pkey = pub_key.pkey(); // Should not panic
}

// ============================================================================
// provider.rs — OpenSslCryptoProvider signer_from_der, verifier_from_der
// ============================================================================

#[test]
fn provider_signer_from_der_ec() {
    let (priv_der, _) = gen_ec_p256();
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    assert_eq!(signer.algorithm(), -7); // ES256
}

#[test]
fn provider_signer_from_der_rsa() {
    let (priv_der, _) = gen_rsa_2048();
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    assert_eq!(signer.algorithm(), -257); // RS256
}

#[test]
fn provider_signer_from_der_ed25519() {
    let (priv_der, _) = gen_ed25519();
    let provider = OpenSslCryptoProvider;
    let signer = provider.signer_from_der(&priv_der).unwrap();
    assert_eq!(signer.algorithm(), -8); // EdDSA
}

#[test]
fn provider_signer_from_der_invalid() {
    let provider = OpenSslCryptoProvider;
    let result = provider.signer_from_der(&[0xDE, 0xAD]);
    assert!(result.is_err());
}

#[test]
fn provider_verifier_from_der_ec() {
    let (_, pub_der) = gen_ec_p256();
    let provider = OpenSslCryptoProvider;
    let verifier = provider.verifier_from_der(&pub_der).unwrap();
    assert_eq!(verifier.algorithm(), -7);
}

#[test]
fn provider_verifier_from_der_rsa() {
    let (_, pub_der) = gen_rsa_2048();
    let provider = OpenSslCryptoProvider;
    let verifier = provider.verifier_from_der(&pub_der).unwrap();
    assert_eq!(verifier.algorithm(), -257);
}

#[test]
fn provider_verifier_from_der_ed25519() {
    let (_, pub_der) = gen_ed25519();
    let provider = OpenSslCryptoProvider;
    let verifier = provider.verifier_from_der(&pub_der).unwrap();
    assert_eq!(verifier.algorithm(), -8);
}

#[test]
fn provider_verifier_from_der_invalid() {
    let provider = OpenSslCryptoProvider;
    let result = provider.verifier_from_der(&[0xDE, 0xAD]);
    assert!(result.is_err());
}

#[test]
fn provider_name() {
    let provider = OpenSslCryptoProvider;
    assert_eq!(provider.name(), "OpenSSL");
}

// ============================================================================
// End-to-end sign+verify for every algorithm using EvpSigner/EvpVerifier
// This ensures both sign_* and verify_* dispatch paths are hit
// ============================================================================

#[test]
fn end_to_end_es256() {
    let (priv_der, pub_der) = gen_ec_p256();
    let signer = EvpSigner::from_der(&priv_der, -7).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -7).unwrap();
    let data = b"e2e es256";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn end_to_end_es384() {
    let (priv_der, pub_der) = gen_ec_p384();
    let signer = EvpSigner::from_der(&priv_der, -35).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -35).unwrap();
    let data = b"e2e es384";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn end_to_end_es512() {
    let (priv_der, pub_der) = gen_ec_p521();
    let signer = EvpSigner::from_der(&priv_der, -36).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -36).unwrap();
    let data = b"e2e es512";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn end_to_end_rs256() {
    let (priv_der, pub_der) = gen_rsa_2048();
    let signer = EvpSigner::from_der(&priv_der, -257).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -257).unwrap();
    let data = b"e2e rs256";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn end_to_end_eddsa() {
    let (priv_der, pub_der) = gen_ed25519();
    let signer = EvpSigner::from_der(&priv_der, -8).unwrap();
    let verifier = EvpVerifier::from_der(&pub_der, -8).unwrap();
    let data = b"e2e eddsa";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}
