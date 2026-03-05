// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests targeting specific uncovered lines in evp_key.rs,
//! evp_signer.rs, evp_verifier.rs, and ecdsa_format.rs.
//!
//! Focuses on code paths not exercised by existing tests:
//! - EvpPrivateKey::from_ec / from_rsa constructors (evp_key.rs)
//! - EvpPublicKey::from_ec / from_rsa constructors (evp_key.rs)
//! - EvpPrivateKey::public_key() extraction (evp_key.rs)
//! - EvpSigner::new() with typed keys (evp_signer.rs)
//! - EvpVerifier::new() with typed keys (evp_verifier.rs)
//! - Streaming finalize with mismatched EC algorithm (evp_signer.rs)
//! - Sign/verify roundtrips via typed key constructors
//! - ECDSA DER conversion with oversized integer (ecdsa_format.rs)

use cose_sign1_crypto_openssl::ecdsa_format;
use cose_sign1_crypto_openssl::{EvpPrivateKey, EvpPublicKey, EvpSigner, EvpVerifier, KeyType};
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

// ===========================================================================
// evp_key.rs — EvpPrivateKey typed constructors
// ===========================================================================

#[test]
fn private_key_from_ec_constructor() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let key = EvpPrivateKey::from_ec(ec_key).unwrap();
    assert_eq!(key.key_type(), KeyType::Ec);
    assert!(!key.pkey().private_key_to_der().unwrap().is_empty());
}

#[test]
fn private_key_from_rsa_constructor() {
    let rsa = Rsa::generate(2048).unwrap();
    let key = EvpPrivateKey::from_rsa(rsa).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa);
    assert!(!key.pkey().private_key_to_der().unwrap().is_empty());
}

#[test]
fn private_key_from_pkey_ed25519() {
    let pkey = PKey::generate_ed25519().unwrap();
    let key = EvpPrivateKey::from_pkey(pkey).unwrap();
    assert_eq!(key.key_type(), KeyType::Ed25519);
}

// ===========================================================================
// evp_key.rs — EvpPrivateKey::public_key() extraction
// ===========================================================================

#[test]
fn extract_public_key_from_ec_private() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();

    let public_key = private_key.public_key().unwrap();
    assert_eq!(public_key.key_type(), KeyType::Ec);
    assert!(!public_key.pkey().public_key_to_der().unwrap().is_empty());
}

#[test]
fn extract_public_key_from_rsa_private() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();

    let public_key = private_key.public_key().unwrap();
    assert_eq!(public_key.key_type(), KeyType::Rsa);
    assert!(!public_key.pkey().public_key_to_der().unwrap().is_empty());
}

#[test]
fn extract_public_key_from_ed25519_private() {
    let pkey = PKey::generate_ed25519().unwrap();
    let private_key = EvpPrivateKey::from_pkey(pkey).unwrap();

    let public_key = private_key.public_key().unwrap();
    assert_eq!(public_key.key_type(), KeyType::Ed25519);
}

// ===========================================================================
// evp_key.rs — EvpPublicKey typed constructors
// ===========================================================================

#[test]
fn public_key_from_ec_constructor() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pub_point = ec_key.public_key();
    let ec_pub = EcKey::from_public_key(&group, pub_point).unwrap();

    let key = EvpPublicKey::from_ec(ec_pub).unwrap();
    assert_eq!(key.key_type(), KeyType::Ec);
    assert!(!key.pkey().public_key_to_der().unwrap().is_empty());
}

#[test]
fn public_key_from_rsa_constructor() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    let rsa_pub = pub_pkey.rsa().unwrap();

    let key = EvpPublicKey::from_rsa(rsa_pub).unwrap();
    assert_eq!(key.key_type(), KeyType::Rsa);
    assert!(!key.pkey().public_key_to_der().unwrap().is_empty());
}

// ===========================================================================
// evp_signer.rs — EvpSigner::new() with typed EvpPrivateKey
// ===========================================================================

#[test]
fn signer_new_ec_sign_roundtrip() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -7).unwrap();
    assert_eq!(signer.algorithm(), -7);
    assert_eq!(signer.key_type(), "EC2");
    assert!(signer.supports_streaming());
    assert!(signer.key_id().is_none());

    let data = b"signer new ec test";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 64);

    let verifier = EvpVerifier::new(public_key, -7).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_new_rsa_sign_roundtrip() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -257).unwrap();
    assert_eq!(signer.algorithm(), -257);
    assert_eq!(signer.key_type(), "RSA");
    assert!(signer.supports_streaming());

    let data = b"signer new rsa test";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 256);

    let verifier = EvpVerifier::new(public_key, -257).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn signer_new_ed25519_sign_roundtrip() {
    let pkey = PKey::generate_ed25519().unwrap();
    let private_key = EvpPrivateKey::from_pkey(pkey).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -8).unwrap();
    assert_eq!(signer.algorithm(), -8);
    assert_eq!(signer.key_type(), "OKP");
    assert!(!signer.supports_streaming());

    let data = b"signer new ed25519 test";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 64);

    let verifier = EvpVerifier::new(public_key, -8).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

// ===========================================================================
// evp_verifier.rs — EvpVerifier::new() with typed EvpPublicKey
// ===========================================================================

#[test]
fn verifier_new_ec_p384() {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pub_point = ec_key.public_key();
    let ec_pub = EcKey::from_public_key(&group, pub_point).unwrap();

    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();
    let public_key = EvpPublicKey::from_ec(ec_pub).unwrap();

    let signer = EvpSigner::new(private_key, -35).unwrap();
    let verifier = EvpVerifier::new(public_key, -35).unwrap();
    assert_eq!(verifier.algorithm(), -35);
    assert!(verifier.supports_streaming());

    let data = b"verifier new p384 test";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 96);
    assert!(verifier.verify(data, &sig).unwrap());
}

#[test]
fn verifier_new_rsa_pss() {
    let rsa = Rsa::generate(2048).unwrap();
    let n = rsa.n().to_owned().unwrap();
    let e = rsa.e().to_owned().unwrap();
    let rsa_pub = Rsa::from_public_components(n, e).unwrap();

    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let public_key = EvpPublicKey::from_rsa(rsa_pub).unwrap();

    let signer = EvpSigner::new(private_key, -37).unwrap();
    let verifier = EvpVerifier::new(public_key, -37).unwrap();

    let data = b"verifier new rsa pss test";
    let sig = signer.sign(data).unwrap();
    assert!(verifier.verify(data, &sig).unwrap());
}

// ===========================================================================
// evp_signer.rs — Streaming sign + verify using typed keys
// ===========================================================================

#[test]
fn streaming_sign_verify_typed_ec_keys() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -7).unwrap();
    let verifier = EvpVerifier::new(public_key, -7).unwrap();

    // Streaming sign
    let mut sign_ctx = signer.sign_init().unwrap();
    sign_ctx.update(b"typed key ").unwrap();
    sign_ctx.update(b"streaming test").unwrap();
    let sig = sign_ctx.finalize().unwrap();
    assert_eq!(sig.len(), 64);

    // Streaming verify
    let mut verify_ctx = verifier.verify_init(&sig).unwrap();
    verify_ctx.update(b"typed key ").unwrap();
    verify_ctx.update(b"streaming test").unwrap();
    assert!(verify_ctx.finalize().unwrap());
}

#[test]
fn streaming_sign_verify_typed_rsa_keys() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -38).unwrap(); // PS384
    let verifier = EvpVerifier::new(public_key, -38).unwrap();

    let mut sign_ctx = signer.sign_init().unwrap();
    sign_ctx.update(b"rsa typed key streaming").unwrap();
    let sig = sign_ctx.finalize().unwrap();

    let mut verify_ctx = verifier.verify_init(&sig).unwrap();
    verify_ctx.update(b"rsa typed key streaming").unwrap();
    assert!(verify_ctx.finalize().unwrap());
}

// ===========================================================================
// evp_signer.rs — Streaming finalize with mismatched EC algorithm
// (covers the _ => UnsupportedAlgorithm path in EvpSigningContext::finalize)
// ===========================================================================

#[test]
fn streaming_finalize_ec_unsupported_algorithm() {
    // Create an EC key but pair it with RS256 algorithm (-257).
    // sign_init() succeeds because -257 maps to SHA256, and the EC|RSA branch
    // in create_signer handles both. But finalize() fails because -257 is not
    // a valid EC algorithm for DER-to-fixed conversion.
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();

    let signer = EvpSigner::new(private_key, -257).unwrap();
    assert!(signer.supports_streaming());

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"data for mismatched algorithm").unwrap();

    let result = ctx.finalize();
    assert!(result.is_err());
    match result {
        Err(CryptoError::UnsupportedAlgorithm(alg)) => assert_eq!(alg, -257),
        other => panic!("expected UnsupportedAlgorithm(-257), got: {:?}", other),
    }
}

#[test]
fn streaming_finalize_ec_with_pss_algorithm() {
    // EC key + PS512 algorithm (-39): should fail at some point in the pipeline
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();

    // Creating signer with mismatched algo may fail at new() or sign_init()
    let signer_result = EvpSigner::new(private_key, -39);
    if let Ok(signer) = signer_result {
        let init_result = signer.sign_init();
        if let Ok(mut ctx) = init_result {
            let _ = ctx.update(b"ec key with pss algo");
            let result = ctx.finalize();
            assert!(result.is_err(), "finalize should fail for EC+PSS mismatch");
        }
        // If sign_init fails, that's also acceptable
    }
    // If new() fails, that's also an acceptable outcome for EC+PSS mismatch
}

// ===========================================================================
// evp_verifier.rs — Streaming verify with invalid data after typed key construction
// ===========================================================================

#[test]
fn streaming_verify_typed_keys_wrong_data() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -7).unwrap();
    let verifier = EvpVerifier::new(public_key, -7).unwrap();

    let sig = signer.sign(b"correct data").unwrap();

    // Verify with wrong data via streaming
    let mut ctx = verifier.verify_init(&sig).unwrap();
    ctx.update(b"wrong data").unwrap();
    let result = ctx.finalize().unwrap();
    assert!(!result);
}

#[test]
fn streaming_verify_typed_rsa_wrong_data() {
    let rsa = Rsa::generate(2048).unwrap();
    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let public_key = private_key.public_key().unwrap();

    let signer = EvpSigner::new(private_key, -257).unwrap();
    let verifier = EvpVerifier::new(public_key, -257).unwrap();

    let sig = signer.sign(b"original").unwrap();

    let mut ctx = verifier.verify_init(&sig).unwrap();
    ctx.update(b"tampered").unwrap();
    let result = ctx.finalize().unwrap();
    assert!(!result);
}

// ===========================================================================
// ecdsa_format.rs — Oversized integer triggers copy_integer_to_fixed error
// ===========================================================================

#[test]
fn der_to_fixed_oversized_r_component() {
    // Craft DER where r is 33 non-zero bytes (too large for 32-byte ES256 field).
    // After trimming one leading 0x00 (if present), it's still > 32 bytes.
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE
    // total_len = 2 + 33 + 2 + 1 = 38
    der.push(38);
    // r: 33 bytes, no leading zero, so trimmed_src.len() == 33 > 32
    der.push(0x02); // INTEGER tag
    der.push(33);   // length
    der.extend(vec![0x7F; 33]); // 33 bytes all non-zero, high bit clear
    // s: 1 byte
    der.push(0x02); // INTEGER tag
    der.push(1);    // length
    der.push(0x42);

    let result = ecdsa_format::der_to_fixed(&der, 64);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("too large"), "got: {err}");
}

#[test]
fn der_to_fixed_oversized_s_component() {
    // Craft DER where r is fine but s is too large for the fixed field.
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE
    // total_len = 2 + 1 + 2 + 33 = 38
    der.push(38);
    // r: 1 byte
    der.push(0x02);
    der.push(1);
    der.push(0x42);
    // s: 33 non-zero bytes
    der.push(0x02);
    der.push(33);
    der.extend(vec![0x7F; 33]);

    let result = ecdsa_format::der_to_fixed(&der, 64);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("too large"), "got: {err}");
}

// ===========================================================================
// Full roundtrip using typed EC P-521 keys (from_ec / from_public_key)
// ===========================================================================

#[test]
fn full_roundtrip_ec_p521_typed_keys() {
    let group = EcGroup::from_curve_name(Nid::SECP521R1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pub_point = ec_key.public_key();
    let ec_pub = EcKey::from_public_key(&group, pub_point).unwrap();

    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();
    let public_key = EvpPublicKey::from_ec(ec_pub).unwrap();

    let signer = EvpSigner::new(private_key, -36).unwrap(); // ES512
    let verifier = EvpVerifier::new(public_key, -36).unwrap();

    let data = b"P-521 typed key full roundtrip test";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 132);
    assert!(verifier.verify(data, &sig).unwrap());
}

// ===========================================================================
// Full roundtrip using typed RSA keys with PSS (from_rsa / from_public_components)
// ===========================================================================

#[test]
fn full_roundtrip_rsa_ps512_typed_keys() {
    let rsa = Rsa::generate(2048).unwrap();
    let n = rsa.n().to_owned().unwrap();
    let e = rsa.e().to_owned().unwrap();
    let rsa_pub = Rsa::from_public_components(n, e).unwrap();

    let private_key = EvpPrivateKey::from_rsa(rsa).unwrap();
    let public_key = EvpPublicKey::from_rsa(rsa_pub).unwrap();

    let signer = EvpSigner::new(private_key, -39).unwrap(); // PS512
    let verifier = EvpVerifier::new(public_key, -39).unwrap();

    let data = b"RSA PS512 typed key roundtrip";
    let sig = signer.sign(data).unwrap();
    assert_eq!(sig.len(), 256);
    assert!(verifier.verify(data, &sig).unwrap());
}

// ===========================================================================
// Multiple streaming contexts from single typed-key signer (tests key cloning)
// ===========================================================================

#[test]
fn multiple_streaming_contexts_typed_ec_key() {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let private_key = EvpPrivateKey::from_ec(ec_key).unwrap();

    let signer = EvpSigner::new(private_key, -7).unwrap();

    // Create first context and sign
    let mut ctx1 = signer.sign_init().unwrap();
    ctx1.update(b"context 1 data").unwrap();
    let sig1 = ctx1.finalize().unwrap();
    assert_eq!(sig1.len(), 64);

    // Create second context and sign different data
    let mut ctx2 = signer.sign_init().unwrap();
    ctx2.update(b"context 2 data").unwrap();
    let sig2 = ctx2.finalize().unwrap();
    assert_eq!(sig2.len(), 64);

    // One-shot sign should still work after contexts are consumed
    let sig3 = signer.sign(b"one-shot after contexts").unwrap();
    assert_eq!(sig3.len(), 64);
}

// ===========================================================================
// Ed25519 one-shot verify with wrong key (cross-key test via typed keys)
// ===========================================================================

#[test]
fn ed25519_verify_wrong_key_typed() {
    let pkey1 = PKey::generate_ed25519().unwrap();
    let pkey2 = PKey::generate_ed25519().unwrap();

    let signer_key = EvpPrivateKey::from_pkey(pkey1).unwrap();
    let wrong_pub_key = EvpPrivateKey::from_pkey(pkey2).unwrap().public_key().unwrap();

    let signer = EvpSigner::new(signer_key, -8).unwrap();
    let verifier = EvpVerifier::new(wrong_pub_key, -8).unwrap();

    let data = b"ed25519 cross-key test";
    let sig = signer.sign(data).unwrap();

    // Verification with wrong key should fail
    let result = verifier.verify(data, &sig);
    match result {
        Ok(false) => {}
        Err(_) => {}
        Ok(true) => panic!("wrong key should not verify"),
    }
}
