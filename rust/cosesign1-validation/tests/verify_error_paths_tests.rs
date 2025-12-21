// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error-path coverage tests for signature verification.
//!
//! These tests intentionally feed invalid/malformed keys, signatures, and COSE
//! structures to ensure the verifier returns deterministic error codes and
//! exercises non-happy-path logic.

use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};
use ml_dsa::{KeyGen, MlDsa65};
use signature::Signer;
use p256::pkcs8::EncodePublicKey as _;

// Helper to build protected headers containing `{ 1: alg }`.
fn encode_protected_map(alg: i64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.i64(alg).unwrap();
    out
}

// Helper to build a minimal COSE_Sign1 structure.
// `payload: None` encodes a detached payload (`null`).
fn encode_sign1(protected: &[u8], payload: Option<&[u8]>, signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);

    enc.array(4).unwrap();
    enc.bytes(protected).unwrap();
    enc.map(0).unwrap();

    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    };

    enc.bytes(signature).unwrap();
    out
}

#[test]
fn verify_fails_for_unsupported_alg_value() {
    let protected = encode_protected_map(1234);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![1, 2, 3]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MISSING_OR_INVALID_ALG"));
}

#[test]
fn verify_reports_cose_parse_error_on_invalid_input() {
    let msg = vec![0xff];
    let opts = VerifyOptions::default();

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("COSE_PARSE_ERROR"));
}

#[test]
fn verify_mldsa65_rejects_bad_public_key_bytes() {
    let protected = encode_protected_map(-49);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 3309]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![0u8; 10]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("INVALID_PUBLIC_KEY"));
}

#[test]
fn verify_mldsa65_rejects_bad_signature_bytes() {
    let protected = encode_protected_map(-49);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 10]);

    // Any correctly-sized ML-DSA-65 verifying key bytes will do.
    let kp = MlDsa65::key_gen_internal(&Default::default());
    let vk_bytes = kp.verifying_key().encode().as_slice().to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(vk_bytes),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_fails_with_invalid_public_key_bytes() {
    let protected = encode_protected_map(-7);

    // A correctly-sized signature so we hit the public key parsing path first.
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("INVALID_PUBLIC_KEY"));
}

#[test]
fn verify_fails_when_signature_verification_fails() {
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let sk = p256::ecdsa::SigningKey::random(&mut rng);
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let pk_der = vk.to_public_key_der().unwrap().to_vec();

    let protected = encode_protected_map(-7);
    let payload = b"payload";

    // Build correct Sig_structure.
    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    // Sign, then corrupt a byte to ensure we exercise the "verification failed" branch.
    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let mut sig_bytes = signature.to_bytes().to_vec();
    sig_bytes[0] ^= 0xff;

    let msg = encode_sign1(&protected, Some(payload), &sig_bytes);

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_detached_payload_without_external_bytes_fails_with_sigstruct_error() {
    let protected = encode_protected_map(-7);

    // Detached payload => null.
    let msg = encode_sign1(&protected, None, &[0u8; 64]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![1, 2, 3]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("SIGSTRUCT_ERROR"));
}

#[test]
fn verify_rs256_rejects_bad_signature_bytes() {
    let protected = encode_protected_map(-257);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 10]);

    // Any valid RSA SPKI will do; we just want to reach signature parsing.
    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(public_key_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_ps256_rejects_bad_signature_bytes() {
    let protected = encode_protected_map(-37);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 10]);

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(public_key_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_rs256_fails_when_signature_verification_fails() {
    let protected = encode_protected_map(-257);
    // 2048-bit key => 256-byte signature length.
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 256]);

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(public_key_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_ps256_fails_when_signature_verification_fails() {
    let protected = encode_protected_map(-37);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 256]);

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_der = private_key
        .to_public_key()
        .to_public_key_der()
        .unwrap()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(public_key_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_es384_rejects_bad_signature_length() {
    use p384::pkcs8::EncodePublicKey as _;

    let protected = encode_protected_map(-35);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 10]);

    let mut rng = rsa::rand_core::OsRng;
    let sk = p384::ecdsa::SigningKey::random(&mut rng);
    let vk = p384::ecdsa::VerifyingKey::from(&sk);
    let pk_der = vk
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_es512_rejects_bad_signature_length() {
    use p521::pkcs8::EncodePublicKey as _;

    let protected = encode_protected_map(-36);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 10]);

    let mut rng = rsa::rand_core::OsRng;
    let secret = p521::SecretKey::random(&mut rng);
    let pk_der = secret
        .public_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_es384_rejects_bad_public_key_bytes() {
    let protected = encode_protected_map(-35);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 96]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("INVALID_PUBLIC_KEY"));
}

#[test]
fn verify_es512_rejects_bad_public_key_bytes() {
    let protected = encode_protected_map(-36);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 132]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("INVALID_PUBLIC_KEY"));
}
