// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification tests for additional algorithms and input encodings.
//!
//! Covers success paths for ES384/ES512/RSA variants and a handful of common
//! failure modes.

use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};
use signature::Signer;
use signature::SignatureEncoding as _;
use p256::pkcs8::DecodePrivateKey as _;
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

fn sign_sig_structure_with_p256(protected: &[u8], payload: &[u8], sk: &p256::ecdsa::SigningKey) -> Vec<u8> {
    let msg = encode_sign1(protected, Some(payload), b"");
    let parsed = parse_cose_sign1(&msg).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed, None).unwrap();

    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    signature.to_bytes().to_vec()
}

#[test]
fn verify_fails_when_alg_missing() {
    // protected = empty map
    let protected = Vec::new();
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
fn verify_fails_when_public_key_missing() {
    let protected = encode_protected_map(-7);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let opts = VerifyOptions::default();
    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MISSING_PUBLIC_KEY"));
}

#[test]
fn verify_fails_with_expected_alg_mismatch() {
    let protected = encode_protected_map(-7);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let opts = VerifyOptions {
        public_key_bytes: Some(vec![1, 2, 3]),
        expected_alg: Some(CoseAlgorithm::ES384),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("ALG_MISMATCH"));
}

#[test]
fn verify_es256_accepts_der_certificate_input() {
    // Generate a self-signed certificate and sign using its key.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();
    let key_pkcs8 = certified.key_pair.serialize_der();

    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pkcs8).unwrap();

    let protected = encode_protected_map(-7);
    let payload = b"payload";
    let signature = sign_sig_structure_with_p256(&protected, payload, &sk);

    let msg = encode_sign1(&protected, Some(payload), &signature);

    let opts = VerifyOptions {
        public_key_bytes: Some(cert_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid);
    assert!(res.failures.is_empty());
}

#[test]
fn verify_es384_succeeds() {
    let mut rng = p384::elliptic_curve::rand_core::OsRng;
    let sk = p384::ecdsa::SigningKey::random(&mut rng);
    let vk = p384::ecdsa::VerifyingKey::from(&sk);
    let pk = p384::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes()).unwrap();
    let pk_der = pk.to_public_key_der().unwrap().to_vec();

    let mut protected = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut protected);
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.i64(-35).unwrap();

    let payload = b"p";

    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    let signature: p384::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();
    let msg = encode_sign1(&protected, Some(payload), &sig_bytes);

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid);
}

#[test]
fn verify_es512_succeeds() {
    let mut rng = p521::elliptic_curve::rand_core::OsRng;
    let sk = p521::ecdsa::SigningKey::random(&mut rng);
    let vk = p521::ecdsa::VerifyingKey::from(&sk);
    let pk = p521::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes()).unwrap();
    let pk_der = pk.to_public_key_der().unwrap().to_vec();

    let mut protected = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut protected);
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.i64(-36).unwrap();

    let payload = b"p";

    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    let signature: p521::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();
    let msg = encode_sign1(&protected, Some(payload), &sig_bytes);

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid);
}

#[test]
fn verify_rs256_and_ps256_succeed() {
    use rsa::pkcs1v15;
    use rsa::pss;
    use rsa::pkcs8::EncodePublicKey;
    use signature::RandomizedSigner;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key_der = private_key.to_public_key().to_public_key_der().unwrap().to_vec();

    let payload = b"p";

    // RS256
    {
        let protected = encode_protected_map(-257);
        let msg0 = encode_sign1(&protected, Some(payload), b"");
        let parsed0 = parse_cose_sign1(&msg0).unwrap();
        let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

        let signing_key = pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key.clone());
        let signature: pkcs1v15::Signature = signing_key.sign(&sig_structure);

        let sig_bytes = signature.to_bytes();
        let msg = encode_sign1(&protected, Some(payload), sig_bytes.as_ref());
        let opts = VerifyOptions {
            public_key_bytes: Some(public_key_der.clone()),
            ..Default::default()
        };

        let res = verify_cose_sign1("v", &msg, &opts);
        assert!(res.is_valid);
    }

    // PS256
    {
        let protected = encode_protected_map(-37);
        let msg0 = encode_sign1(&protected, Some(payload), b"");
        let parsed0 = parse_cose_sign1(&msg0).unwrap();
        let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

        let signing_key = pss::SigningKey::<sha2::Sha256>::new(private_key);
        let mut rng = rsa::rand_core::OsRng;
        let signature: pss::Signature = signing_key.sign_with_rng(&mut rng, &sig_structure);

        let sig_bytes = signature.to_bytes();
        let msg = encode_sign1(&protected, Some(payload), sig_bytes.as_ref());
        let opts = VerifyOptions {
            public_key_bytes: Some(public_key_der),
            ..Default::default()
        };

        let res = verify_cose_sign1("v", &msg, &opts);
        assert!(res.is_valid);
    }
}

#[test]
fn verify_fails_on_bad_signature_length_es256() {
    let mut rng = p256::elliptic_curve::rand_core::OsRng;
    let sk = p256::ecdsa::SigningKey::random(&mut rng);
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let pk_der = vk.to_public_key_der().unwrap().to_vec();

    let protected = encode_protected_map(-7);
    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 63]);

    let opts = VerifyOptions {
        public_key_bytes: Some(pk_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}
