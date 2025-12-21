// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_common::parse_cose_sign1;
use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};
use minicbor::Encoder;
use p256::ecdsa::signature::Signer;
use p256::pkcs8::EncodePublicKey;
use p256::ecdsa::SigningKey;

fn build_sign1_es256(payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    // protected = { 1: -7 }
    let protected = {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        buf
    };

    // Create Sig_structure bytes
    let sig_structure = {
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.str("Signature1").unwrap();
        enc.bytes(&protected).unwrap();
        enc.bytes(&[]).unwrap();
        enc.bytes(payload).unwrap();
        out
    };

    let sig: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let cose_sig = sig.to_bytes();

    // COSE_Sign1 array
    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(payload).unwrap();
    enc.bytes(&cose_sig).unwrap();
    out
}

#[test]
fn verify_es256_succeeds() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let payload = b"hello";
    let cose = build_sign1_es256(payload, &sk);

    // Sanity: parse ok
    let parsed = parse_cose_sign1(&cose).unwrap();
    assert_eq!(parsed.protected_headers.get_i64(1), Some(-7));

    let opts = VerifyOptions {
        public_key_bytes: Some(sk.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec()),
        expected_alg: Some(CoseAlgorithm::ES256),
        ..Default::default()
    };

    let res = verify_cose_sign1("Signature", &cose, &opts);
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_es256_fails_with_wrong_key() {
    let k1 = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let k2 = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let payload = b"hello";
    let cose = build_sign1_es256(payload, &k1);

    let opts = VerifyOptions {
        public_key_bytes: Some(k2.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec()),
        expected_alg: Some(CoseAlgorithm::ES256),
        ..Default::default()
    };

    let res = verify_cose_sign1("Signature", &cose, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}
