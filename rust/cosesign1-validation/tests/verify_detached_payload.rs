// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Detached payload verification tests.
//!
//! COSE_Sign1 may omit the payload (set it to `null`). In that case, callers
//! must supply the external payload bytes for verification to succeed.

use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};
use minicbor::Encoder;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePublicKey;

// Build a minimal ES256 COSE_Sign1 with a detached payload.
fn build_detached_es256(external_payload: &[u8], sk: &SigningKey) -> Vec<u8> {
    let protected = {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        buf
    };

    let sig_structure = {
        let mut out = Vec::new();
        let mut enc = Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.str("Signature1").unwrap();
        enc.bytes(&protected).unwrap();
        enc.bytes(&[]).unwrap();
        enc.bytes(external_payload).unwrap();
        out
    };

    let sig: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let cose_sig = sig.to_bytes();

    let mut out = Vec::new();
    let mut enc = Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.null().unwrap();
    enc.bytes(&cose_sig).unwrap();
    out
}

#[test]
fn detached_payload_requires_external_bytes() {
    let sk = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);

    let cose = build_detached_es256(b"claims", &sk);

    let mut opts = VerifyOptions::default();
    opts.public_key_bytes = Some(sk.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec());
    opts.expected_alg = Some(CoseAlgorithm::ES256);

    let res = verify_cose_sign1("Sig", &cose, &opts);
    assert!(!res.is_valid);

    let mut opts2 = opts.clone();
    opts2.external_payload = Some(b"claims".to_vec());
    let res2 = verify_cose_sign1("Sig", &cose, &opts2);
    assert!(res2.is_valid, "{res2:?}");
}
