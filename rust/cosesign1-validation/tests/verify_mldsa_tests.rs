// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end ML-DSA verification tests.
//!
//! These tests cover:
//! - Success cases for ML-DSA-44/65/87.
//! - Failure with wrong key.
//! - Accepting DER SPKI input.
//! - Rejecting DER certificates whose SPKI algorithm OID does not match.

use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};
use ml_dsa::{KeyGen, MlDsa44, MlDsa65, MlDsa87};
use signature::Signer;

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

fn build_signed_mldsa<P>(alg: i64, kp: &ml_dsa::KeyPair<P>, payload: &[u8]) -> Vec<u8>
where
    P: ml_dsa::MlDsaParams,
{
    let protected = encode_protected_map(alg);

    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    let sig: ml_dsa::Signature<P> = kp.signing_key().sign(&sig_structure);
    let sig_bytes = sig.encode().as_slice().to_vec();

    encode_sign1(&protected, Some(payload), &sig_bytes)
}

#[test]
fn verify_mldsa44_succeeds() {
    let kp = MlDsa44::key_gen_internal(&Default::default());
    let payload = b"payload";

    let msg = build_signed_mldsa(-48, &kp, payload);

    let opts = VerifyOptions {
        public_key_bytes: Some(kp.verifying_key().encode().as_slice().to_vec()),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_mldsa65_succeeds() {
    let kp = MlDsa65::key_gen_internal(&Default::default());
    let payload = b"payload";

    let msg = build_signed_mldsa(-49, &kp, payload);

    let opts = VerifyOptions {
        public_key_bytes: Some(kp.verifying_key().encode().as_slice().to_vec()),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_mldsa65_succeeds_with_der_spki_input() {
    use spki::EncodePublicKey as _;

    let kp = MlDsa65::key_gen_internal(&Default::default());
    let payload = b"payload";

    let msg = build_signed_mldsa(-49, &kp, payload);
    let spki_der = kp.verifying_key().to_public_key_der().unwrap().to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(spki_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_mldsa87_succeeds() {
    let kp = MlDsa87::key_gen_internal(&Default::default());
    let payload = b"payload";

    let msg = build_signed_mldsa(-50, &kp, payload);

    let opts = VerifyOptions {
        public_key_bytes: Some(kp.verifying_key().encode().as_slice().to_vec()),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_mldsa65_fails_with_wrong_key() {
    let kp1 = MlDsa65::key_gen_internal(&Default::default());

    let mut seed2 = ml_dsa::B32::default();
    let seed_bytes: &mut [u8] = seed2.as_mut();
    for b in seed_bytes {
        *b = 0x42;
    }
    let kp2 = MlDsa65::key_gen_internal(&seed2);

    let payload = b"payload";
    let msg = build_signed_mldsa(-49, &kp1, payload);

    let opts = VerifyOptions {
        public_key_bytes: Some(kp2.verifying_key().encode().as_slice().to_vec()),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("BAD_SIGNATURE"));
}

#[test]
fn verify_mldsa65_rejects_der_certificate_with_wrong_oid() {
    let kp = MlDsa65::key_gen_internal(&Default::default());
    let payload = b"payload";
    let msg = build_signed_mldsa(-49, &kp, payload);

    // Any non-ML-DSA certificate should be rejected via OID mismatch.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let opts = VerifyOptions {
        public_key_bytes: Some(cert_der),
        ..Default::default()
    };

    let res = verify_cose_sign1("v", &msg, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("INVALID_PUBLIC_KEY"));
    let msg = res.failures[0].message.as_str();
    assert!(msg.contains("unexpected public key algorithm OID"), "{res:?}");
}
