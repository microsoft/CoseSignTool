// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `x5c`-based verification.
//!
//! The Rust port currently extracts the leaf certificate from `x5c` and then
//! delegates to the signature verifier.
//! Chain evaluation and revocation checking are explicitly not implemented yet;
//! tests cover both supported and unsupported modes.

use cosesign1_x509::{verify_cose_sign1_with_x5c, X509ChainVerifyOptions, X509RevocationMode};
use cosesign1_validation::VerifyOptions;
use signature::Signer;

// Helper to build protected headers containing `{ 1: alg, 33: [leaf_cert_der] }`.
fn encode_protected_with_alg_and_x5c(alg: i64, leaf_cert_der: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.map(2).unwrap();

    enc.i64(1).unwrap();
    enc.i64(alg).unwrap();

    // x5c label 33
    enc.i64(33).unwrap();
    enc.array(1).unwrap();
    enc.bytes(leaf_cert_der).unwrap();

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
fn x5c_verification_succeeds_without_chain_options() {
    use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
    use p256::pkcs8::DecodePrivateKey as _;

    // Generate a self-signed leaf cert and use its key to sign the COSE.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let leaf_cert_der = certified.cert.der().to_vec();
    let leaf_key_pkcs8 = certified.key_pair.serialize_der();
    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key_pkcs8).unwrap();

    let protected = encode_protected_with_alg_and_x5c(-7, &leaf_cert_der);
    let payload = b"payload";

    // Build message with empty signature, compute Sig_structure, then sign.
    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();
    let msg = encode_sign1(&protected, Some(payload), &sig_bytes);

    let opts = VerifyOptions::default();
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &opts, None);
    assert!(res.is_valid);
}

#[test]
fn x5c_verification_succeeds_in_allow_untrusted_mode() {
    use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
    use p256::pkcs8::DecodePrivateKey as _;

    // Generate a self-signed leaf cert and use its key to sign the COSE.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let leaf_cert_der = certified.cert.der().to_vec();
    let leaf_key_pkcs8 = certified.key_pair.serialize_der();
    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key_pkcs8).unwrap();

    let protected = encode_protected_with_alg_and_x5c(-7, &leaf_cert_der);
    let payload = b"payload";

    // Build message with empty signature, compute Sig_structure, then sign.
    let msg0 = encode_sign1(&protected, Some(payload), b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();

    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();
    let msg = encode_sign1(&protected, Some(payload), &sig_bytes);

    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.allow_untrusted_roots = true;

    let opts = VerifyOptions::default();
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &opts, Some(&chain));
    assert!(res.is_valid);
}

#[test]
fn x5c_verification_succeeds_with_detached_payload_and_external_bytes() {
    use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
    use p256::pkcs8::DecodePrivateKey as _;

    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let leaf_cert_der = certified.cert.der().to_vec();
    let leaf_key_pkcs8 = certified.key_pair.serialize_der();
    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key_pkcs8).unwrap();

    let protected = encode_protected_with_alg_and_x5c(-7, &leaf_cert_der);
    let external_payload = b"payload";

    // Detached payload (null)
    let msg0 = encode_sign1(&protected, None, b"");
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, Some(external_payload)).unwrap();

    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();
    let msg = encode_sign1(&protected, None, &sig_bytes);

    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.allow_untrusted_roots = true;

    let opts = VerifyOptions {
        external_payload: Some(external_payload.to_vec()),
        ..Default::default()
    };
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &opts, Some(&chain));
    assert!(res.is_valid);
}

#[test]
fn x5c_rejects_missing_header() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MISSING_X5C"));
}

#[test]
fn x5c_rejects_chain_verification_when_not_allowed() {
    // A minimal but correctly-typed x5c to reach the chain check.
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.bytes(b"not-a-real-cert").unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let chain = X509ChainVerifyOptions {
        revocation_mode: X509RevocationMode::NoCheck,
        allow_untrusted_roots: false,
        ..Default::default()
    };

    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), Some(&chain));
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("CHAIN_VERIFY_UNSUPPORTED"));
}

#[test]
fn x5c_rejects_revocation_mode_when_enabled() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.bytes(b"not-a-real-cert").unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);

    let chain = X509ChainVerifyOptions {
        revocation_mode: X509RevocationMode::Online,
        allow_untrusted_roots: true,
        ..Default::default()
    };

    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), Some(&chain));
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("REVOCATION_UNSUPPORTED"));
}

#[test]
fn x5c_rejects_empty_array() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.array(0).unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("X5C_EMPTY"));
}

#[test]
fn x5c_rejects_non_bstr_elements() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.i64(123).unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("X5C_TYPE_ERROR"));
}

#[test]
fn x5c_reports_cose_parse_error_on_invalid_input() {
    let msg = vec![0xff];
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("COSE_PARSE_ERROR"));
}

#[test]
fn x5c_treats_protected_wrong_type_as_missing() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.bytes(b"not-an-array").unwrap();
        out
    };

    let msg = encode_sign1(&protected, Some(b"p"), &[0u8; 64]);
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MISSING_X5C"));
}

#[test]
fn x5c_treats_unprotected_wrong_type_as_missing() {
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        out
    };

    let msg = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected).unwrap();
        enc.map(1).unwrap();
        enc.i64(33).unwrap();
        enc.bytes(b"not-an-array").unwrap();
        enc.bytes(b"p").unwrap();
        enc.bytes(&[0u8; 64]).unwrap();
        out
    };
    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), None);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MISSING_X5C"));
}

#[test]
fn x5c_falls_back_to_unprotected_when_protected_wrong_type() {
    use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1};
    use p256::pkcs8::DecodePrivateKey as _;

    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let leaf_cert_der = certified.cert.der().to_vec();
    let leaf_key_pkcs8 = certified.key_pair.serialize_der();
    let sk = p256::ecdsa::SigningKey::from_pkcs8_der(&leaf_key_pkcs8).unwrap();

    // Protected has x5c label but wrong type (bstr instead of array).
    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(2).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(33).unwrap();
        enc.bytes(b"wrong-type").unwrap();
        out
    };

    // Unprotected has the correct x5c array.
    let payload = b"payload";

    let msg0 = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected).unwrap();
        enc.map(1).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.bytes(&leaf_cert_der).unwrap();
        enc.bytes(payload).unwrap();
        enc.bytes(b"").unwrap();
        out
    };
    let parsed0 = parse_cose_sign1(&msg0).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed0, None).unwrap();
    let signature: p256::ecdsa::Signature = sk.sign(&sig_structure);
    let sig_bytes = signature.to_bytes().to_vec();

    let msg = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected).unwrap();
        enc.map(1).unwrap();
        enc.i64(33).unwrap();
        enc.array(1).unwrap();
        enc.bytes(&leaf_cert_der).unwrap();
        enc.bytes(payload).unwrap();
        enc.bytes(&sig_bytes).unwrap();
        out
    };

    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.allow_untrusted_roots = true;

    let res = verify_cose_sign1_with_x5c("x5c", &msg, &VerifyOptions::default(), Some(&chain));
    assert!(res.is_valid);
}
