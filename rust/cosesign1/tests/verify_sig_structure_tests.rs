// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `verify_sig_structure`.
//!
//! `verify_sig_structure` is the core algorithm dispatcher that verifies
//! `Sig_structure` bytes against a signature and public key material.
//!
//! These tests are intentionally a mix of success and failure cases to exercise
//! parsing and dispatch branches for ECDSA, RSA, and ML-DSA.

mod common;

use common::*;
use rand_core::OsRng;
use rsa::pkcs8::EncodePublicKey as _;
use signature::Signer as _;

/// Exercises error mapping for ES384 and ES512 signature byte parsing.
#[test]
fn verify_sig_structure_reports_bad_es384_and_es512_signature_bytes() {
    let msg = b"sig_structure";
    let bad_sig = b"not-a-valid-ecdsa-sig";

    // Use valid public keys but invalid signature bytes.
    let sk384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let vk384 = p384::ecdsa::VerifyingKey::from(&sk384);
    let pk384 = p384::PublicKey::from(&vk384);
    let spki384 = pk384.to_public_key_der().unwrap();
    assert!(cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::ES384, spki384.as_bytes(), msg, bad_sig).is_err());

    let sk521 = p521::SecretKey::random(&mut OsRng);
    let pk521 = sk521.public_key();
    let spki521 = pk521.to_public_key_der().unwrap();
    assert!(cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::ES512, spki521.as_bytes(), msg, bad_sig).is_err());
}

/// Exercises ML-DSA OID mismatch handling by providing a non-ML-DSA certificate.
#[test]
fn verify_sig_structure_reports_mldsa_oid_mismatch_for_non_mldsa_cert() {
    let (cert_der, _sk) = make_self_signed_p256_cert_and_key();
    let err = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, &cert_der, b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("unexpected public key algorithm OID"));
}

/// Exercises ML-DSA public key decoding failures.
#[test]
fn verify_sig_structure_reports_bad_mldsa_public_key_bytes() {
    let err = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, &[0u8; 1], b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("bad ML-DSA public key bytes"));
}

fn find_mldsa44_public_key_len_that_reaches_signature_parsing() -> usize {
    // We don't assume an exact key size for the `ml_dsa` crate version; instead,
    // probe a small set of known ML-DSA public key sizes and pick the one that
    // gets past public-key parsing (i.e., we reach signature parsing).
    let msg = b"mldsa";
    let bad_sig = [0u8; 1];

    // Common ML-DSA (Dilithium) public key sizes.
    for n in [1312usize, 1952, 2592, 1024, 2048, 4096] {
        let pk = vec![0u8; n];
        let err = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, &pk, msg, &bad_sig).unwrap_err();
        if err.0 == "BAD_SIGNATURE" {
            return n;
        }
    }

    panic!("could not find an ML-DSA-44 public key length that reaches signature parsing");
}

/// Exercises ML-DSA signature decoding failures.
#[test]
fn verify_sig_structure_reports_bad_mldsa_signature_bytes() {
    // Find a public key length that passes key parsing, then supply an invalid-length signature.
    let pk_len = find_mldsa44_public_key_len_that_reaches_signature_parsing();
    let pk = vec![0u8; pk_len];

    let err = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, &pk, b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");
    assert!(err.1.contains("bad ML-DSA signature bytes"));
}

/// Exercises ML-DSA signature verification failure (well-formed signature, wrong message).
#[test]
fn verify_sig_structure_reports_mldsa_signature_verification_failed() {
    // Use deterministic key generation + signing from the ml-dsa crate, then verify against
    // a *different* message to ensure we hit the vk.verify() failure mapping.
    use ml_dsa::{KeyGen as _, MlDsa44};
    use ml_dsa::signature::Signer as _;

    let seed: ml_dsa::B32 = [42u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);

    let msg_signed = b"signed";
    let msg_verified = b"verified";
    let sig = kp.signing_key().sign(msg_signed);

    let public_key = kp.verifying_key().encode();
    let signature = sig.encode();

    let err = cosesign1::verify_sig_structure(
        cosesign1::CoseAlgorithm::MLDsa44,
        public_key.as_ref(),
        msg_verified,
        signature.as_ref(),
    )
    .unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");
    assert!(err.1.contains("signature verification failed"));
}

/// Raw non-DER key bytes take the raw branch and fail decoding.
#[test]
fn verify_ml_dsa_raw_key_path_is_exercised() {
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, b"raw", b"msg", b"sig");
    assert!(r.is_err());
}

/// Verifies a valid ES256 signature using both SPKI and cert-derived key inputs.
#[test]
fn verify_sig_structure_succeeds_for_es256_with_spki_and_cert_inputs() {
    // Generate a P-256 key and sign an arbitrary message.
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let pk = p256::PublicKey::from(&verifying_key);
    let spki = pk.to_public_key_der().unwrap();

    let msg = b"message";
    let sig: p256::ecdsa::Signature = signing_key.sign(msg);
    let sig_bytes = sig.to_bytes();

    // SPKI DER works.
    assert!(cosesign1::verify_sig_structure(
        cosesign1::CoseAlgorithm::ES256,
        spki.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&sig_bytes)
    )
    .is_ok());

    // Cert DER also works via SPKI extraction.
    let (cert_der, cert_signing_key) = make_self_signed_p256_cert_and_key();
    let cert_verifying_key = p256::ecdsa::VerifyingKey::from(&cert_signing_key);
    let cert_pk = p256::PublicKey::from(&cert_verifying_key);
    let cert_spki = cert_pk.to_public_key_der().unwrap();
    let cert_sig: p256::ecdsa::Signature = cert_signing_key.sign(msg);
    let cert_sig_bytes = cert_sig.to_bytes();
    assert!(cosesign1::verify_sig_structure(
        cosesign1::CoseAlgorithm::ES256,
        cert_spki.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&cert_sig_bytes)
    )
    .is_ok());

    // Also exercise passing a full cert as the key bytes (SPKI extracted internally).
    assert!(cosesign1::verify_sig_structure(
        cosesign1::CoseAlgorithm::ES256,
        cert_der.as_slice(),
        msg,
        AsRef::<[u8]>::as_ref(&cert_sig_bytes)
    )
    .is_ok());
}

/// Exercises the algorithm dispatch table by attempting to verify with each supported algorithm.
#[test]
fn verify_sig_structure_exercises_algorithm_dispatch_paths() {
    let msg = b"sig_structure";
    let sig = b"sig";

    for alg in [
        cosesign1::CoseAlgorithm::ES256,
        cosesign1::CoseAlgorithm::ES384,
        cosesign1::CoseAlgorithm::ES512,
        cosesign1::CoseAlgorithm::RS256,
        cosesign1::CoseAlgorithm::PS256,
        cosesign1::CoseAlgorithm::MLDsa44,
        cosesign1::CoseAlgorithm::MLDsa65,
        cosesign1::CoseAlgorithm::MLDsa87,
    ] {
        let r = cosesign1::verify_sig_structure(alg, &[], msg, sig);
        assert!(r.is_err());
    }
}

/// Exercises deeper key and signature parsing branches with valid keys and invalid signatures.
#[test]
fn verify_sig_structure_exercises_deeper_key_and_signature_parsing_paths() {
    // ECDSA: valid key, invalid signature bytes.
    let (_cert_der, sk) = make_self_signed_p256_cert_and_key();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let pk = p256::PublicKey::from(&vk);
    let spki = pk.to_public_key_der().unwrap();
    let msg = b"sig_structure";
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::ES256, spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // P-384 and P-521: generate keys and feed invalid signature bytes.
    let sk384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let vk384 = p384::ecdsa::VerifyingKey::from(&sk384);
    let pk384 = p384::PublicKey::from(&vk384);
    let spki384 = pk384.to_public_key_der().unwrap();
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::ES384, spki384.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    let sk521 = p521::SecretKey::random(&mut OsRng);
    let pk521 = sk521.public_key();
    let spki521 = pk521.to_public_key_der().unwrap();
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::ES512, spki521.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // RSA: valid key, invalid signature bytes to hit signature parsing errors.
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::RS256, rsa_spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::PS256, rsa_spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // ML-DSA: force OID mismatch by passing a P-256 cert and SPKI.
    let (cert_der, _sk2) = make_self_signed_p256_cert_and_key();
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, cert_der.as_slice(), msg, b"bad");
    assert!(r.is_err());
    let spki_der = extract_spki_from_cert_der(&cert_der);
    let r = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, spki_der.as_slice(), msg, b"bad");
    assert!(r.is_err());
}

/// Exercises the SPKI parsing branch for ML-DSA by providing a non-ML-DSA SPKI.
#[test]
fn mldsa_verifier_exercises_spki_parsing_branch() {
    // Provide an SPKI DER (not a certificate) for a non-ML-DSA key.
    use rsa::pkcs8::EncodePublicKey as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    let err = cosesign1::verify_sig_structure(cosesign1::CoseAlgorithm::MLDsa44, rsa_spki.as_bytes(), b"msg", &[0u8; 1])
        .unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("unexpected public key algorithm OID"));
}
