// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for detached payload verification (streaming).
//!
//! These tests exercise the reader-based detached verification paths, including
//! CBOR length prefix encoding branches and error mapping for malformed inputs.

mod common;

use common::*;
use rsa::pkcs8::EncodePublicKey as _;
use signature::Signer as _;
use std::io::SeekFrom;

/// Missing provider match in detached streaming verification yields `MISSING_PUBLIC_KEY`.
#[test]
fn streaming_detached_payload_reports_missing_public_key_when_no_provider_matches() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(b"payload".to_vec());
    let res = msg.verify_signature_with_payload_reader(&mut rdr, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

/// Seek errors on the payload reader surface as `PAYLOAD_READ_ERROR`.
#[test]
fn streaming_detached_payload_reports_seek_error() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = ErrorReadSeek { err: "boom" };
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(b"pk"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

/// Exercises CBOR bstr length prefix branches using a virtual-length reader.
#[test]
fn detached_streaming_hits_cbor_bstr_header_length_branches() {
    // We only need to hit the length-prefix encoding branches, so we use a
    // deterministic signature and a virtual-length reader.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    // Lengths chosen to cover 1-byte/2-byte/4-byte/8-byte CBOR bstr length forms.
    for len in [
        23u64,
        24u64,
        255u64,
        256u64,
        65_535u64,
        65_536u64,
        4_294_967_295u64,
        4_294_967_296u64,
    ] {
        let mut rdr = VirtualLenEofReader { len, pos: 0 };
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(b"pk"));
        assert!(!res.is_valid);
    }
}

/// ML-DSA detached streaming rejects payloads too large to buffer.
///
/// Note: this branch is only reachable on 32-bit targets.
#[cfg(target_pointer_width = "32")]
#[test]
fn detached_streaming_mldsa_rejects_payload_too_large_to_buffer() {
    for alg in [
        cosesign1::CoseAlgorithm::MLDsa44,
        cosesign1::CoseAlgorithm::MLDsa65,
        cosesign1::CoseAlgorithm::MLDsa87,
    ] {
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);
        let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
        let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

        // Pick a virtual length above usize::MAX to trigger the guard.
        let len = (usize::MAX as u64) + 1;
        let mut rdr = VirtualLenEofReader { len, pos: 0 };

        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(b"pk"));
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
    }
}

/// Ensures detached streaming rejects inputs where a payload is embedded.
#[test]
fn detached_streaming_rejects_when_payload_is_embedded() {
    use cosesign1::verify_parsed_cose_sign1_detached_payload_reader;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"embedded"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&msg).unwrap();
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };

    let mut rdr = std::io::Cursor::new(b"payload".to_vec());
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut rdr, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

/// Detached payload verification requires external payload bytes.
#[test]
fn verify_detached_payload_requires_external_payload() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let cose = sign_es256_detached_with_key(b"detached", &protected, &[], &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    // Missing external payload should fail early.
    let res = msg.verify_signature(None, Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PAYLOAD")));

    // Providing external payload allows signature verification to proceed (it will still fail
    // due to invalid public key if we don't provide a valid one).
    let res2 = msg.verify_signature(Some(b"detached"), Some(&[0u8; 1]));
    assert!(!res2.is_valid);
    assert!(res2
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_PUBLIC_KEY")));
}

/// Detached streaming verification succeeds for ES256.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let public_key = p256::PublicKey::from(&verifying_key);
    let spki = public_key.to_public_key_der().unwrap();

    let payload = b"detached";
    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let cose = sign_es256_detached_with_key(payload, &protected, &[], &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(spki.as_bytes()));
    assert!(res.is_valid, "{res:?}");
}

/// Detached streaming verification succeeds for ES384.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_es384() {
    let signing_key = p384::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let public_key_der = signing_key.verifying_key().to_public_key_der().unwrap();

    let alg = cosesign1::CoseAlgorithm::ES384;
    let payload = b"es384-detached";
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
    let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig: p384::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    let cose = encode_cose_sign1(false, &protected, &[], None, AsRef::<[u8]>::as_ref(&sig_bytes));
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key_der.as_bytes()));
    assert!(res.is_valid, "{alg:?} failed: {res:?}");
}

/// Detached streaming verification succeeds for ES512.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_es512() {
    let signing_key = p521::ecdsa::SigningKey::random(&mut rand_core::OsRng);
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let point = verifying_key.to_encoded_point(false);
    let pk = p521::PublicKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let public_key_der = pk.to_public_key_der().unwrap();

    let alg = cosesign1::CoseAlgorithm::ES512;
    let payload = b"es512-detached";
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
    let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig: p521::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    let cose = encode_cose_sign1(false, &protected, &[], None, AsRef::<[u8]>::as_ref(&sig_bytes));
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key_der.as_bytes()));
    assert!(res.is_valid, "{alg:?} failed: {res:?}");
}

/// Detached streaming verification succeeds for RS256.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_rs256() {
    use rsa::pkcs1v15::SigningKey as RsaPkcs1SigningKey;
    use rsa::signature::RandomizedSigner as _;
    use rsa::signature::SignatureEncoding as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let spki = rsa_pub.to_public_key_der().unwrap();

    let alg = cosesign1::CoseAlgorithm::RS256;
    let payload = b"rs256-detached";
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
    let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();

    let signer = RsaPkcs1SigningKey::<sha2::Sha256>::new(rsa_priv);
    let signature = signer.sign_with_rng(&mut rng, &sig_structure);
    let signature_bytes = signature.to_vec();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature_bytes.as_slice());
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(spki.as_bytes()));
    assert!(res.is_valid, "{alg:?} failed: {res:?}");
}

/// Detached streaming verification succeeds for PS256.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_ps256() {
    use rsa::pss::SigningKey as RsaPssSigningKey;
    use rsa::signature::RandomizedSigner as _;
    use rsa::signature::SignatureEncoding as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let spki = rsa_pub.to_public_key_der().unwrap();

    let alg = cosesign1::CoseAlgorithm::PS256;
    let payload = b"ps256-detached";
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
    let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();

    let signer = RsaPssSigningKey::<sha2::Sha256>::new(rsa_priv);
    let signature = signer.sign_with_rng(&mut rng, &sig_structure);
    let signature_bytes = signature.to_vec();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature_bytes.as_slice());
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(spki.as_bytes()));
    assert!(res.is_valid, "{alg:?} failed: {res:?}");
}

/// Detached streaming verification succeeds for ML-DSA-44.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_mldsa44() {
    use ml_dsa::{KeyGen as _, MlDsa44};
    use ml_dsa::signature::Signer as _;

    let seed: ml_dsa::B32 = [7u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);
    let public_key = kp.verifying_key().encode();

    let alg = cosesign1::CoseAlgorithm::MLDsa44;
    let payload = b"mldsa44-detached";
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
    let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig = kp.signing_key().sign(&sig_structure);
    let signature = sig.encode();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
    assert!(res.is_valid, "{alg:?} failed: {res:?}");
}

/// Detached streaming verification succeeds for ML-DSA-65 and ML-DSA-87.
#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_mldsa65_and_87() {
    use ml_dsa::{KeyGen as _, MlDsa65, MlDsa87};
    use ml_dsa::signature::Signer as _;

    // ML-DSA-65
    {
        let seed: ml_dsa::B32 = [9u8; 32].into();
        let kp = MlDsa65::key_gen_internal(&seed);
        let public_key = kp.verifying_key().encode();

        let alg = cosesign1::CoseAlgorithm::MLDsa65;
        let payload = b"mldsa65-detached".as_slice();
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

        let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
        let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
        let sig = kp.signing_key().sign(&sig_structure);
        let signature = sig.encode();

        let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
        let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(payload);
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
        assert!(res.is_valid, "{alg:?} failed: {res:?}");
    }

    // ML-DSA-87
    {
        let seed: ml_dsa::B32 = [10u8; 32].into();
        let kp = MlDsa87::key_gen_internal(&seed);
        let public_key = kp.verifying_key().encode();

        let alg = cosesign1::CoseAlgorithm::MLDsa87;
        let payload = b"mldsa87-detached".as_slice();
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

        let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let parsed_for_sig = cosesign1::parse_cose_sign1(&tmp).unwrap();
        let sig_structure = cosesign1::encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
        let sig = kp.signing_key().sign(&sig_structure);
        let signature = sig.encode();

        let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
        let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(payload);
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
        assert!(res.is_valid, "{alg:?} failed: {res:?}");
    }
}

/// Exercises expected-alg mismatch, missing alg, and missing public key branches.
#[test]
fn detached_streaming_reports_expected_alg_mismatch_missing_alg_and_missing_public_key_bytes() {
    use cosesign1::verify_parsed_cose_sign1_detached_payload_reader;

    // expected_alg mismatch
    let protected = encode_protected_header_bytes(&[(
        1,
        TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64),
    )]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: Some(cosesign1::CoseAlgorithm::ES384),
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("ALG_MISMATCH")));

    // missing alg header
    let protected = encode_protected_header_bytes(&[]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_OR_INVALID_ALG")));

    // missing public key bytes (this is the detached-streaming verifier's own branch)
    let protected = encode_protected_header_bytes(&[(
        1,
        TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64),
    )]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: None,
        expected_alg: None,
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

/// Bad signature bytes are mapped consistently for RSA prehash verifiers.
#[test]
fn rsa_detached_streaming_maps_bad_signature_bytes_in_prehash_verifiers() {
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    for alg in [cosesign1::CoseAlgorithm::RS256, cosesign1::CoseAlgorithm::PS256] {
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);
        let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(b"".to_vec());
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(rsa_spki.as_bytes()));
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("BAD_SIGNATURE")));
    }
}

/// Detached streaming verification reports a clear error if the payload stream
/// reports an invalid position (e.g., current position beyond end).
#[test]
fn detached_streaming_reports_invalid_payload_stream_position() {
    struct BadPositionReader;

    impl std::io::Read for BadPositionReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl std::io::Seek for BadPositionReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            match pos {
                // `stream_position()` calls `seek(SeekFrom::Current(0))`.
                SeekFrom::Current(0) => Ok(10),
                // Length computation uses `seek(SeekFrom::End(0))`.
                SeekFrom::End(0) => Ok(5),
                // Reset back to start position.
                SeekFrom::Start(n) => Ok(n),
                // Other seeks aren't used by this test.
                _ => Ok(0),
            }
        }
    }

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = BadPositionReader;
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
    assert!(res
        .failures
        .iter()
        .any(|f| f.message.contains("invalid payload stream position")));
}

/// Detached streaming surfaces errors if seeking to the end of the payload fails.
#[test]
fn detached_streaming_reports_seek_to_end_failure() {
    struct EndSeekFailsReader;

    impl std::io::Read for EndSeekFailsReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl std::io::Seek for EndSeekFailsReader {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            match pos {
                SeekFrom::Current(0) => Ok(0),
                SeekFrom::End(0) => Err(std::io::Error::new(std::io::ErrorKind::Other, "boom")),
                SeekFrom::Start(n) => Ok(n),
                _ => Ok(0),
            }
        }
    }

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = EndSeekFailsReader;
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
    assert!(res
        .failures
        .iter()
        .any(|f| f.message.contains("failed to seek payload")));
}
