// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for COSE hash envelope (payload-hash-alg).
//!
//! These tests exercise the branches where the COSE_Sign1 payload contains the
//! digest of an external preimage, and verification recomputes and compares the
//! digest prior to running the signature verification step.

mod common;

use common::*;
use sha2::Digest as _;

use std::io::{Read, Seek, SeekFrom};

/// Exercises invalid indirect signature errors and digest mismatch reporting.
#[test]
fn verify_signature_with_payload_reader_exercises_hash_envelope_errors_and_mismatch() {
    // Empty embedded digest is invalid.
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b""), &[0u8; 64]);
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"abc".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));

    // Digest mismatch.
    let digest = sha2::Sha256::digest(b"expected");
    let msg = encode_cose_sign1(
        false,
        &protected,
        &[],
        Some(AsRef::<[u8]>::as_ref(&digest)),
        &[0u8; 64],
    );
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"different".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
}

#[test]
fn verify_signature_with_payload_reader_rejects_unprotected_payload_hash_alg() {
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);

    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(258), TestCborValue::Int(-16))];
    let msg = encode_cose_sign1(false, &protected, &unprotected, Some(&[1u8; 32]), &[0u8; 64]);
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();

    let mut payload = std::io::Cursor::new(b"preimage".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

#[test]
fn verify_signature_with_payload_reader_reports_payload_read_error() {
    struct AlwaysFailReader;

    impl Read for AlwaysFailReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::Other, "read failed"))
        }
    }

    impl Seek for AlwaysFailReader {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);

    let digest = sha2::Sha256::digest(b"expected");
    let msg = encode_cose_sign1(
        false,
        &protected,
        &[],
        Some(AsRef::<[u8]>::as_ref(&digest)),
        &[0u8; 64],
    );
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();

    let mut payload = AlwaysFailReader;
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_READ_ERROR")));
}

/// Validates SHA-384 and SHA-512 hash envelope support.
#[test]
fn cose_hash_envelope_supports_sha384_and_sha512() {
    for (hash_alg_header, digest_len) in [(-43i64, 48usize), (-44i64, 64usize)] {
        let protected = encode_protected_header_bytes(&[
            (1, TestCborValue::Int(-7)),
            (258, TestCborValue::Int(hash_alg_header)),
        ]);

        let msg = encode_cose_sign1(false, &protected, &[], Some(&vec![0u8; digest_len]), &[0u8; 64]);
        let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();

        let mut payload = std::io::Cursor::new(b"preimage".to_vec());
        let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
    }
}

/// Drives the in-memory hash envelope verifier (non-reader path) for SHA-384 and SHA-512.
#[test]
fn verify_hash_envelope_sha384_and_sha512_mismatch_uses_in_memory_hashing() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    for (hash_alg_header, preimage) in [(-43i64, b"preimage-384".as_slice()), (-44i64, b"preimage-512".as_slice())] {
        let embedded_digest = match hash_alg_header {
            -43 => sha2::Sha384::digest(preimage).to_vec(),
            -44 => sha2::Sha512::digest(preimage).to_vec(),
            _ => unreachable!(),
        };

        let protected = [
            (1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64)),
            (258i64, TestCborValue::Int(hash_alg_header)),
        ];

        // Note: the COSE payload is the digest; verification compares against `payload_to_verify`.
        let cose = sign_es256(false, Some(embedded_digest.as_slice()), None, &protected, &[], &signing_key);
        let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

        let res = msg.verify_signature(Some(b"different-preimage"), Some(&[0u8; 1]));
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
    }
}

/// Ensures digest checking is skipped if no payload bytes are provided to verify.
#[test]
fn cose_hash_envelope_without_payload_to_verify_skips_digest_check() {
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"not-a-digest"), &[0u8; 64]);
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();
    let res = cose.verify_signature(None, Some(b"bad-key"));
    assert!(!res.is_valid);
    // Crucially: we skipped digest checking, so we should not report PAYLOAD_MISMATCH.
    assert!(!res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
}

/// Ensures a matching digest does not short-circuit signature verification.
#[test]
fn cose_hash_envelope_with_matching_digest_does_not_short_circuit() {
    let preimage = b"hello-hash-envelope";
    let digest = sha2::Sha256::digest(preimage);

    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);

    let msg = encode_cose_sign1(false, &protected, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();

    let res = cose.verify_signature(Some(preimage), Some(b"definitely-not-a-public-key"));
    assert!(!res.is_valid);
    assert_ne!(
        res.failures
            .first()
            .and_then(|f| f.error_code.as_deref()),
        Some("PAYLOAD_MISMATCH")
    );
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some("override")
    );
}

/// Ensures SHA-384 and SHA-512 digest match continues into the signature step.
#[test]
fn verify_signature_with_payload_reader_hash_envelope_sha384_and_sha512_match_executes_signature_step() {
    for (hash_alg_header, digest_bytes) in [
        (-43i64, sha2::Sha384::digest(b"preimage").to_vec()),
        (-44i64, sha2::Sha512::digest(b"preimage").to_vec()),
    ] {
        let protected = encode_protected_header_bytes(&[
            (1, TestCborValue::Int(-7)),
            (258, TestCborValue::Int(hash_alg_header)),
        ]);
        let msg = encode_cose_sign1(false, &protected, &[], Some(digest_bytes.as_slice()), &[0u8; 64]);
        let cose = cosesign1::CoseSign1::from_bytes(&msg).unwrap();

        let mut payload = std::io::Cursor::new(b"preimage".to_vec());
        let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
        assert!(!res.is_valid);
        // Digest check passed, so we should not report PAYLOAD_MISMATCH.
        assert!(!res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
    }
}

/// Rejects a digest mismatch for a signed hash envelope message.
#[test]
fn verify_hash_envelope_mismatch_is_rejected() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [
        (1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64)),
        (258i64, TestCborValue::Int(-16)),
    ];
    let unprotected = x5c_unprotected_header(cert_der);

    let embedded_digest = vec![1u8; 32];
    let cose = sign_es256(false, Some(embedded_digest.as_slice()), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"not the preimage"), None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
}

/// Rejects unprotected payload-hash-alg headers.
#[test]
fn verify_hash_envelope_rejects_unprotected_payload_hash_alg() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(258), TestCborValue::Int(-16))];

    let cose = sign_es256(false, Some(&[1u8; 32]), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"anything"), None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

/// Rejects empty digest bytes for hash envelope payloads.
#[test]
fn verify_hash_envelope_rejects_empty_digest_bytes() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [
        (1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64)),
        (258i64, TestCborValue::Int(-16)),
    ];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![];

    let cose = sign_es256(false, Some(&[]), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"preimage"), Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

/// Rejects unsupported `payload-hash-alg` values.
#[test]
fn cose_hash_envelope_rejects_unsupported_hash_alg_value() {
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64)),
        (258, TestCborValue::Int(-999)),
    ]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"digest"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"payload"), Some(b"pk"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}
