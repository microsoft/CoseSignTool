// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for the top-level verification APIs.
//!
//! These tests focus on the `cosesign1::*` free functions:
//! - `verify_cose_sign1`
//! - `verify_parsed_cose_sign1`
//!
//! They validate error mapping when parsing or required headers/options are
//! missing.

mod common;

use common::*;
use std::io::Cursor;

/// Covers additional alg header values by forcing verification failure.
#[test]
fn verify_cose_sign1_covers_more_alg_header_values() {
    let msg = b"hello";
    let sig = vec![0u8; 1];

    for alg in [-7i64, -35, -36, -48, -49, -50, -37, -257] {
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg))]);
        let cose = encode_cose_sign1(false, &protected, &[], Some(msg), &sig);
        let opts = cosesign1::VerifyOptions {
            external_payload: None,
            public_key_bytes: Some(vec![1u8]),
            expected_alg: None,
        };
        let res = cosesign1::verify_cose_sign1("Signature", &cose, &opts);
        assert!(!res.is_valid);
    }
}

/// Exercises several error branches in `verify_parsed_cose_sign1`.
#[test]
fn verify_parsed_cose_sign1_error_paths_are_exercised() {
    // Missing alg.
    let protected = encode_protected_header_bytes(&[]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = cosesign1::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);

    // Unsupported alg.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-999))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    let res = cosesign1::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);

    // alg in unprotected map.
    let protected = encode_protected_header_bytes(&[]);
    let unprotected = vec![(TestCborKey::Int(1), TestCborValue::Int(-7))];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    let opts2 = cosesign1::VerifyOptions {
        public_key_bytes: None,
        ..opts.clone()
    };
    let res = cosesign1::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts2);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));

    // Sig_structure error for detached payload without external payload.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();
    let res = cosesign1::verify_parsed_cose_sign1("Signature", &parsed, None, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

/// Verifying garbage bytes yields a parse error result.
#[test]
fn verify_cose_sign1_reports_parse_error_for_garbage() {
    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = cosesign1::verify_cose_sign1("Signature", &[0xff, 0xff, 0xff], &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("COSE_PARSE_ERROR")));
}

/// `expected_alg` mismatches are reported as `ALG_MISMATCH`.
#[test]
fn verify_expected_alg_mismatch_is_reported() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();

    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(cert_der),
        expected_alg: Some(cosesign1::CoseAlgorithm::RS256),
    };

    let res = cosesign1::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("ALG_MISMATCH")));
}

/// Detached-payload streaming verification reports `MISSING_OR_INVALID_ALG` when `alg` is absent.
#[test]
fn verify_parsed_detached_payload_reader_reports_missing_alg() {
    let protected = encode_protected_header_bytes(&[]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = cosesign1::parse_cose_sign1(&cose).unwrap();

    let opts = cosesign1::VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };

    let mut rdr = Cursor::new(b"hello".to_vec());
    let res = cosesign1::verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut rdr, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_OR_INVALID_ALG")));
}
