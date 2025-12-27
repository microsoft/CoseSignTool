// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for `CoseSign1` high-level verification methods.
//!
//! These tests focus on:
//! - `CoseSign1::verify_signature` (embedded payload)
//! - provider resolution (x5c provider vs explicit override)
//! - basic failure mapping when providers do not match

mod common;

use common::*;
use cosesign1_abstractions::SigningKeyProviderId;
use std::io::Cursor;

/// Missing provider match leads to `MISSING_PUBLIC_KEY`.
#[test]
fn verify_signature_reports_missing_public_key_when_no_provider_matches() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

/// Malformed x5c headers are mapped to provider errors.
#[test]
fn verify_signature_reports_provider_error_when_x5c_header_is_malformed() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Null]),
    )];
    let cose = encode_cose_sign1(false, &protected, &unprotected_bad_x5c, Some(b"hello"), &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PUBLIC_KEY_PROVIDER_ERROR")));
}

/// A valid ES256 signature is verified via the x5c provider.
#[test]
fn verify_signature_succeeds_via_x5c_provider() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(true, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, None);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some(cosesign1_x509::X5C_PROVIDER_NAME)
    );
}

/// A caller-provided public key override bypasses provider resolution.
#[test]
fn verify_signature_succeeds_with_public_key_override() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, Some(cert_der.as_slice()));
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some("override")
    );
}

/// Missing provider match leads to `MISSING_PUBLIC_KEY` for the payload-reader API.
#[test]
fn verify_signature_with_payload_reader_reports_missing_public_key_when_no_provider_matches() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = Cursor::new(b"hello".to_vec());
    let res = msg.verify_signature_with_payload_reader(&mut rdr, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

/// Malformed x5c headers are mapped to provider errors for the payload-reader API.
#[test]
fn verify_signature_with_payload_reader_reports_provider_error_when_x5c_header_is_malformed() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Null]),
    )];
    let cose = encode_cose_sign1(false, &protected, &unprotected_bad_x5c, None, &[0u8; 64]);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = Cursor::new(b"hello".to_vec());
    let res = msg.verify_signature_with_payload_reader(&mut rdr, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PUBLIC_KEY_PROVIDER_ERROR")));
}

/// A valid detached ES256 signature is verified via the x5c provider, and records provider metadata.
#[test]
fn verify_signature_with_payload_reader_succeeds_via_x5c_provider_and_records_provider_name() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let payload = b"hello";

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256_detached_with_key(payload, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = Cursor::new(payload.to_vec());
    let res = msg.verify_signature_with_payload_reader(&mut rdr, None);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some(cosesign1_x509::X5C_PROVIDER_NAME)
    );
}

/// A caller-provided public key override bypasses provider resolution for the payload-reader API.
#[test]
fn verify_signature_with_payload_reader_succeeds_with_public_key_override_and_records_override() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let payload = b"hello";

    let protected = [(1i64, TestCborValue::Int(cosesign1::CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256_detached_with_key(payload, &protected, &unprotected, &signing_key);
    let msg = cosesign1::CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = Cursor::new(payload.to_vec());
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(cert_der.as_slice()));
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some("override")
    );
}
