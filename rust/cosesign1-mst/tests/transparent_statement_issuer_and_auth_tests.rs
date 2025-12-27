// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transparent statement verification (issuer parsing + authorization decisions).
//!
//! These tests cover:
//! - How issuer is read from receipt headers (CWT map vs bytes)
//! - How unauthorized receipts are treated based on `VerificationOptions`
//! - How failures are bucketed and surfaced

mod common;

use common::*;
use cosesign1::CoseAlgorithm;
use cosesign1_mst::{
    verify_transparent_statement, AuthorizedReceiptBehavior, OfflineEcKeyStore, ResolvedKey,
    UnauthorizedReceiptBehavior, VerificationOptions,
};
use p256::pkcs8::EncodePublicKey;

#[test]
fn transparent_statement_unauthorized_receipts_are_ignored_when_configured() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[44u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let issuer_authorized = "issuer.example";
    let issuer_unauthorized = "other.example";
    let kid_authorized = "kid-1";
    let kid_unauthorized = "kid-2";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let receipt_authorized = build_receipt_es256(kid_authorized, issuer_authorized, &statement_without_unprotected, &sk);
    let receipt_unauthorized =
        build_receipt_es256(kid_unauthorized, issuer_unauthorized, &statement_without_unprotected, &sk);

    let statement = encode_statement_with_receipts(
        statement_payload,
        statement_sig,
        &[receipt_authorized.clone(), receipt_unauthorized.clone()],
    );

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
    key_store.insert(
        issuer_authorized,
        kid_authorized,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer_authorized.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert_eq!(res.metadata.get("receipts").map(|s| s.as_str()), Some("2"));
}

#[test]
fn transparent_statement_cwt_bytes_decode_error_yields_unknown_issuer() {
    // CWT is present as bytes, but the bytes are not valid CBOR.
    let mut protected = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap(); // ES256
        enc.i64(4).unwrap();
        enc.bytes(b"kid-1").unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap(); // vds = CCF
        enc.i64(15).unwrap();
        enc.bytes(&[0xff]).unwrap();
    }

    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec!["issuer.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::FailIfPresent;

    let key_store = OfflineEcKeyStore::default();
    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNAUTHORIZED_RECEIPT"));
}

#[test]
fn transparent_statement_reads_issuer_from_cwt_bytes_and_reports_key_not_found() {
    let kid = "kid-1";
    let issuer = "issuer.example";
    let protected = encode_receipt_headers(kid, Some(issuer), Some(2), true);
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_KEY_NOT_FOUND")));
}

#[test]
fn transparent_statement_reads_issuer_from_cwt_map_and_wrong_type_yields_unknown_issuer() {
    let kid = "kid-1";
    let issuer = "issuer.example";

    let protected_map = encode_receipt_headers(kid, Some(issuer), Some(2), false);
    let receipt1 = encode_receipt_with_vdp_value(&protected_map, None, b"sig");

    let protected_wrong = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.i64(123).unwrap();
        out
    };
    let receipt2 = encode_receipt_with_vdp_value(&protected_wrong, None, b"sig");

    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt1, receipt2]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_UNKNOWN_ISSUER")));
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_KEY_NOT_FOUND")));
}

#[test]
fn transparent_statement_cwt_iss_non_text_yields_unknown_issuer() {
    let kid = "kid-1";

    let protected = {
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.map(4).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(4).unwrap();
        enc.bytes(kid.as_bytes()).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(123).unwrap();
        out
    };
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_UNKNOWN_ISSUER")));
}

#[test]
fn transparent_statement_unauthorized_receipt_verification_failures_are_bucketed() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[30u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let mut receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    *receipt.last_mut().unwrap() ^= 0x01;
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec!["different.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAnyMatching;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_RECEIPT_SIGNATURE_INVALID")));
}

#[test]
fn transparent_statement_verify_all_matching_reports_required_domain_failed() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[24u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer = "issuer.example";
    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let mut receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    *receipt.last_mut().unwrap() ^= 0x01;
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAllMatching;

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_REQUIRED_DOMAIN_FAILED")));
}

#[test]
fn transparent_statement_fail_if_present_rejects_unauthorized_receipt() {
    let kid = "kid-1";
    let receipt = encode_receipt_with_vdp_value(
        &encode_receipt_headers(kid, Some("issuer.example"), Some(2), false),
        None,
        b"sig",
    );
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec!["good.example".to_string()];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::FailIfPresent;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNAUTHORIZED_RECEIPT"));
}

#[test]
fn transparent_statement_unknown_issuer_verifyall_reports_unknown_issuer() {
    let kid = "kid-1";
    // Receipt parses but has no issuer.
    let protected = encode_receipt_headers(kid, None, Some(2), false);
    let receipt = encode_receipt_with_vdp_value(&protected, None, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_UNKNOWN_ISSUER"));
}

#[test]
fn transparent_statement_supports_non_ascii_kid_via_hex_normalization() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[14u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let issuer = "issuer.example";
    let kid_bytes = [0u8, 1, 255];
    let kid_hex = "0001ff";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256_with_kid_bytes(&kid_bytes, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt]);

    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let mut key_store = OfflineEcKeyStore::default();
    key_store.insert(
        issuer,
        kid_hex,
        ResolvedKey {
            public_key_bytes: der.as_bytes().to_vec(),
            expected_alg: CoseAlgorithm::ES256,
        },
    );

    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![issuer.to_string()];

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}
