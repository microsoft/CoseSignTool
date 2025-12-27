// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transparent statement verification (basic shapes).
//!
//! These tests focus on how the verifier interprets the *statement* structure:
//! receipts header presence/shape, payload being bytes vs null, and basic happy-path.

mod common;

use common::*;
use cosesign1::CoseAlgorithm;
use cosesign1_mst::{
    verify_transparent_statement, AuthorizedReceiptBehavior, OfflineEcKeyStore, ResolvedKey,
    UnauthorizedReceiptBehavior, VerificationOptions,
};
use p256::pkcs8::EncodePublicKey;

#[test]
fn transparent_statement_happy_path_verifies() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[4u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);
    let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt.clone()]);

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
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

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
    assert_eq!(res.metadata.get("receipts").map(|s| s.as_str()), Some("1"));
}

#[test]
fn transparent_statement_receipts_wrapped_array_is_accepted() {
    // Encode receipts header value as a bstr containing a CBOR array of bstr receipts.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);

    let mut receipts_array = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut receipts_array);
        enc.array(1).unwrap();
        enc.bytes(&receipt).unwrap();
    }

    let statement = encode_statement_with_receipts_value(Some(statement_payload), statement_sig, &receipts_array);

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
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

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn transparent_statement_with_null_payload_verifies() {
    // Statement payload is null and receipts are embedded normally.
    let sk = p256::ecdsa::SigningKey::from_bytes(&[6u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();

    let kid = "kid-1";
    let issuer = "issuer.example";

    let statement_sig = b"sig";
    let statement_without_unprotected = encode_statement_without_unprotected_payload(None, statement_sig);
    let receipt = build_receipt_es256(kid, issuer, &statement_without_unprotected, &sk);

    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(1).unwrap();
        enc.bytes(&receipt).unwrap();
        enc.null().unwrap();
        enc.bytes(statement_sig).unwrap();
        out
    };

    let mut key_store = OfflineEcKeyStore::default();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();
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

    let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
    assert!(res.is_valid, "{:?}", res.failures);
}

#[test]
fn transparent_statement_rejects_receipts_with_wrong_element_type() {
    // Statement unprotected header 394 is an array, but an element is not a bstr.
    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(1).unwrap();
        enc.i64(123).unwrap();
        enc.bytes(b"payload").unwrap();
        enc.bytes(b"sig").unwrap();
        out
    };

    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_missing_receipts_header_reports_no_receipt() {
    let statement = encode_statement_without_unprotected(b"payload", b"sig");
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_receipts_wrapped_array_rejects_non_bstr_element() {
    // receipts header is a bstr wrapping a CBOR array, but the array element is not a bstr.
    let mut receipts_array = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut receipts_array);
        enc.array(1).unwrap();
        enc.i64(123).unwrap();
    }
    let statement = encode_statement_with_receipts_value(Some(b"payload"), b"sig", &receipts_array);
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_receipts_wrapped_value_not_array_reports_no_receipt() {
    // receipts header is a bstr wrapping a CBOR value that is not an array.
    let mut not_array = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut not_array);
        enc.map(0).unwrap();
    }
    let statement = encode_statement_with_receipts_value(Some(b"payload"), b"sig", &not_array);
    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_invalid_cbor_reports_parse_error() {
    let res = verify_transparent_statement(
        "mst",
        b"not-cbor",
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("CBOR_PARSE_ERROR"));
}

#[test]
fn transparent_statement_empty_receipts_array_reports_no_receipt() {
    let statement = {
        let protected_empty: Vec<u8> = Vec::new();
        let mut out = Vec::new();
        let mut enc = minicbor::Encoder::new(&mut out);
        enc.array(4).unwrap();
        enc.bytes(&protected_empty).unwrap();
        enc.map(1).unwrap();
        enc.i64(394).unwrap();
        enc.array(0).unwrap();
        enc.bytes(b"payload").unwrap();
        enc.bytes(b"sig").unwrap();
        out
    };

    let res = verify_transparent_statement(
        "mst",
        &statement,
        &OfflineEcKeyStore::default(),
        &VerificationOptions::default(),
    );
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_RECEIPT"));
}

#[test]
fn transparent_statement_reports_kid_missing_in_receipt() {
    let issuer = "issuer.example";

    // Protected headers: alg, vds, issuer; no KID.
    let mut protected = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected);
        enc.map(3).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        enc.i64(395).unwrap();
        enc.i64(2).unwrap();
        enc.i64(15).unwrap();
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.str(issuer).unwrap();
    }
    let inclusion_map = encode_inclusion_map_with_path(b"claims", &[]);
    let receipt = encode_receipt(&protected, &inclusion_map, b"sig");
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[receipt]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_KID_MISSING")));
}

#[test]
fn transparent_statement_no_authorized_and_ignoreall_reports_no_verifiable_receipts() {
    // If we're configured to ignore unauthorized receipts and we have no authorized domains,
    // there is nothing verifiable.
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);
    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_VERIFIABLE_RECEIPTS"));
}

#[test]
fn transparent_statement_reports_receipt_parse_errors_when_verifyall() {
    // Receipt bytes are not CBOR.
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);

    let mut opts = VerificationOptions::default();
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_RECEIPT_PARSE_ERROR"));
}

#[test]
fn transparent_statement_authorized_domain_normalization_ignores_empty_and_unknown() {
    // Empty strings and the internal "unknown issuer" sentinel should be ignored.
    let statement = encode_statement_with_receipts(b"payload", b"sig", &[b"not-cbor".to_vec()]);
    let mut opts = VerificationOptions::default();
    opts.authorized_domains = vec![
        "".to_string(),
        "__unknown-issuer::0".to_string(),
        "issuer.example".to_string(),
    ];
    opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::VerifyAll;

    let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
    assert!(!res.is_valid);
}

#[test]
fn transparent_statement_authorized_behavior_variants() {
    let sk = p256::ecdsa::SigningKey::from_bytes(&[15u8; 32].into()).expect("sk");
    let vk = sk.verifying_key();
    let der = p256::PublicKey::from_sec1_bytes(vk.to_encoded_point(false).as_bytes())
        .unwrap()
        .to_public_key_der()
        .unwrap();

    let kid = "kid-1";
    let issuer1 = "issuer1.example";
    let issuer2 = "issuer2.example";

    let statement_sig = b"sig";
    let statement_payload = b"payload";
    let statement_without_unprotected = encode_statement_without_unprotected(statement_payload, statement_sig);

    let receipt1 = build_receipt_es256(kid, issuer1, &statement_without_unprotected, &sk);
    let receipt2 = build_receipt_es256(kid, issuer2, &statement_without_unprotected, &sk);

    // VerifyAnyMatching succeeds if at least one authorized receipt verifies.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt1.clone(), receipt2.clone()]);
        let mut key_store = OfflineEcKeyStore::default();
        key_store.insert(
            issuer1,
            kid,
            ResolvedKey {
                public_key_bytes: der.as_bytes().to_vec(),
                expected_alg: CoseAlgorithm::ES256,
            },
        );

        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string(), issuer2.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAnyMatching;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

        let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
        assert!(res.is_valid, "{:?}", res.failures);
    }

    // VerifyAllMatching: if no receipts exist for authorized domains, fail.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt2.clone()]);
        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::VerifyAllMatching;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;
        let res = verify_transparent_statement("mst", &statement, &OfflineEcKeyStore::default(), &opts);
        assert!(!res.is_valid);
        assert_eq!(res.failures[0].error_code.as_deref(), Some("MST_NO_VALID_AUTHORIZED_RECEIPTS"));
    }

    // RequireAll: if a required domain is missing, fail.
    {
        let statement = encode_statement_with_receipts(statement_payload, statement_sig, &[receipt1.clone()]);
        let mut key_store = OfflineEcKeyStore::default();
        key_store.insert(
            issuer1,
            kid,
            ResolvedKey {
                public_key_bytes: der.as_bytes().to_vec(),
                expected_alg: CoseAlgorithm::ES256,
            },
        );

        let mut opts = VerificationOptions::default();
        opts.authorized_domains = vec![issuer1.to_string(), issuer2.to_string()];
        opts.authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;
        opts.unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::IgnoreAll;

        let res = verify_transparent_statement("mst", &statement, &key_store, &opts);
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("MST_REQUIRED_DOMAIN_MISSING")));
    }
}
