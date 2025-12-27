// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for MST (transparent statements) verification helpers.
//!
//! The MST verifier is in `cosesign1_mst` and is consumed by the `cosesign1`
//! pipeline. These tests cover CBOR parsing branches and error reporting.

mod common;

use common::*;

/// Reads receipt issuer from both map and bstr-wrapped map forms.
#[test]
fn mst_verifier_reads_receipt_issuer_from_map_and_bstr() {
    // Receipt 1: protected header CWT map (label 15) is wrapped in a bstr.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.str("issuer.example").unwrap();
    let cwt_map_bytes = enc.into_writer();

    let receipt1_protected = encode_protected_header_bytes(&[
        (15, TestCborValue::Bytes(cwt_map_bytes)),
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt1 = encode_cose_sign1(true, &receipt1_protected, &[], None, &[]);

    // Receipt 2: protected header CWT map is a map, but iss is not a text string => issuer becomes unknown.
    let receipt2_protected = encode_protected_header_bytes(&[
        (
            15,
            TestCborValue::Map(vec![(TestCborKey::Int(1), TestCborValue::Int(123))]),
        ),
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt2 = encode_cose_sign1(true, &receipt2_protected, &[], None, &[]);

    // Transparent statement with embedded receipts in unprotected header label 394.
    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![(
        TestCborKey::Int(394),
        TestCborValue::Array(vec![TestCborValue::Bytes(receipt1), TestCborValue::Bytes(receipt2)]),
    )];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let options = cosesign1_mst::VerificationOptions::default();
    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_UNAUTHORIZED_RECEIPT")));
}

/// Invalid CBOR inside VDP maps to an inclusion parse error.
#[test]
fn mst_verifier_reports_inclusion_parse_error_for_invalid_cbor_in_vdp() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(TestCborKey::Int(-1), TestCborValue::Bytes(vec![0xff, 0x00]))]),
    )];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);

    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_INCLUSION_PARSE_ERROR")));
}

/// Malformed proof paths map to MST path parse error.
#[test]
fn mst_verifier_reports_path_parse_error_for_malformed_proof_path() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    // Inclusion proof map: { 2: [ [ true ] ] }  (path element length != 2)
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(2).unwrap();
    enc.array(1).unwrap();
    enc.array(1).unwrap();
    enc.bool(true).unwrap();
    let inclusion_map_bytes = enc.into_writer();

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes)]),
        )]),
    )];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);

    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_PATH_PARSE_ERROR")));
}

/// Exercises JWKS parsing and offline key store insertion paths.
#[test]
fn mst_jwks_parsing_and_key_store_add_paths() {
    assert!(cosesign1_mst::parse_jwks(b"not-json").is_err());

    let jwks = r#"{
            "keys": [
                {"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"k1"},
                {"kty":"EC","crv":"P-999","x":"AA","y":"AA","kid":"skip-curve"},
                {"kty":"RSA","crv":"P-256","x":"AA","y":"AA","kid":"skip-kty"}
            ]
        }"#;
    let doc = cosesign1_mst::parse_jwks(jwks.as_bytes()).unwrap();
    let mut store = cosesign1_mst::OfflineEcKeyStore::default();

    // First key is syntactically valid JSON but not a valid EC point; add_issuer_keys should error.
    assert!(cosesign1_mst::add_issuer_keys(&mut store, "issuer.example", &doc).is_err());
}

/// Accepts an embedded receipts array when the array is wrapped in a bstr.
#[test]
fn mst_verifier_accepts_embedded_receipts_array_wrapped_in_bstr() {
    let receipt_protected = encode_protected_header_bytes(&[
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt = encode_cose_sign1(true, &receipt_protected, &[], None, &[]);

    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(1).unwrap();
    enc.bytes(&receipt).unwrap();
    let receipts_array_cbor = enc.into_writer();

    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![(TestCborKey::Int(394), TestCborValue::Bytes(receipts_array_cbor))];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let mut options = cosesign1_mst::VerificationOptions::default();
    options.unauthorized_receipt_behavior = cosesign1_mst::UnauthorizedReceiptBehavior::VerifyAll;
    options.authorized_receipt_behavior = cosesign1_mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
}

/// Inserts supported keys and skips unsupported ones.
#[test]
fn mst_add_issuer_keys_inserts_supported_keys_and_skips_unsupported() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let good = make_p256_jwk("kid1", &signing_key);

    let doc = cosesign1_mst::JwksDocument {
        keys: vec![
            good.clone(),
            cosesign1_mst::JwkEcPublicKey {
                kty: "EC".to_string(),
                crv: "P-999".to_string(),
                x: "AA".to_string(),
                y: "AA".to_string(),
                kid: "skip-curve".to_string(),
            },
            cosesign1_mst::JwkEcPublicKey {
                kty: "RSA".to_string(),
                crv: "P-256".to_string(),
                x: "AA".to_string(),
                y: "AA".to_string(),
                kid: "skip-kty".to_string(),
            },
        ],
    };

    let mut store = cosesign1_mst::OfflineEcKeyStore::default();
    let inserted = cosesign1_mst::add_issuer_keys(&mut store, "issuer.example", &doc).unwrap();
    assert_eq!(inserted, 1);
    assert!(store.resolve("issuer.example", "kid1").is_some());
}

/// Rejects a non-bstr element inside a bstr-wrapped receipts array.
#[test]
fn mst_verifier_reports_non_bstr_element_in_receipts_wrapped_array() {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(1).unwrap();
    enc.i64(1).unwrap();
    let receipts_array_cbor = enc.into_writer();

    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![(TestCborKey::Int(394), TestCborValue::Bytes(receipts_array_cbor))];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let options = cosesign1_mst::VerificationOptions::default();
    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
}

/// Exercises path-bytes decoding and missing leaf reporting.
#[test]
fn mst_verifier_path_bytes_branch_and_leaf_missing_are_exercised() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    // Path encoded as a bstr containing a CBOR array, but malformed (inner length != 2).
    let mut path_enc = minicbor::Encoder::new(Vec::new());
    path_enc.array(1).unwrap();
    path_enc.array(1).unwrap();
    path_enc.bool(true).unwrap();
    let bad_path_bytes = path_enc.into_writer();

    let mut map_enc = minicbor::Encoder::new(Vec::new());
    map_enc.map(1).unwrap();
    map_enc.i64(2).unwrap();
    map_enc.bytes(&bad_path_bytes).unwrap();
    let inclusion_map_bytes = map_enc.into_writer();

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes)]),
        )]),
    )];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);
    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_PATH_PARSE_ERROR")));

    // Path parses successfully, but leaf is missing => MST_LEAF_MISSING.
    let mut map_enc = minicbor::Encoder::new(Vec::new());
    map_enc.map(1).unwrap();
    map_enc.i64(2).unwrap();
    // Re-encode as value: [[true, h]]
    map_enc.array(1).unwrap();
    map_enc.array(2).unwrap();
    map_enc.bool(true).unwrap();
    map_enc.bytes(&[1u8]).unwrap();
    let inclusion_map_bytes2 = map_enc.into_writer();

    let receipt_unprotected2 = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes2)]),
        )]),
    )];
    let receipt2 = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected2, None, &[]);
    let res2 = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert!(res2
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MST_LEAF_MISSING")));
}
