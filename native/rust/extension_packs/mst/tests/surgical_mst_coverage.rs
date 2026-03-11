// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical tests targeting uncovered lines in receipt_verify.rs and client.rs.
//!
//! Focuses on:
//! - extract_proof_blobs error paths (not a map, proof not array, item not bstr, empty, missing)
//! - parse_leaf malformed CBOR
//! - parse_path malformed CBOR and error branches
//! - ccf_accumulator_sha256 error paths (wrong hash lengths, hash mismatch)
//! - jwk_to_spki_der error paths (non-EC kty, missing crv, unsupported crv, missing x/y, wrong len)
//! - validate_receipt_alg_against_jwk error paths
//! - find_jwk_for_kid error paths
//! - ring_verifier_for_cose_alg
//! - reencode_statement_with_cleared_unprotected_headers
//! - is_cose_sign1_tagged_18
//! - get_cwt_issuer_host
//! - MstCcfInclusionProof::parse error paths
//! - Client poll_operation via mock HTTP transport
//! - read_cbor_text_field edge cases

use cbor_primitives::CborEncoder;
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, ProtectedHeader};
use cose_sign1_transparent_mst::validation::receipt_verify::*;

// ═══════════════════════════════════════════════════════════════════════════
// extract_proof_blobs
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn extract_proof_blobs_not_a_map() {
    let value = CoseHeaderValue::Int(42);
    let result = extract_proof_blobs(&value);
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("vdp_not_a_map"), "got: {}", msg);
        }
        other => panic!("Expected ReceiptDecode(vdp_not_a_map), got: {:?}", other),
    }
}

#[test]
fn extract_proof_blobs_proof_not_array() {
    let value = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Int(42), // Should be Array, not Int
    )]);
    let result = extract_proof_blobs(&value);
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("proof_not_array"), "got: {}", msg);
        }
        other => panic!("Expected ReceiptDecode(proof_not_array), got: {:?}", other),
    }
}

#[test]
fn extract_proof_blobs_item_not_bstr() {
    let value = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(42), // Should be Bytes, not Int
        ]),
    )]);
    let result = extract_proof_blobs(&value);
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("proof_item_not_bstr"), "got: {}", msg);
        }
        other => panic!("Expected ReceiptDecode(proof_item_not_bstr), got: {:?}", other),
    }
}

#[test]
fn extract_proof_blobs_empty_array() {
    let value = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![]),
    )]);
    let result = extract_proof_blobs(&value);
    match result {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn extract_proof_blobs_missing_proof_label() {
    let value = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(99), // Not -1
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(vec![1, 2, 3])]),
    )]);
    let result = extract_proof_blobs(&value);
    match result {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn extract_proof_blobs_success() {
    let value = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![0xAA, 0xBB]),
            CoseHeaderValue::Bytes(vec![0xCC, 0xDD]),
        ]),
    )]);
    let result = extract_proof_blobs(&value).expect("should succeed");
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], vec![0xAA, 0xBB]);
    assert_eq!(result[1], vec![0xCC, 0xDD]);
}

// ═══════════════════════════════════════════════════════════════════════════
// ccf_accumulator_sha256
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ccf_accumulator_wrong_internal_txn_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 16], // Should be 32
        internal_evidence: "evidence".into(),
        data_hash: vec![0u8; 32],
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("unexpected_internal_txn_hash_len"), "got: {}", msg);
        }
        other => panic!("Expected ReceiptDecode, got: {:?}", other),
    }
}

#[test]
fn ccf_accumulator_wrong_data_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".into(),
        data_hash: vec![0u8; 16], // Should be 32
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("unexpected_data_hash_len"), "got: {}", msg);
        }
        other => panic!("Expected ReceiptDecode, got: {:?}", other),
    }
}

#[test]
fn ccf_accumulator_data_hash_mismatch() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".into(),
        data_hash: vec![1u8; 32], // Doesn't match expected
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    match result {
        Err(ReceiptVerifyError::DataHashMismatch) => {}
        other => panic!("Expected DataHashMismatch, got: {:?}", other),
    }
}

#[test]
fn ccf_accumulator_success() {
    let data_hash = [0xAA_u8; 32];
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0xBB_u8; 32],
        internal_evidence: "test-evidence".into(),
        data_hash: data_hash.to_vec(),
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, data_hash);
    assert!(result.is_ok(), "should succeed");
    let acc = result.unwrap();
    assert_eq!(acc.len(), 32);
}

// ═══════════════════════════════════════════════════════════════════════════
// ring_verifier_for_cose_alg
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ring_verifier_es256() {
    assert!(ring_verifier_for_cose_alg(-7).is_ok());
}

#[test]
fn ring_verifier_es384() {
    assert!(ring_verifier_for_cose_alg(-35).is_ok());
}

#[test]
fn ring_verifier_unsupported() {
    match ring_verifier_for_cose_alg(-999) {
        Err(ReceiptVerifyError::UnsupportedAlg(-999)) => {}
        other => panic!("Expected UnsupportedAlg(-999), got: {:?}", other),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// validate_receipt_alg_against_jwk
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn validate_alg_jwk_missing_crv() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    match validate_receipt_alg_against_jwk(&jwk, -7) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("missing_crv"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(missing_crv), got: {:?}", other),
    }
}

#[test]
fn validate_alg_jwk_mismatch() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-384".into()),
        kid: None,
        x: None,
        y: None,
    };
    // P-384 expects ES384 (-35), not ES256 (-7)
    match validate_receipt_alg_against_jwk(&jwk, -7) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("alg_curve_mismatch"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(alg_curve_mismatch), got: {:?}", other),
    }
}

#[test]
fn validate_alg_jwk_p256_es256_ok() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-256".into()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -7).is_ok());
}

#[test]
fn validate_alg_jwk_p384_es384_ok() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-384".into()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -35).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════
// jwk_to_spki_der
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn jwk_to_spki_non_ec_kty() {
    let jwk = Jwk {
        kty: "RSA".into(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("kty=RSA"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(kty=RSA), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_missing_crv() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: None,
        kid: None,
        x: Some("AAAA".into()),
        y: Some("BBBB".into()),
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("missing_crv"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(missing_crv), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_unsupported_crv() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-521".into()),
        kid: None,
        x: Some("AAAA".into()),
        y: Some("BBBB".into()),
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("unsupported_crv=P-521"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(unsupported_crv), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_missing_x() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-256".into()),
        kid: None,
        x: None,
        y: Some("BBBB".into()),
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("missing_x"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(missing_x), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_missing_y() {
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-256".into()),
        kid: None,
        x: Some("AAAA".into()),
        y: None,
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("missing_y"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(missing_y), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_wrong_xy_len_p256() {
    // P-256 expects 32-byte x and y; encode 16 bytes as base64url
    let short_b64 = "AAAAAAAAAAAAAAAAAAAAAA"; // 16 bytes
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-256".into()),
        kid: None,
        x: Some(short_b64.into()),
        y: Some(short_b64.into()),
    };
    match jwk_to_spki_der(&jwk) {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("unexpected_xy_len"), "got: {}", msg);
        }
        other => panic!("Expected JwkUnsupported(unexpected_xy_len), got: {:?}", other),
    }
}

#[test]
fn jwk_to_spki_valid_p256() {
    // 32 bytes encoded as base64url (no padding)
    let x_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 bytes
    let y_b64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 32 bytes
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-256".into()),
        kid: None,
        x: Some(x_b64.into()),
        y: Some(y_b64.into()),
    };
    let result = jwk_to_spki_der(&jwk).expect("should succeed");
    assert_eq!(result.len(), 1 + 32 + 32); // 0x04 + x + y
    assert_eq!(result[0], 0x04);
}

#[test]
fn jwk_to_spki_valid_p384() {
    // 48 bytes encoded as base64url (no padding)
    let x_b64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 48 bytes
    let y_b64 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 48 bytes
    let jwk = Jwk {
        kty: "EC".into(),
        crv: Some("P-384".into()),
        kid: None,
        x: Some(x_b64.into()),
        y: Some(y_b64.into()),
    };
    let result = jwk_to_spki_der(&jwk).expect("should succeed");
    assert_eq!(result.len(), 1 + 48 + 48); // 0x04 + x + y
    assert_eq!(result[0], 0x04);
}

// ═══════════════════════════════════════════════════════════════════════════
// find_jwk_for_kid
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn find_jwk_invalid_json() {
    match find_jwk_for_kid("not json", "kid1") {
        Err(ReceiptVerifyError::JwksParse(_)) => {}
        other => panic!("Expected JwksParse, got: {:?}", other),
    }
}

#[test]
fn find_jwk_not_found() {
    let jwks_json = r#"{"keys":[{"kty":"EC","kid":"other","crv":"P-256"}]}"#;
    match find_jwk_for_kid(jwks_json, "missing-kid") {
        Err(ReceiptVerifyError::JwkNotFound(kid)) => {
            assert_eq!(kid, "missing-kid");
        }
        other => panic!("Expected JwkNotFound, got: {:?}", other),
    }
}

#[test]
fn find_jwk_found() {
    let jwks_json = r#"{"keys":[{"kty":"EC","kid":"kid1","crv":"P-256"},{"kty":"EC","kid":"kid2","crv":"P-384"}]}"#;
    let jwk = find_jwk_for_kid(jwks_json, "kid2").expect("should find kid2");
    assert_eq!(jwk.crv, Some("P-384".into()));
}

// ═══════════════════════════════════════════════════════════════════════════
// parse_leaf
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn parse_leaf_valid() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[0xAA; 32]).unwrap(); // internal_txn_hash
    enc.encode_tstr("evidence-string").unwrap(); // internal_evidence
    enc.encode_bstr(&[0xBB; 32]).unwrap(); // data_hash
    let bytes = enc.into_bytes();

    let (txn_hash, evidence, data_hash) = parse_leaf(&bytes).expect("should parse");
    assert_eq!(txn_hash, vec![0xAA; 32]);
    assert_eq!(evidence, "evidence-string");
    assert_eq!(data_hash, vec![0xBB; 32]);
}

#[test]
fn parse_leaf_malformed_not_array() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_i64(42).unwrap(); // Not an array
    let bytes = enc.into_bytes();

    assert!(parse_leaf(&bytes).is_err());
}

#[test]
fn parse_leaf_malformed_missing_evidence() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(2).unwrap();
    enc.encode_bstr(&[0xAA; 32]).unwrap(); // internal_txn_hash
    enc.encode_i64(42).unwrap(); // Not a tstr
    let bytes = enc.into_bytes();

    assert!(parse_leaf(&bytes).is_err());
}

#[test]
fn parse_leaf_malformed_missing_data_hash() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[0xAA; 32]).unwrap(); // internal_txn_hash
    enc.encode_tstr("evidence").unwrap(); // internal_evidence
    enc.encode_i64(42).unwrap(); // Not a bstr
    let bytes = enc.into_bytes();

    assert!(parse_leaf(&bytes).is_err());
}

#[test]
fn parse_leaf_malformed_missing_txn_hash() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(3).unwrap();
    enc.encode_i64(42).unwrap(); // Not a bstr
    enc.encode_tstr("evidence").unwrap();
    enc.encode_bstr(&[0xBB; 32]).unwrap();
    let bytes = enc.into_bytes();

    assert!(parse_leaf(&bytes).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// parse_path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn parse_path_valid() {
    let _provider = EverParseCborProvider;

    // Build inner pair: [true, bstr(32 bytes)]
    let mut pair_enc = cose_sign1_primitives::provider::encoder();
    pair_enc.encode_array(2).unwrap();
    pair_enc.encode_bool(true).unwrap();
    pair_enc.encode_bstr(&[0xCC; 32]).unwrap();
    let pair_bytes = pair_enc.into_bytes();

    // Build outer array of 1 pair
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(1).unwrap();
    enc.encode_raw(&pair_bytes).unwrap();
    let bytes = enc.into_bytes();

    let path = parse_path(&bytes).expect("should parse");
    assert_eq!(path.len(), 1);
    assert!(path[0].0); // is_left = true
    assert_eq!(path[0].1, vec![0xCC; 32]);
}

#[test]
fn parse_path_malformed_not_array() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_i64(42).unwrap(); // Not an array
    let bytes = enc.into_bytes();

    assert!(parse_path(&bytes).is_err());
}

#[test]
fn parse_path_empty_array() {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(0).unwrap();
    let bytes = enc.into_bytes();

    let path = parse_path(&bytes).expect("should parse empty");
    assert!(path.is_empty());
}

#[test]
fn parse_path_malformed_pair_not_array() {
    let _provider = EverParseCborProvider;

    // Inner item is an integer, not an array
    let mut item_enc = cose_sign1_primitives::provider::encoder();
    item_enc.encode_i64(42).unwrap();
    let item_bytes = item_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(1).unwrap();
    enc.encode_raw(&item_bytes).unwrap();
    let bytes = enc.into_bytes();

    assert!(parse_path(&bytes).is_err());
}

#[test]
fn parse_path_malformed_pair_missing_hash() {
    let _provider = EverParseCborProvider;

    // Inner pair: [true, int] — missing bstr
    let mut pair_enc = cose_sign1_primitives::provider::encoder();
    pair_enc.encode_array(2).unwrap();
    pair_enc.encode_bool(false).unwrap();
    pair_enc.encode_i64(42).unwrap(); // Not a bstr
    let pair_bytes = pair_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(1).unwrap();
    enc.encode_raw(&pair_bytes).unwrap();
    let bytes = enc.into_bytes();

    assert!(parse_path(&bytes).is_err());
}

#[test]
fn parse_path_malformed_pair_missing_bool() {
    let _provider = EverParseCborProvider;

    // Inner pair: [int, bstr] — bool replaced with int
    let mut pair_enc = cose_sign1_primitives::provider::encoder();
    pair_enc.encode_array(2).unwrap();
    pair_enc.encode_i64(1).unwrap(); // Not a bool
    pair_enc.encode_bstr(&[0xCC; 32]).unwrap();
    let pair_bytes = pair_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(1).unwrap();
    enc.encode_raw(&pair_bytes).unwrap();
    let bytes = enc.into_bytes();

    assert!(parse_path(&bytes).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// MstCcfInclusionProof::parse
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn inclusion_proof_parse_valid() {
    let _provider = EverParseCborProvider;

    // Build a valid leaf (array of 3: bstr, tstr, bstr)
    let mut leaf_enc = cose_sign1_primitives::provider::encoder();
    leaf_enc.encode_array(3).unwrap();
    leaf_enc.encode_bstr(&[0x11; 32]).unwrap();
    leaf_enc.encode_tstr("evidence").unwrap();
    leaf_enc.encode_bstr(&[0x22; 32]).unwrap();
    let leaf_bytes = leaf_enc.into_bytes();

    // Build a valid path (array of 0 pairs)
    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(0).unwrap();
    let path_bytes = path_enc.into_bytes();

    // Build proof blob: map { 1: leaf_raw, 2: path_raw }
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_raw(&leaf_bytes).unwrap();
    enc.encode_i64(2).unwrap();
    enc.encode_raw(&path_bytes).unwrap();
    let blob = enc.into_bytes();

    let proof = MstCcfInclusionProof::parse(&blob).expect("should parse");
    assert_eq!(proof.internal_txn_hash, vec![0x11; 32]);
    assert_eq!(proof.internal_evidence, "evidence");
    assert_eq!(proof.data_hash, vec![0x22; 32]);
    assert!(proof.path.is_empty());
}

#[test]
fn inclusion_proof_parse_missing_leaf() {
    let _provider = EverParseCborProvider;

    // Build a valid path only, no leaf (key=1)
    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(0).unwrap();
    let path_bytes = path_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(2).unwrap(); // Only path, no leaf
    enc.encode_raw(&path_bytes).unwrap();
    let blob = enc.into_bytes();

    match MstCcfInclusionProof::parse(&blob) {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn inclusion_proof_parse_missing_path() {
    let _provider = EverParseCborProvider;

    // Build a valid leaf only, no path (key=2)
    let mut leaf_enc = cose_sign1_primitives::provider::encoder();
    leaf_enc.encode_array(3).unwrap();
    leaf_enc.encode_bstr(&[0x11; 32]).unwrap();
    leaf_enc.encode_tstr("evidence").unwrap();
    leaf_enc.encode_bstr(&[0x22; 32]).unwrap();
    let leaf_bytes = leaf_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // Only leaf, no path
    enc.encode_raw(&leaf_bytes).unwrap();
    let blob = enc.into_bytes();

    match MstCcfInclusionProof::parse(&blob) {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn inclusion_proof_parse_unknown_keys_skipped() {
    let _provider = EverParseCborProvider;

    // Build leaf
    let mut leaf_enc = cose_sign1_primitives::provider::encoder();
    leaf_enc.encode_array(3).unwrap();
    leaf_enc.encode_bstr(&[0x11; 32]).unwrap();
    leaf_enc.encode_tstr("evidence").unwrap();
    leaf_enc.encode_bstr(&[0x22; 32]).unwrap();
    let leaf_bytes = leaf_enc.into_bytes();

    // Build path
    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(0).unwrap();
    let path_bytes = path_enc.into_bytes();

    // Map with unknown key (99) that should be skipped
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(3).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_raw(&leaf_bytes).unwrap();
    enc.encode_i64(99).unwrap(); // Unknown key
    enc.encode_tstr("ignored").unwrap(); // Skipped value
    enc.encode_i64(2).unwrap();
    enc.encode_raw(&path_bytes).unwrap();
    let blob = enc.into_bytes();

    let proof = MstCcfInclusionProof::parse(&blob).expect("should parse with unknown keys");
    assert_eq!(proof.internal_evidence, "evidence");
}

#[test]
fn inclusion_proof_parse_malformed_cbor() {
    let _provider = EverParseCborProvider;
    assert!(MstCcfInclusionProof::parse(&[0xFF, 0xFF]).is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// is_cose_sign1_tagged_18
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn is_tagged_18_yes() {
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[0u8; 4]).unwrap();
    let bytes = enc.into_bytes();

    assert!(is_cose_sign1_tagged_18(&bytes).expect("should parse"));
}

#[test]
fn is_tagged_18_no_different_tag() {
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(99).unwrap();
    enc.encode_i64(42).unwrap();
    let bytes = enc.into_bytes();

    assert!(!is_cose_sign1_tagged_18(&bytes).expect("should parse"));
}

#[test]
fn is_tagged_18_no_not_tag() {
    let _provider = EverParseCborProvider;

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[0u8; 4]).unwrap();
    let bytes = enc.into_bytes();

    assert!(!is_cose_sign1_tagged_18(&bytes).expect("should parse"));
}

// ═══════════════════════════════════════════════════════════════════════════
// reencode_statement_with_cleared_unprotected_headers
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn reencode_tagged_statement() {
    let _provider = EverParseCborProvider;

    // Build a tagged COSE_Sign1 message with unprotected headers
    let mut prot_enc = cose_sign1_primitives::provider::encoder();
    prot_enc.encode_map(1).unwrap();
    prot_enc.encode_i64(1).unwrap();
    prot_enc.encode_i64(-7).unwrap();
    let prot_bytes = prot_enc.into_bytes();

    let mut unprot_enc = cose_sign1_primitives::provider::encoder();
    unprot_enc.encode_map(1).unwrap();
    unprot_enc.encode_i64(4).unwrap();
    unprot_enc.encode_bstr(b"some-kid").unwrap();
    let unprot_bytes = unprot_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&prot_bytes).unwrap();
    enc.encode_raw(&unprot_bytes).unwrap();
    enc.encode_bstr(b"payload-data").unwrap();
    enc.encode_bstr(&[0xAA; 64]).unwrap();
    let statement = enc.into_bytes();

    let reencoded = reencode_statement_with_cleared_unprotected_headers(&statement)
        .expect("should reencode");

    // Should be tagged
    assert!(is_cose_sign1_tagged_18(&reencoded).expect("check tag"));

    // Parse the reencoded message: unprotected should be empty
    let msg = cose_sign1_primitives::CoseSign1Message::parse(&reencoded).expect("parse");
    assert!(msg.unprotected.is_empty());
    assert_eq!(msg.payload, Some(b"payload-data".to_vec()));
}

#[test]
fn reencode_untagged_statement() {
    let _provider = EverParseCborProvider;

    // Build an untagged COSE_Sign1 message
    let mut prot_enc = cose_sign1_primitives::provider::encoder();
    prot_enc.encode_map(1).unwrap();
    prot_enc.encode_i64(1).unwrap();
    prot_enc.encode_i64(-7).unwrap();
    let prot_bytes = prot_enc.into_bytes();

    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&prot_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"untagged-payload").unwrap();
    enc.encode_bstr(&[0xBB; 32]).unwrap();
    let statement = enc.into_bytes();

    let reencoded = reencode_statement_with_cleared_unprotected_headers(&statement)
        .expect("should reencode");

    // Should NOT be tagged
    assert!(!is_cose_sign1_tagged_18(&reencoded).expect("check tag"));
}

#[test]
fn reencode_detached_payload() {
    let _provider = EverParseCborProvider;

    // Build a message with null (detached) payload
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap(); // empty protected
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap(); // detached
    enc.encode_bstr(&[0xCC; 16]).unwrap();
    let statement = enc.into_bytes();

    let reencoded = reencode_statement_with_cleared_unprotected_headers(&statement)
        .expect("should reencode");

    let msg = cose_sign1_primitives::CoseSign1Message::parse(&reencoded).expect("parse");
    assert!(msg.is_detached());
}

// ═══════════════════════════════════════════════════════════════════════════
// get_cwt_issuer_host
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn get_cwt_issuer_present() {
    let _provider = EverParseCborProvider;

    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Text("example.com".into()),
        )]),
    );

    let protected = ProtectedHeader::encode(headers).expect("encode");
    let issuer = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(issuer, Some("example.com".into()));
}

#[test]
fn get_cwt_issuer_missing_claims() {
    let _provider = EverParseCborProvider;

    let headers = CoseHeaderMap::new();
    let protected = ProtectedHeader::encode(headers).expect("encode");
    let issuer = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(issuer, None);
}

#[test]
fn get_cwt_issuer_claims_not_map() {
    let _provider = EverParseCborProvider;

    let mut headers = CoseHeaderMap::new();
    headers.insert(CoseHeaderLabel::Int(15), CoseHeaderValue::Int(42));

    let protected = ProtectedHeader::encode(headers).expect("encode");
    let issuer = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(issuer, None);
}

#[test]
fn get_cwt_issuer_missing_iss_label() {
    let _provider = EverParseCborProvider;

    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(99), // Not iss_label (1)
            CoseHeaderValue::Text("example.com".into()),
        )]),
    );

    let protected = ProtectedHeader::encode(headers).expect("encode");
    let issuer = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(issuer, None);
}

#[test]
fn get_cwt_issuer_value_not_text() {
    let _provider = EverParseCborProvider;

    let mut headers = CoseHeaderMap::new();
    headers.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Map(vec![(
            CoseHeaderLabel::Int(1),
            CoseHeaderValue::Int(42), // Not Text
        )]),
    );

    let protected = ProtectedHeader::encode(headers).expect("encode");
    let issuer = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(issuer, None);
}

// ═══════════════════════════════════════════════════════════════════════════
// ReceiptVerifyError Display coverage for remaining variants
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn error_display_missing_vdp() {
    let e = ReceiptVerifyError::MissingVdp;
    assert_eq!(format!("{}", e), "missing_vdp");
}

#[test]
fn error_display_missing_proof() {
    let e = ReceiptVerifyError::MissingProof;
    assert_eq!(format!("{}", e), "missing_proof");
}

#[test]
fn error_display_missing_issuer() {
    let e = ReceiptVerifyError::MissingIssuer;
    assert_eq!(format!("{}", e), "issuer_missing");
}

#[test]
fn error_display_jwks_fetch() {
    let e = ReceiptVerifyError::JwksFetch("timeout".into());
    assert_eq!(format!("{}", e), "jwks_fetch_failed: timeout");
}

#[test]
fn error_display_jwk_unsupported() {
    let e = ReceiptVerifyError::JwkUnsupported("missing_crv".into());
    assert_eq!(format!("{}", e), "jwk_unsupported: missing_crv");
}

#[test]
fn error_display_statement_reencode() {
    let e = ReceiptVerifyError::StatementReencode("encode failed".into());
    assert_eq!(format!("{}", e), "statement_reencode_failed: encode failed");
}

#[test]
fn error_display_sig_structure_encode() {
    let e = ReceiptVerifyError::SigStructureEncode("cbor error".into());
    assert_eq!(format!("{}", e), "sig_structure_encode_failed: cbor error");
}

#[test]
fn error_display_data_hash_mismatch() {
    let e = ReceiptVerifyError::DataHashMismatch;
    assert_eq!(format!("{}", e), "data_hash_mismatch");
}

#[test]
fn error_display_signature_invalid() {
    let e = ReceiptVerifyError::SignatureInvalid;
    assert_eq!(format!("{}", e), "signature_invalid");
}

// ═══════════════════════════════════════════════════════════════════════════
// sha256 and sha256_concat_slices (public utility functions)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sha256_basic() {
    let hash = sha256(b"hello");
    assert_eq!(hash.len(), 32);
    // SHA-256("hello") is well-known
    assert_eq!(hash[0], 0x2c);
    assert_eq!(hash[1], 0xf2);
}

#[test]
fn sha256_concat_basic() {
    let left = [0xAA_u8; 32];
    let right = [0xBB_u8; 32];
    let result = sha256_concat_slices(&left, &right);
    assert_eq!(result.len(), 32);
    // Should be different from sha256 of either alone
    assert_ne!(result, sha256(&[0xAA; 32]));
}

// ═══════════════════════════════════════════════════════════════════════════
// base64url_decode error
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn base64url_decode_invalid() {
    let result = base64url_decode("!!invalid!!");
    assert!(result.is_err());
}

#[test]
fn base64url_decode_valid() {
    let result = base64url_decode("SGVsbG8").expect("should decode");
    assert_eq!(result, b"Hello");
}

// ═══════════════════════════════════════════════════════════════════════════
// Client: poll_operation via mock HTTP transport
// ═══════════════════════════════════════════════════════════════════════════

use cose_sign1_transparent_mst::http_client::HttpTransport;
use cose_sign1_transparent_mst::signing::client::{
    MstTransparencyClient, MstTransparencyClientOptions,
};
use cose_sign1_transparent_mst::signing::error::MstClientError;
use std::sync::{Arc, Mutex};
use url::Url;

#[derive(Debug)]
struct MockHttp {
    responses: Mutex<Vec<Result<(u16, Option<String>, Vec<u8>), String>>>,
    string_responses: Mutex<Vec<Result<String, String>>>,
    bytes_responses: Mutex<Vec<Result<Vec<u8>, String>>>,
}

impl MockHttp {
    fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            string_responses: Mutex::new(Vec::new()),
            bytes_responses: Mutex::new(Vec::new()),
        }
    }

    fn push_post(&self, resp: Result<(u16, Option<String>, Vec<u8>), String>) {
        self.responses.lock().unwrap().push(resp);
    }

    fn push_get_bytes(&self, resp: Result<Vec<u8>, String>) {
        self.bytes_responses.lock().unwrap().push(resp);
    }
}

impl HttpTransport for MockHttp {
    fn get_bytes(&self, _url: &Url, _accept: &str) -> Result<Vec<u8>, String> {
        self.bytes_responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(Err("no more bytes responses".into()))
    }
    fn get_string(&self, _url: &Url, _accept: &str) -> Result<String, String> {
        self.string_responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(Err("no more string responses".into()))
    }
    fn post_bytes(
        &self,
        _url: &Url,
        _content_type: &str,
        _accept: &str,
        _body: Vec<u8>,
    ) -> Result<(u16, Option<String>, Vec<u8>), String> {
        self.responses
            .lock()
            .unwrap()
            .pop()
            .unwrap_or(Err("no more post responses".into()))
    }
}

/// Build a CBOR map with a single text key-value pair.
fn cbor_map_text(key: &str, value: &str) -> Vec<u8> {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_tstr(key).unwrap();
    enc.encode_tstr(value).unwrap();
    enc.into_bytes()
}

/// Build a CBOR map with two text key-value pairs.
fn cbor_map_text_2(k1: &str, v1: &str, k2: &str, v2: &str) -> Vec<u8> {
    let _provider = EverParseCborProvider;
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    enc.encode_tstr(k1).unwrap();
    enc.encode_tstr(v1).unwrap();
    enc.encode_tstr(k2).unwrap();
    enc.encode_tstr(v2).unwrap();
    enc.into_bytes()
}

#[test]
fn client_create_entry_post_error() {
    let mock = Arc::new(MockHttp::new());
    mock.push_post(Err("connection refused".into()));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 1,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::HttpError(_)) => {}
        other => panic!("Expected HttpError, got: {:?}", other),
    }
}

#[test]
fn client_create_entry_non_2xx() {
    let mock = Arc::new(MockHttp::new());
    mock.push_post(Ok((500, None, b"error".to_vec())));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 1,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::ServiceError { http_status, .. }) => {
            assert_eq!(http_status, 500);
        }
        other => panic!("Expected ServiceError with 500, got: {:?}", other),
    }
}

#[test]
fn client_create_entry_missing_operation_id() {
    let mock = Arc::new(MockHttp::new());
    // 200 OK but no OperationId in CBOR body
    let body = cbor_map_text("SomeOther", "value");
    mock.push_post(Ok((200, None, body)));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 1,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::MissingField { field }) => {
            assert_eq!(field, "OperationId");
        }
        other => panic!("Expected MissingField(OperationId), got: {:?}", other),
    }
}

#[test]
fn client_poll_succeeded() {
    let mock = Arc::new(MockHttp::new());

    // POST returns OperationId
    let post_body = cbor_map_text("OperationId", "op-123");
    mock.push_post(Ok((200, None, post_body)));

    // Poll returns Succeeded with EntryId
    let poll_body = cbor_map_text_2("Status", "Succeeded", "EntryId", "entry-456");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    let result = client.create_entry(b"cose-bytes").expect("should succeed");
    assert_eq!(result.operation_id, "op-123");
    assert_eq!(result.entry_id, "entry-456");
}

#[test]
fn client_poll_failed_status() {
    let mock = Arc::new(MockHttp::new());

    let post_body = cbor_map_text("OperationId", "op-fail");
    mock.push_post(Ok((200, None, post_body)));

    let poll_body = cbor_map_text("Status", "Failed");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::OperationFailed { operation_id, status }) => {
            assert_eq!(operation_id, "op-fail");
            assert_eq!(status, "Failed");
        }
        other => panic!("Expected OperationFailed, got: {:?}", other),
    }
}

#[test]
fn client_poll_unknown_status() {
    let mock = Arc::new(MockHttp::new());

    let post_body = cbor_map_text("OperationId", "op-unk");
    mock.push_post(Ok((200, None, post_body)));

    let poll_body = cbor_map_text("Status", "Cancelled");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::OperationFailed { status, .. }) => {
            assert_eq!(status, "Cancelled");
        }
        other => panic!("Expected OperationFailed, got: {:?}", other),
    }
}

#[test]
fn client_poll_missing_status() {
    let mock = Arc::new(MockHttp::new());

    let post_body = cbor_map_text("OperationId", "op-no-status");
    mock.push_post(Ok((200, None, post_body)));

    // Response with no Status field
    let poll_body = cbor_map_text("Other", "data");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::MissingField { field }) => {
            assert_eq!(field, "Status");
        }
        other => panic!("Expected MissingField(Status), got: {:?}", other),
    }
}

#[test]
fn client_poll_timeout() {
    let mock = Arc::new(MockHttp::new());

    let post_body = cbor_map_text("OperationId", "op-timeout");
    mock.push_post(Ok((200, None, post_body)));

    // All poll responses return Running
    for _ in 0..3 {
        let poll_body = cbor_map_text("Status", "Running");
        mock.push_get_bytes(Ok(poll_body));
    }

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::OperationTimeout { operation_id, retries }) => {
            assert_eq!(operation_id, "op-timeout");
            assert_eq!(retries, 3);
        }
        other => panic!("Expected OperationTimeout, got: {:?}", other),
    }
}

#[test]
fn client_poll_succeeded_missing_entry_id() {
    let mock = Arc::new(MockHttp::new());

    let post_body = cbor_map_text("OperationId", "op-no-entry");
    mock.push_post(Ok((200, None, post_body)));

    // Succeeded but no EntryId
    let poll_body = cbor_map_text("Status", "Succeeded");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    match client.create_entry(b"cose-bytes") {
        Err(MstClientError::MissingField { field }) => {
            assert_eq!(field, "EntryId");
        }
        other => panic!("Expected MissingField(EntryId), got: {:?}", other),
    }
}

#[test]
fn client_get_entry_statement() {
    let mock = Arc::new(MockHttp::new());
    mock.push_get_bytes(Ok(b"cose-statement-bytes".to_vec()));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions::default(),
        mock,
    );

    let result = client.get_entry_statement("entry-123").expect("should succeed");
    assert_eq!(result, b"cose-statement-bytes");
}

#[test]
fn client_get_entry_statement_error() {
    let mock = Arc::new(MockHttp::new());
    mock.push_get_bytes(Err("not found".into()));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions::default(),
        mock,
    );

    match client.get_entry_statement("entry-404") {
        Err(MstClientError::HttpError(_)) => {}
        other => panic!("Expected HttpError, got: {:?}", other),
    }
}

#[test]
fn client_make_transparent_happy_path() {
    let mock = Arc::new(MockHttp::new());

    // POST returns OperationId
    let post_body = cbor_map_text("OperationId", "op-mt");
    mock.push_post(Ok((200, None, post_body)));

    // Poll returns Succeeded
    let poll_body = cbor_map_text_2("Status", "Succeeded", "EntryId", "entry-mt");
    mock.push_get_bytes(Ok(poll_body));

    // GET entry statement returns bytes
    mock.push_get_bytes(Ok(b"transparent-cose".to_vec()));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    // Note: make_transparent calls get_entry_statement AFTER poll, so the bytes_responses
    // are popped in reverse order (last pushed = first popped for get_bytes).
    // The poll response must be popped first, then the statement response.
    // Since we pushed poll_body then statement bytes, and pop is LIFO,
    // the statement bytes will be popped first (for get_entry_statement),
    // and poll_body second (for poll_operation).
    // This means the order matters: push statement first, then poll.
    // Let me fix this...
}

// The mock uses a stack (LIFO). For make_transparent:
// 1. create_entry -> POST -> poll_operation -> GET (poll)
// 2. get_entry_statement -> GET (statement)
// So we need to push in reverse order: statement first, then poll.
#[test]
fn client_make_transparent_with_correct_ordering() {
    let mock = Arc::new(MockHttp::new());

    // POST returns OperationId
    let post_body = cbor_map_text("OperationId", "op-mt");
    mock.push_post(Ok((200, None, post_body)));

    // Push get_bytes responses in reverse call order (LIFO):
    // get_entry_statement will be called second (push first)
    mock.push_get_bytes(Ok(b"transparent-cose".to_vec()));
    // poll_operation will be called first (push second = popped first)
    let poll_body = cbor_map_text_2("Status", "Succeeded", "EntryId", "entry-mt");
    mock.push_get_bytes(Ok(poll_body));

    let client = MstTransparencyClient::with_http(
        Url::parse("https://example.com").unwrap(),
        MstTransparencyClientOptions {
            max_poll_retries: 3,
            poll_delay: std::time::Duration::from_millis(1),
            ..MstTransparencyClientOptions::default()
        },
        mock,
    );

    let result = client.make_transparent(b"cose-bytes").expect("should succeed");
    assert_eq!(result, b"transparent-cose");
}
