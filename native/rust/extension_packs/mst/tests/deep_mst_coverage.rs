// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for MST receipt verification error paths.
//!
//! Targets uncovered lines in validation/receipt_verify.rs:
//! - base64url decode errors
//! - ReceiptVerifyError Display variants
//! - extract_proof_blobs error paths
//! - parse_leaf / parse_path error paths
//! - jwk_to_spki_der edge cases
//! - validate_receipt_alg_against_jwk mismatch
//! - ccf_accumulator_sha256 size checks
//! - find_jwk_for_kid not found
//! - resolve_receipt_signing_key offline fallback
//! - get_cwt_issuer_host non-map path
//! - is_cose_sign1_tagged_18 paths
//! - reencode_statement_with_cleared_unprotected_headers

extern crate cbor_primitives_everparse;

use cose_sign1_transparent_mst::validation::receipt_verify::*;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

// =========================================================================
// ReceiptVerifyError Display coverage
// =========================================================================

#[test]
fn error_display_receipt_decode() {
    let e = ReceiptVerifyError::ReceiptDecode("bad cbor".to_string());
    let s = format!("{}", e);
    assert!(s.contains("receipt_decode_failed"));
    assert!(s.contains("bad cbor"));
}

#[test]
fn error_display_missing_alg() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingAlg),
        "receipt_missing_alg"
    );
}

#[test]
fn error_display_missing_kid() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingKid),
        "receipt_missing_kid"
    );
}

#[test]
fn error_display_unsupported_alg() {
    let e = ReceiptVerifyError::UnsupportedAlg(-999);
    let s = format!("{}", e);
    assert!(s.contains("unsupported_alg"));
    assert!(s.contains("-999"));
}

#[test]
fn error_display_unsupported_vds() {
    let e = ReceiptVerifyError::UnsupportedVds(99);
    let s = format!("{}", e);
    assert!(s.contains("unsupported_vds"));
    assert!(s.contains("99"));
}

#[test]
fn error_display_missing_vdp() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingVdp),
        "missing_vdp"
    );
}

#[test]
fn error_display_missing_proof() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingProof),
        "missing_proof"
    );
}

#[test]
fn error_display_missing_issuer() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingIssuer),
        "issuer_missing"
    );
}

#[test]
fn error_display_jwks_parse() {
    let e = ReceiptVerifyError::JwksParse("bad json".to_string());
    assert!(format!("{}", e).contains("jwks_parse_failed"));
}

#[test]
fn error_display_jwks_fetch() {
    let e = ReceiptVerifyError::JwksFetch("network error".to_string());
    assert!(format!("{}", e).contains("jwks_fetch_failed"));
}

#[test]
fn error_display_jwk_not_found() {
    let e = ReceiptVerifyError::JwkNotFound("kid123".to_string());
    assert!(format!("{}", e).contains("jwk_not_found_for_kid"));
    assert!(format!("{}", e).contains("kid123"));
}

#[test]
fn error_display_jwk_unsupported() {
    let e = ReceiptVerifyError::JwkUnsupported("rsa".to_string());
    assert!(format!("{}", e).contains("jwk_unsupported"));
}

#[test]
fn error_display_statement_reencode() {
    let e = ReceiptVerifyError::StatementReencode("cbor fail".to_string());
    assert!(format!("{}", e).contains("statement_reencode_failed"));
}

#[test]
fn error_display_sig_structure_encode() {
    let e = ReceiptVerifyError::SigStructureEncode("sig fail".to_string());
    assert!(format!("{}", e).contains("sig_structure_encode_failed"));
}

#[test]
fn error_display_data_hash_mismatch() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::DataHashMismatch),
        "data_hash_mismatch"
    );
}

#[test]
fn error_display_signature_invalid() {
    assert_eq!(
        format!("{}", ReceiptVerifyError::SignatureInvalid),
        "signature_invalid"
    );
}

#[test]
fn error_is_std_error() {
    // Covers impl std::error::Error for ReceiptVerifyError
    let e: Box<dyn std::error::Error> =
        Box::new(ReceiptVerifyError::MissingAlg);
    assert!(e.to_string().contains("missing_alg"));
}

// =========================================================================
// base64url_decode
// =========================================================================

#[test]
fn base64url_decode_valid() {
    let decoded = base64url_decode("SGVsbG8").unwrap();
    assert_eq!(decoded, b"Hello");
}

#[test]
fn base64url_decode_invalid_byte() {
    let result = base64url_decode("invalid!@#$");
    assert!(result.is_err());
    let msg = result.unwrap_err();
    assert!(msg.contains("invalid base64 byte"));
}

#[test]
fn base64url_decode_empty() {
    let decoded = base64url_decode("").unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn base64url_decode_padded() {
    // Padding is stripped by the function
    let decoded = base64url_decode("SGVsbG8=").unwrap();
    assert_eq!(decoded, b"Hello");
}

// =========================================================================
// extract_proof_blobs
// =========================================================================

#[test]
fn extract_proof_blobs_vdp_not_a_map() {
    // Covers "vdp_not_a_map" error path
    let value = CoseHeaderValue::Int(42);
    let result = extract_proof_blobs(&value);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("vdp_not_a_map"));
}

#[test]
fn extract_proof_blobs_proof_not_array() {
    // Covers "proof_not_array" error path
    let pairs = vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Int(99),
    )];
    let value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&value);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("proof_not_array"));
}

#[test]
fn extract_proof_blobs_empty_proof_array() {
    // Covers MissingProof when array is empty
    let pairs = vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![]),
    )];
    let value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&value);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_proof"));
}

#[test]
fn extract_proof_blobs_item_not_bstr() {
    // Covers "proof_item_not_bstr" error path
    let pairs = vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(1)]),
    )];
    let value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&value);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("proof_item_not_bstr"));
}

#[test]
fn extract_proof_blobs_no_matching_label() {
    // Covers MissingProof when label -1 not present
    let pairs = vec![(
        CoseHeaderLabel::Int(42),
        CoseHeaderValue::Bytes(vec![1, 2, 3]),
    )];
    let value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&value);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_proof"));
}

#[test]
fn extract_proof_blobs_valid() {
    // Covers the success path
    let blob1 = vec![0xA1, 0x01, 0x02]; // some bytes
    let blob2 = vec![0xB1, 0x03, 0x04];
    let pairs = vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(blob1.clone()),
            CoseHeaderValue::Bytes(blob2.clone()),
        ]),
    )];
    let value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&value).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], blob1);
    assert_eq!(result[1], blob2);
}

// =========================================================================
// ring_verifier_for_cose_alg
// =========================================================================

#[test]
fn ring_verifier_es256() {
    let result = ring_verifier_for_cose_alg(-7);
    assert!(result.is_ok());
}

#[test]
fn ring_verifier_es384() {
    let result = ring_verifier_for_cose_alg(-35);
    assert!(result.is_ok());
}

#[test]
fn ring_verifier_unsupported() {
    let result = ring_verifier_for_cose_alg(-999);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unsupported_alg"));
}

// =========================================================================
// validate_receipt_alg_against_jwk
// =========================================================================

#[test]
fn validate_alg_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = validate_receipt_alg_against_jwk(&jwk, -7);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_crv"));
}

#[test]
fn validate_alg_p256_es256_ok() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -7).is_ok());
}

#[test]
fn validate_alg_p384_es384_ok() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -35).is_ok());
}

#[test]
fn validate_alg_curve_mismatch() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: None,
    };
    let result = validate_receipt_alg_against_jwk(&jwk, -35); // P-256 + ES384 = mismatch
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("alg_curve_mismatch"));
}

// =========================================================================
// jwk_to_spki_der
// =========================================================================

#[test]
fn jwk_to_spki_non_ec_kty() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("kty=RSA"));
}

#[test]
fn jwk_to_spki_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_crv"));
}

#[test]
fn jwk_to_spki_unsupported_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-521".to_string()),
        kid: None,
        x: Some("AAAA".to_string()),
        y: Some("BBBB".to_string()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unsupported_crv=P-521"));
}

#[test]
fn jwk_to_spki_missing_x() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: Some("AAAA".to_string()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_x"));
}

#[test]
fn jwk_to_spki_missing_y() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("AAAA".to_string()),
        y: None,
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("missing_y"));
}

#[test]
fn jwk_to_spki_wrong_coord_length() {
    // P-256 expects 32-byte x/y, provide short ones
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("AQID".to_string()), // 3 bytes
        y: Some("BAUF".to_string()), // 3 bytes
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unexpected_xy_len"));
}

#[test]
fn jwk_to_spki_p256_valid() {
    // Valid P-256 coordinates (32 bytes each in base64url)
    let x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 bytes of zeros
    let y = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 32 bytes of 0x04...
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some(x.to_string()),
        y: Some(y.to_string()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes[0], 0x04); // uncompressed point marker
    assert_eq!(bytes.len(), 1 + 32 + 32);
}

#[test]
fn jwk_to_spki_p384_valid() {
    // Valid P-384 coordinates (48 bytes each in base64url)
    let x = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 48 bytes
    let y = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 48 bytes
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: None,
        x: Some(x.to_string()),
        y: Some(y.to_string()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert_eq!(bytes[0], 0x04);
    assert_eq!(bytes.len(), 1 + 48 + 48);
}

// =========================================================================
// find_jwk_for_kid
// =========================================================================

#[test]
fn find_jwk_kid_found() {
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"abc","x":"AA","y":"BB"}]}"#;
    let result = find_jwk_for_kid(jwks, "abc");
    assert!(result.is_ok());
    let jwk = result.unwrap();
    assert_eq!(jwk.kid.as_deref(), Some("abc"));
}

#[test]
fn find_jwk_kid_not_found() {
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"xyz","x":"AA","y":"BB"}]}"#;
    let result = find_jwk_for_kid(jwks, "no-such-kid");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("jwk_not_found"));
}

#[test]
fn find_jwk_invalid_json() {
    let result = find_jwk_for_kid("not json", "kid");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("jwks_parse_failed"));
}

// =========================================================================
// ccf_accumulator_sha256
// =========================================================================

#[test]
fn ccf_accumulator_bad_txn_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 16], // wrong length (not 32)
        internal_evidence: "evidence".to_string(),
        data_hash: vec![0u8; 32],
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unexpected_internal_txn_hash_len"));
}

#[test]
fn ccf_accumulator_bad_data_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".to_string(),
        data_hash: vec![0u8; 16], // wrong length (not 32)
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("unexpected_data_hash_len"));
}

#[test]
fn ccf_accumulator_data_hash_mismatch() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".to_string(),
        data_hash: vec![1u8; 32], // different from expected
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(msg.contains("data_hash_mismatch"));
}

#[test]
fn ccf_accumulator_valid() {
    let data_hash = [0xABu8; 32];
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "some evidence".to_string(),
        data_hash: data_hash.to_vec(),
        path: vec![],
    };
    let result = ccf_accumulator_sha256(&proof, data_hash);
    assert!(result.is_ok());
    let acc = result.unwrap();
    assert_eq!(acc.len(), 32);
}

// =========================================================================
// sha256 / sha256_concat_slices
// =========================================================================

#[test]
fn sha256_basic() {
    let hash = sha256(b"hello");
    assert_eq!(hash.len(), 32);
    // SHA-256("hello") is a known value; check first few bytes
    assert_eq!(hash[0], 0x2c);
    assert_eq!(hash[1], 0xf2);
    assert_eq!(hash[2], 0x4d);
}

#[test]
fn sha256_concat_basic() {
    let left = [0u8; 32];
    let right = [1u8; 32];
    let result = sha256_concat_slices(&left, &right);
    assert_eq!(result.len(), 32);
    // Verify it's not just one of the inputs
    assert_ne!(result, left);
    assert_ne!(result, right);
}

// =========================================================================
// is_cose_sign1_tagged_18
// =========================================================================

#[test]
fn is_tagged_with_tag_18() {
    // CBOR tag 18 = 0xD2, then a minimal COSE_Sign1 array
    let tagged: Vec<u8> = vec![0xD2, 0x84, 0x40, 0xA0, 0xF6, 0x40];
    let result = is_cose_sign1_tagged_18(&tagged);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn is_tagged_without_tag() {
    // Just a CBOR array (no tag)
    let untagged: Vec<u8> = vec![0x84, 0x40, 0xA0, 0xF6, 0x40];
    let result = is_cose_sign1_tagged_18(&untagged);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn is_tagged_empty_input() {
    let result = is_cose_sign1_tagged_18(&[]);
    // Empty input should error (can't peek type)
    assert!(result.is_err());
}

// =========================================================================
// get_cwt_issuer_host
// =========================================================================

#[test]
fn get_cwt_issuer_host_non_map_value() {
    // When the CWT claims value is not a map, should return None
    let mut hdr = cose_sign1_primitives::CoseHeaderMap::new();
    hdr.insert(
        CoseHeaderLabel::Int(15),
        CoseHeaderValue::Bytes(vec![1, 2, 3]),
    );
    let protected = cose_sign1_primitives::ProtectedHeader::encode(hdr).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert!(result.is_none());
}

#[test]
fn get_cwt_issuer_host_map_without_iss() {
    // Map present but without iss label
    let inner_pairs = vec![(
        CoseHeaderLabel::Int(2), // subject, not issuer
        CoseHeaderValue::Text("test-subject".to_string()),
    )];
    let mut hdr = cose_sign1_primitives::CoseHeaderMap::new();
    hdr.insert(CoseHeaderLabel::Int(15), CoseHeaderValue::Map(inner_pairs));
    let protected = cose_sign1_primitives::ProtectedHeader::encode(hdr).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert!(result.is_none());
}

#[test]
fn get_cwt_issuer_host_found() {
    let inner_pairs = vec![(
        CoseHeaderLabel::Int(1),
        CoseHeaderValue::Text("example.ledger.azure.net".to_string()),
    )];
    let mut hdr = cose_sign1_primitives::CoseHeaderMap::new();
    hdr.insert(CoseHeaderLabel::Int(15), CoseHeaderValue::Map(inner_pairs));
    let protected = cose_sign1_primitives::ProtectedHeader::encode(hdr).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, Some("example.ledger.azure.net".to_string()));
}

#[test]
fn get_cwt_issuer_host_label_not_present() {
    let hdr = cose_sign1_primitives::CoseHeaderMap::new();
    let protected = cose_sign1_primitives::ProtectedHeader::encode(hdr).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert!(result.is_none());
}
