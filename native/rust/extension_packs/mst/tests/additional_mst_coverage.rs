// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional MST coverage tests.
//!
//! Targets: receipt_verify error paths, base64 utilities, JWK handling,
//! proof parsing, MST client options, error Display, fact construction,
//! and trust pack construction variants.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cose_sign1_transparent_mst::http_client::MockHttpTransport;
use cose_sign1_transparent_mst::signing::client::{MstTransparencyClient, MstTransparencyClientOptions};
use cose_sign1_transparent_mst::signing::error::MstClientError;
use cose_sign1_transparent_mst::validation::facts::{
    MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
    MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_transparent_mst::validation::pack::MstTrustPack;
use cose_sign1_transparent_mst::validation::receipt_verify::{
    base64url_decode, ccf_accumulator_sha256, extract_proof_blobs,
    find_jwk_for_kid, is_cose_sign1_tagged_18, jwk_to_spki_der, ring_verifier_for_cose_alg,
    sha256, sha256_concat_slices, validate_receipt_alg_against_jwk, Jwk,
    MstCcfInclusionProof, ReceiptVerifyError,
};
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};

// ============================================================================
// ReceiptVerifyError Display and Debug for all variants
// ============================================================================

#[test]
fn receipt_error_display_all_variants() {
    let cases: Vec<(ReceiptVerifyError, &str)> = vec![
        (ReceiptVerifyError::ReceiptDecode("bad cbor".into()), "receipt_decode_failed: bad cbor"),
        (ReceiptVerifyError::MissingAlg, "receipt_missing_alg"),
        (ReceiptVerifyError::MissingKid, "receipt_missing_kid"),
        (ReceiptVerifyError::UnsupportedAlg(-99), "unsupported_alg: -99"),
        (ReceiptVerifyError::UnsupportedVds(42), "unsupported_vds: 42"),
        (ReceiptVerifyError::MissingVdp, "missing_vdp"),
        (ReceiptVerifyError::MissingProof, "missing_proof"),
        (ReceiptVerifyError::MissingIssuer, "issuer_missing"),
        (ReceiptVerifyError::JwksParse("json err".into()), "jwks_parse_failed: json err"),
        (ReceiptVerifyError::JwksFetch("timeout".into()), "jwks_fetch_failed: timeout"),
        (ReceiptVerifyError::JwkNotFound("kid123".into()), "jwk_not_found_for_kid: kid123"),
        (ReceiptVerifyError::JwkUnsupported("RSA".into()), "jwk_unsupported: RSA"),
        (ReceiptVerifyError::StatementReencode("enc err".into()), "statement_reencode_failed: enc err"),
        (ReceiptVerifyError::SigStructureEncode("sig err".into()), "sig_structure_encode_failed: sig err"),
        (ReceiptVerifyError::DataHashMismatch, "data_hash_mismatch"),
        (ReceiptVerifyError::SignatureInvalid, "signature_invalid"),
    ];
    for (err, expected) in cases {
        let msg = format!("{}", err);
        assert_eq!(msg, expected, "Display mismatch for {:?}", err);
    }
}

#[test]
fn receipt_error_debug_all_variants() {
    let variants: Vec<ReceiptVerifyError> = vec![
        ReceiptVerifyError::ReceiptDecode("x".into()),
        ReceiptVerifyError::MissingAlg,
        ReceiptVerifyError::MissingKid,
        ReceiptVerifyError::UnsupportedAlg(-7),
        ReceiptVerifyError::UnsupportedVds(0),
        ReceiptVerifyError::MissingVdp,
        ReceiptVerifyError::MissingProof,
        ReceiptVerifyError::MissingIssuer,
        ReceiptVerifyError::JwksParse("y".into()),
        ReceiptVerifyError::JwksFetch("z".into()),
        ReceiptVerifyError::JwkNotFound("k".into()),
        ReceiptVerifyError::JwkUnsupported("u".into()),
        ReceiptVerifyError::StatementReencode("r".into()),
        ReceiptVerifyError::SigStructureEncode("s".into()),
        ReceiptVerifyError::DataHashMismatch,
        ReceiptVerifyError::SignatureInvalid,
    ];
    for e in &variants {
        let debug = format!("{:?}", e);
        assert!(!debug.is_empty());
    }
}

#[test]
fn receipt_error_implements_std_error() {
    let e = ReceiptVerifyError::MissingAlg;
    let std_err: &dyn std::error::Error = &e;
    assert!(!std_err.to_string().is_empty());
}

// ============================================================================
// MstClientError Display and Debug
// ============================================================================

#[test]
fn mst_client_error_display_all_variants() {
    let cases: Vec<(MstClientError, &str)> = vec![
        (MstClientError::HttpError("conn refused".into()), "HTTP error: conn refused"),
        (MstClientError::CborParseError("bad map".into()), "CBOR parse error: bad map"),
        (
            MstClientError::OperationTimeout { operation_id: "op1".into(), retries: 5 },
            "Operation op1 timed out after 5 retries",
        ),
        (
            MstClientError::OperationFailed { operation_id: "op2".into(), status: "Failed".into() },
            "Operation op2 failed with status: Failed",
        ),
        (
            MstClientError::MissingField { field: "EntryId".into() },
            "Missing required field: EntryId",
        ),
    ];
    for (err, expected) in cases {
        assert_eq!(format!("{}", err), expected);
    }
}

#[test]
fn mst_client_error_debug_all() {
    let variants: Vec<MstClientError> = vec![
        MstClientError::HttpError("x".into()),
        MstClientError::CborParseError("y".into()),
        MstClientError::OperationTimeout { operation_id: "z".into(), retries: 10 },
        MstClientError::OperationFailed { operation_id: "w".into(), status: "s".into() },
        MstClientError::MissingField { field: "f".into() },
    ];
    for e in &variants {
        assert!(!format!("{:?}", e).is_empty());
    }
}

#[test]
fn mst_client_error_implements_std_error() {
    let e = MstClientError::HttpError("test".into());
    let std_err: &dyn std::error::Error = &e;
    assert!(!std_err.to_string().is_empty());
}

// ============================================================================
// Base64 and base64url decoding
// ============================================================================

#[test]
fn base64url_decode_valid() {
    let decoded = base64url_decode("AQID").unwrap();
    assert_eq!(decoded, vec![1, 2, 3]);
}

#[test]
fn base64url_decode_empty() {
    let decoded = base64url_decode("").unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn base64url_decode_with_padding() {
    let decoded = base64url_decode("AQID==").unwrap();
    assert_eq!(decoded, vec![1, 2, 3]);
}

#[test]
fn base64url_decode_invalid_char() {
    let result = base64url_decode("invalid!char");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("invalid base64 byte"));
}

// ============================================================================
// SHA-256 utilities
// ============================================================================

#[test]
fn sha256_empty() {
    let hash = sha256(b"");
    // SHA-256 of empty string is a well-known value
    assert_eq!(
        hex::encode(&hash),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn sha256_hello() {
    let hash = sha256(b"hello");
    assert_eq!(hash.len(), 32);
}

#[test]
fn sha256_concat_slices_deterministic() {
    let left = sha256(b"left");
    let right = sha256(b"right");
    let combined = sha256_concat_slices(&left, &right);
    let combined2 = sha256_concat_slices(&left, &right);
    assert_eq!(combined, combined2);

    // Order matters
    let reversed = sha256_concat_slices(&right, &left);
    assert_ne!(combined, reversed);
}

// ============================================================================
// ring verifier selection
// ============================================================================

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
fn ring_verifier_unsupported_alg() {
    let result = ring_verifier_for_cose_alg(-99);
    assert!(matches!(result, Err(ReceiptVerifyError::UnsupportedAlg(-99))));
}

#[test]
fn ring_verifier_zero_alg() {
    let result = ring_verifier_for_cose_alg(0);
    assert!(matches!(result, Err(ReceiptVerifyError::UnsupportedAlg(0))));
}

// ============================================================================
// JWK handling
// ============================================================================

#[test]
fn find_jwk_for_kid_found() {
    let jwks_json = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"kid1","x":"AQID","y":"BAUG"}]}"#;
    let result = find_jwk_for_kid(jwks_json, "kid1");
    assert!(result.is_ok());
    let jwk = result.unwrap();
    assert_eq!(jwk.kid.as_deref(), Some("kid1"));
}

#[test]
fn find_jwk_for_kid_not_found() {
    let jwks_json = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"kid1","x":"AQID","y":"BAUG"}]}"#;
    let result = find_jwk_for_kid(jwks_json, "missing_kid");
    assert!(matches!(result, Err(ReceiptVerifyError::JwkNotFound(_))));
}

#[test]
fn find_jwk_for_kid_invalid_json() {
    let result = find_jwk_for_kid("not json", "kid1");
    assert!(matches!(result, Err(ReceiptVerifyError::JwksParse(_))));
}

#[test]
fn find_jwk_for_kid_empty_keys() {
    let result = find_jwk_for_kid(r#"{"keys":[]}"#, "kid1");
    assert!(matches!(result, Err(ReceiptVerifyError::JwkNotFound(_))));
}

#[test]
fn jwk_to_spki_der_not_ec() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
    assert!(result.unwrap_err().to_string().contains("kty=RSA"));
}

#[test]
fn jwk_to_spki_der_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: Some("AQID".into()),
        y: Some("BAUG".into()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
}

#[test]
fn jwk_to_spki_der_unsupported_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-521".into()),
        kid: None,
        x: Some("AQID".into()),
        y: Some("BAUG".into()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
    assert!(result.unwrap_err().to_string().contains("P-521"));
}

#[test]
fn jwk_to_spki_der_missing_x() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".into()),
        kid: None,
        x: None,
        y: Some("BAUG".into()),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
}

#[test]
fn jwk_to_spki_der_missing_y() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".into()),
        kid: None,
        x: Some("AQID".into()),
        y: None,
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
}

#[test]
fn jwk_to_spki_der_wrong_xy_length_p256() {
    // P-256 expects 32 bytes each
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".into()),
        kid: None,
        x: Some("AQID".into()),   // only 3 bytes decoded
        y: Some("BAUG".into()),   // only 3 bytes decoded
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
    assert!(result.unwrap_err().to_string().contains("unexpected_xy_len"));
}

#[test]
fn jwk_to_spki_der_valid_p256() {
    // 32 bytes each = 43 base64url chars (approximately)
    let x_bytes = vec![0u8; 32];
    let y_bytes = vec![0u8; 32];
    let x_b64 = base64url_encode(&x_bytes);
    let y_b64 = base64url_encode(&y_bytes);

    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".into()),
        kid: Some("test".into()),
        x: Some(x_b64),
        y: Some(y_b64),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_ok());
    let spki = result.unwrap();
    // Should be 0x04 + 32 + 32 = 65 bytes
    assert_eq!(spki.len(), 65);
    assert_eq!(spki[0], 0x04);
}

#[test]
fn jwk_to_spki_der_valid_p384() {
    let x_bytes = vec![0u8; 48];
    let y_bytes = vec![0u8; 48];
    let x_b64 = base64url_encode(&x_bytes);
    let y_b64 = base64url_encode(&y_bytes);

    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".into()),
        kid: Some("test384".into()),
        x: Some(x_b64),
        y: Some(y_b64),
    };
    let result = jwk_to_spki_der(&jwk);
    assert!(result.is_ok());
    let spki = result.unwrap();
    // Should be 0x04 + 48 + 48 = 97 bytes
    assert_eq!(spki.len(), 97);
    assert_eq!(spki[0], 0x04);
}

// Helper for encoding base64url (no padding)
fn base64url_encode(data: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(alphabet[((triple >> 18) & 0x3F) as usize] as char);
        result.push(alphabet[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(alphabet[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(alphabet[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }
    result
}

// ============================================================================
// validate_receipt_alg_against_jwk
// ============================================================================

#[test]
fn validate_alg_es256_with_p256() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".into()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -7).is_ok());
}

#[test]
fn validate_alg_es384_with_p384() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".into()),
        kid: None,
        x: None,
        y: None,
    };
    assert!(validate_receipt_alg_against_jwk(&jwk, -35).is_ok());
}

#[test]
fn validate_alg_mismatch_es256_with_p384() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".into()),
        kid: None,
        x: None,
        y: None,
    };
    let result = validate_receipt_alg_against_jwk(&jwk, -7);
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
    assert!(result.unwrap_err().to_string().contains("alg_curve_mismatch"));
}

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
    assert!(matches!(result, Err(ReceiptVerifyError::JwkUnsupported(_))));
    assert!(result.unwrap_err().to_string().contains("missing_crv"));
}

// ============================================================================
// ccf_accumulator_sha256
// ============================================================================

#[test]
fn ccf_accumulator_wrong_internal_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 16], // wrong: should be 32
        internal_evidence: "evidence".into(),
        data_hash: vec![0u8; 32],
        path: Vec::new(),
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(matches!(result, Err(ReceiptVerifyError::ReceiptDecode(_))));
    assert!(result.unwrap_err().to_string().contains("internal_txn_hash_len"));
}

#[test]
fn ccf_accumulator_wrong_data_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".into(),
        data_hash: vec![0u8; 16], // wrong: should be 32
        path: Vec::new(),
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(matches!(result, Err(ReceiptVerifyError::ReceiptDecode(_))));
    assert!(result.unwrap_err().to_string().contains("data_hash_len"));
}

#[test]
fn ccf_accumulator_data_hash_mismatch() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "evidence".into(),
        data_hash: vec![1u8; 32], // different from expected
        path: Vec::new(),
    };
    let result = ccf_accumulator_sha256(&proof, [0u8; 32]);
    assert!(matches!(result, Err(ReceiptVerifyError::DataHashMismatch)));
}

#[test]
fn ccf_accumulator_success() {
    let data_hash = sha256(b"test payload");
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0xAA; 32],
        internal_evidence: "some_evidence".into(),
        data_hash: data_hash.to_vec(),
        path: Vec::new(),
    };
    let result = ccf_accumulator_sha256(&proof, data_hash);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

// ============================================================================
// is_cose_sign1_tagged_18
// ============================================================================

#[test]
fn is_tagged_18_with_tag() {
    // CBOR tag(18) followed by an array: 0xD2 0x84
    let bytes = [0xD2, 0x84, 0x40, 0xA0, 0xF6, 0x40];
    let result = is_cose_sign1_tagged_18(&bytes);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[test]
fn is_tagged_18_without_tag() {
    // Just an array: 0x84
    let bytes = [0x84, 0x40, 0xA0, 0xF6, 0x40];
    let result = is_cose_sign1_tagged_18(&bytes);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn is_tagged_18_empty_input() {
    let result = is_cose_sign1_tagged_18(&[]);
    assert!(result.is_err());
}

// ============================================================================
// extract_proof_blobs
// ============================================================================

#[test]
fn extract_proof_blobs_not_a_map() {
    use cose_sign1_primitives::CoseHeaderValue;
    let val = CoseHeaderValue::Int(42);
    let result = extract_proof_blobs(&val);
    assert!(matches!(result, Err(ReceiptVerifyError::ReceiptDecode(_))));
}

#[test]
fn extract_proof_blobs_missing_proof_label() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(999), // not -1
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(vec![1, 2, 3])]),
    )]);
    let result = extract_proof_blobs(&val);
    assert!(matches!(result, Err(ReceiptVerifyError::MissingProof)));
}

#[test]
fn extract_proof_blobs_proof_not_array() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Int(42),
    )]);
    let result = extract_proof_blobs(&val);
    assert!(matches!(result, Err(ReceiptVerifyError::ReceiptDecode(_))));
}

#[test]
fn extract_proof_blobs_empty_array() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![]),
    )]);
    let result = extract_proof_blobs(&val);
    assert!(matches!(result, Err(ReceiptVerifyError::MissingProof)));
}

#[test]
fn extract_proof_blobs_item_not_bstr() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(42)]),
    )]);
    let result = extract_proof_blobs(&val);
    assert!(matches!(result, Err(ReceiptVerifyError::ReceiptDecode(_))));
}

#[test]
fn extract_proof_blobs_success() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
    let val = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![0xAA, 0xBB]),
            CoseHeaderValue::Bytes(vec![0xCC, 0xDD]),
        ]),
    )]);
    let result = extract_proof_blobs(&val);
    assert!(result.is_ok());
    let blobs = result.unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(blobs[0], vec![0xAA, 0xBB]);
}

// ============================================================================
// MstTransparencyClientOptions defaults and construction
// ============================================================================

#[test]
fn client_options_default() {
    let opts = MstTransparencyClientOptions::default();
    assert_eq!(opts.api_version, "2024-01-01");
    assert!(opts.api_key.is_none());
    assert_eq!(opts.max_poll_retries, 30);
    assert_eq!(opts.poll_delay, Duration::from_secs(2));
}

#[test]
fn client_options_custom() {
    let opts = MstTransparencyClientOptions {
        api_version: "2025-06-01".to_string(),
        api_key: Some("my-api-key".to_string()),
        max_poll_retries: 5,
        poll_delay: Duration::from_millis(100),
    };
    assert_eq!(opts.api_version, "2025-06-01");
    assert_eq!(opts.api_key.as_deref(), Some("my-api-key"));
    assert_eq!(opts.max_poll_retries, 5);
}

#[test]
fn client_options_debug() {
    let opts = MstTransparencyClientOptions::default();
    let debug = format!("{:?}", opts);
    assert!(debug.contains("MstTransparencyClientOptions"));
}

// ============================================================================
// MstTrustPack construction variants
// ============================================================================

#[test]
fn mst_trust_pack_new() {
    let pack = MstTrustPack::new(true, Some("{}".into()), Some("2024-01-01".into()));
    assert!(pack.allow_network);
    assert!(pack.offline_jwks_json.is_some());
    assert!(pack.jwks_api_version.is_some());
}

#[test]
fn mst_trust_pack_offline_with_jwks() {
    let pack = MstTrustPack::offline_with_jwks(r#"{"keys":[]}"#);
    assert!(!pack.allow_network);
    assert_eq!(pack.offline_jwks_json.as_deref(), Some(r#"{"keys":[]}"#));
    assert!(pack.jwks_api_version.is_none());
}

#[test]
fn mst_trust_pack_online() {
    let pack = MstTrustPack::online();
    assert!(pack.allow_network);
    assert!(pack.offline_jwks_json.is_none());
    assert!(pack.jwks_api_version.is_none());
}

#[test]
fn mst_trust_pack_default() {
    let pack = MstTrustPack::default();
    assert!(!pack.allow_network);
    assert!(pack.offline_jwks_json.is_none());
    assert!(pack.jwks_api_version.is_none());
}

#[test]
fn mst_trust_pack_clone() {
    let pack = MstTrustPack::new(true, Some("jwks".into()), Some("v1".into()));
    let cloned = pack.clone();
    assert_eq!(cloned.allow_network, pack.allow_network);
    assert_eq!(cloned.offline_jwks_json, pack.offline_jwks_json);
    assert_eq!(cloned.jwks_api_version, pack.jwks_api_version);
}

#[test]
fn mst_trust_pack_debug() {
    let pack = MstTrustPack::online();
    let debug = format!("{:?}", pack);
    assert!(debug.contains("MstTrustPack"));
}

#[test]
fn mst_trust_pack_trait_producer_name() {
    use cose_sign1_validation_primitives::facts::TrustFactProducer;
    let pack = MstTrustPack::online();
    assert_eq!(pack.name(), "cose_sign1_transparent_mst::MstTrustPack");
}

#[test]
fn mst_trust_pack_trait_provides_non_empty() {
    use cose_sign1_validation_primitives::facts::TrustFactProducer;
    let pack = MstTrustPack::online();
    assert!(!pack.provides().is_empty());
    assert_eq!(pack.provides().len(), 11);
}

#[test]
fn mst_trust_pack_cose_sign1_trait_name() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = MstTrustPack::online();
    assert_eq!(CoseSign1TrustPack::name(&pack), "MstTrustPack");
}

#[test]
fn mst_trust_pack_default_plan_exists() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = MstTrustPack::online();
    let plan = pack.default_trust_plan();
    assert!(plan.is_some());
}

#[test]
fn mst_trust_pack_fact_producer_arc() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;
    let pack = MstTrustPack::online();
    let producer = pack.fact_producer();
    assert_eq!(producer.name(), "cose_sign1_transparent_mst::MstTrustPack");
}

// ============================================================================
// MstReceiptPresentFact
// ============================================================================

#[test]
fn receipt_present_fact_true() {
    let fact = MstReceiptPresentFact { present: true };
    match fact.get_property("present") {
        Some(FactValue::Bool(v)) => assert!(v),
        _ => panic!("expected Bool(true)"),
    }
}

#[test]
fn receipt_present_fact_false() {
    let fact = MstReceiptPresentFact { present: false };
    match fact.get_property("present") {
        Some(FactValue::Bool(v)) => assert!(!v),
        _ => panic!("expected Bool(false)"),
    }
}

#[test]
fn receipt_present_fact_unknown_property() {
    let fact = MstReceiptPresentFact { present: true };
    assert!(fact.get_property("unknown").is_none());
    assert!(fact.get_property("").is_none());
}

#[test]
fn receipt_present_fact_clone_eq() {
    let fact = MstReceiptPresentFact { present: true };
    let cloned = fact.clone();
    assert_eq!(fact, cloned);
}

// ============================================================================
// MstReceiptTrustedFact
// ============================================================================

#[test]
fn receipt_trusted_fact_true() {
    let fact = MstReceiptTrustedFact { trusted: true, details: None };
    match fact.get_property("trusted") {
        Some(FactValue::Bool(v)) => assert!(v),
        _ => panic!("expected Bool(true)"),
    }
}

#[test]
fn receipt_trusted_fact_false_with_details() {
    let fact = MstReceiptTrustedFact {
        trusted: false,
        details: Some("signature mismatch".into()),
    };
    match fact.get_property("trusted") {
        Some(FactValue::Bool(v)) => assert!(!v),
        _ => panic!("expected Bool(false)"),
    }
    assert_eq!(fact.details.as_deref(), Some("signature mismatch"));
}

#[test]
fn receipt_trusted_fact_unknown_property() {
    let fact = MstReceiptTrustedFact { trusted: true, details: None };
    assert!(fact.get_property("details").is_none());
    assert!(fact.get_property("").is_none());
}

// ============================================================================
// MstReceiptIssuerFact
// ============================================================================

#[test]
fn receipt_issuer_fact_value() {
    let fact = MstReceiptIssuerFact { issuer: "mst.example.com".into() };
    match fact.get_property("issuer") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, "mst.example.com"),
        _ => panic!("expected Str"),
    }
}

#[test]
fn receipt_issuer_fact_unknown() {
    let fact = MstReceiptIssuerFact { issuer: "x".into() };
    assert!(fact.get_property("host").is_none());
}

// ============================================================================
// MstReceiptKidFact
// ============================================================================

#[test]
fn receipt_kid_fact_value() {
    let fact = MstReceiptKidFact { kid: "my-key-id".into() };
    match fact.get_property("kid") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, "my-key-id"),
        _ => panic!("expected Str"),
    }
}

#[test]
fn receipt_kid_fact_unknown() {
    let fact = MstReceiptKidFact { kid: "x".into() };
    assert!(fact.get_property("key_id").is_none());
}

// ============================================================================
// MstReceiptStatementSha256Fact
// ============================================================================

#[test]
fn receipt_sha256_fact_value() {
    let fact = MstReceiptStatementSha256Fact {
        sha256_hex: "abcdef1234567890".into(),
    };
    match fact.get_property("sha256_hex") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert_eq!(s, "abcdef1234567890"),
        _ => panic!("expected Str"),
    }
}

#[test]
fn receipt_sha256_fact_unknown() {
    let fact = MstReceiptStatementSha256Fact { sha256_hex: "x".into() };
    assert!(fact.get_property("hash").is_none());
}

// ============================================================================
// MstReceiptStatementCoverageFact
// ============================================================================

#[test]
fn receipt_coverage_fact_value() {
    let fact = MstReceiptStatementCoverageFact {
        coverage: "sha256(COSE_Sign1 bytes with unprotected headers cleared)".into(),
    };
    match fact.get_property("coverage") {
        Some(FactValue::Str(Cow::Borrowed(s))) => assert!(s.contains("sha256")),
        _ => panic!("expected Str"),
    }
}

#[test]
fn receipt_coverage_fact_unknown() {
    let fact = MstReceiptStatementCoverageFact { coverage: "x".into() };
    assert!(fact.get_property("scope").is_none());
}

// ============================================================================
// MstReceiptSignatureVerifiedFact
// ============================================================================

#[test]
fn receipt_verified_fact_true() {
    let fact = MstReceiptSignatureVerifiedFact { verified: true };
    match fact.get_property("verified") {
        Some(FactValue::Bool(v)) => assert!(v),
        _ => panic!("expected Bool(true)"),
    }
}

#[test]
fn receipt_verified_fact_false() {
    let fact = MstReceiptSignatureVerifiedFact { verified: false };
    match fact.get_property("verified") {
        Some(FactValue::Bool(v)) => assert!(!v),
        _ => panic!("expected Bool(false)"),
    }
}

#[test]
fn receipt_verified_fact_unknown() {
    let fact = MstReceiptSignatureVerifiedFact { verified: true };
    assert!(fact.get_property("sig_ok").is_none());
}

// ============================================================================
// MockHttpTransport
// ============================================================================

#[test]
fn mock_http_transport_debug() {
    let mock = MockHttpTransport::new();
    let debug = format!("{:?}", mock);
    assert!(debug.contains("MockHttpTransport"));
}

#[test]
fn mock_http_transport_get_not_found() {
    use cose_sign1_transparent_mst::http_client::HttpTransport;
    let mock = MockHttpTransport::new();
    let url = url::Url::parse("https://example.com/test").unwrap();
    let result = mock.get_bytes(&url, "application/json");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("No mock response"));
}

#[test]
fn mock_http_transport_post_not_found() {
    use cose_sign1_transparent_mst::http_client::HttpTransport;
    let mock = MockHttpTransport::new();
    let url = url::Url::parse("https://example.com/entries").unwrap();
    let result = mock.post_bytes(&url, "application/cose", "application/cbor", vec![]);
    assert!(result.is_err());
}

#[test]
fn mock_http_transport_get_string_success() {
    use cose_sign1_transparent_mst::http_client::HttpTransport;
    let mut mock = MockHttpTransport::new();
    let url_str = "https://example.com/data";
    mock.get_responses.insert(url_str.into(), Ok(b"hello world".to_vec()));
    let url = url::Url::parse(url_str).unwrap();
    let result = mock.get_string(&url, "text/plain");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "hello world");
}

#[test]
fn mock_http_transport_get_string_invalid_utf8() {
    use cose_sign1_transparent_mst::http_client::HttpTransport;
    let mut mock = MockHttpTransport::new();
    let url_str = "https://example.com/binary";
    mock.get_responses.insert(url_str.into(), Ok(vec![0xFF, 0xFE]));
    let url = url::Url::parse(url_str).unwrap();
    let result = mock.get_string(&url, "text/plain");
    assert!(result.is_err());
}

// Helper for hex encoding (used in sha256 test)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
            s
        })
    }
}
