// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in receipt_verify.rs.
//!
//! Covers: sha256/sha256_concat_slices, parse_leaf, parse_path, MstCcfInclusionProof::parse,
//! ccf_accumulator_sha256, extract_proof_blobs, validate_cose_alg_supported,
//! validate_receipt_alg_against_jwk, local_jwk_to_ec_jwk, find_jwk_for_kid,
//! is_cose_sign1_tagged_18, reencode_statement_with_cleared_unprotected_headers,
//! and base64url_decode.

extern crate cbor_primitives_everparse;

use cbor_primitives::CborEncoder;
use cose_sign1_transparent_mst::validation::receipt_verify::*;
use crypto_primitives::EcJwk;
use std::borrow::Cow;

// ============================================================================
// Target: lines 273-278 — sha256 and sha256_concat_slices
// ============================================================================
#[test]
fn test_sha256_known_value() {
    let hash = sha256(b"hello");
    // SHA-256 of "hello" is well-known
    assert_eq!(hash.len(), 32);
    let hex_str = hash
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert_eq!(
        hex_str,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn test_sha256_concat_slices_commutative_check() {
    let a = sha256(b"left");
    let b = sha256(b"right");

    let ab = sha256_concat_slices(&a, &b);
    let ba = sha256_concat_slices(&b, &a);

    // Concatenation order matters for Merkle trees
    assert_ne!(ab, ba);
    assert_eq!(ab.len(), 32);
    assert_eq!(ba.len(), 32);
}

// ============================================================================
// Target: lines 297-334 — reencode_statement_with_cleared_unprotected_headers
// Build a minimal COSE_Sign1 message and reencode it.
// ============================================================================
#[test]
fn test_reencode_statement_clears_unprotected() {
    // Build a minimal COSE_Sign1 as CBOR bytes:
    // Tag(18) [ protected_bstr, {}, payload_bstr, signature_bstr ]
    let mut enc = cose_sign1_primitives::provider::encoder();

    // Encode with tag 18
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[0xA0]).unwrap(); // protected: empty map encoded as bstr
    enc.encode_map(0).unwrap(); // unprotected: empty map
    enc.encode_bstr(b"test payload").unwrap(); // payload
    enc.encode_bstr(b"fake signature").unwrap(); // signature

    let statement_bytes = enc.into_bytes();

    let result = reencode_statement_with_cleared_unprotected_headers(&statement_bytes);
    assert!(result.is_ok());
    let reencoded = result.unwrap();
    assert!(!reencoded.is_empty());
}

#[test]
fn test_reencode_untagged_statement() {
    // Build untagged COSE_Sign1
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[0xA0]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(b"sig").unwrap();

    let statement_bytes = enc.into_bytes();
    let result = reencode_statement_with_cleared_unprotected_headers(&statement_bytes);
    assert!(result.is_ok());
}

// ============================================================================
// Target: lines 310, 314, 318, 322, 329, 333 — individual encode errors in reencode
// (These are error maps for individual encode operations. We test them by passing
// completely invalid CBOR that still partially parses.)
// ============================================================================
#[test]
fn test_reencode_invalid_cbor_statement() {
    let result = reencode_statement_with_cleared_unprotected_headers(&[0xFF, 0xFF]);
    assert!(result.is_err());
}

// ============================================================================
// Target: lines 339-347 — is_cose_sign1_tagged_18
// ============================================================================
#[test]
fn test_is_cose_sign1_tagged_18_true() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(18).unwrap();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    let bytes = enc.into_bytes();

    assert!(is_cose_sign1_tagged_18(&bytes).unwrap());
}

#[test]
fn test_is_cose_sign1_tagged_18_false_no_tag() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(&[]).unwrap();
    let bytes = enc.into_bytes();

    assert!(!is_cose_sign1_tagged_18(&bytes).unwrap());
}

#[test]
fn test_is_cose_sign1_tagged_18_different_tag() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(99).unwrap();
    enc.encode_array(0).unwrap();
    let bytes = enc.into_bytes();

    let result = is_cose_sign1_tagged_18(&bytes).unwrap();
    assert!(!result);
}

// ============================================================================
// Target: lines 362, 393 — resolve/fetch are pub(crate), so we exercise them
// indirectly via verify_mst_receipt with crafted receipts.
// ============================================================================

// ============================================================================
// Target: lines 436, 440, 446, 452, 457 — MstCcfInclusionProof::parse
// ============================================================================
#[test]
fn test_inclusion_proof_parse_valid() {
    // Build a valid inclusion proof as CBOR:
    // Map { 1: leaf_array, 2: path_array }
    let mut enc = cose_sign1_primitives::provider::encoder();

    // Build leaf: array of [bstr(internal_txn_hash), tstr(evidence), bstr(data_hash)]
    let mut leaf_enc = cose_sign1_primitives::provider::encoder();
    leaf_enc.encode_array(3).unwrap();
    leaf_enc.encode_bstr(&[0xAA; 32]).unwrap(); // internal_txn_hash
    leaf_enc.encode_tstr("evidence_string").unwrap(); // internal_evidence
    leaf_enc.encode_bstr(&[0xBB; 32]).unwrap(); // data_hash
    let leaf_bytes = leaf_enc.into_bytes();

    // Build path: array of [array([bool, bstr])]
    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(1).unwrap(); // 1 element in path
                                       // Each path element is an array [bool, bstr]
    let mut pair_enc = cose_sign1_primitives::provider::encoder();
    pair_enc.encode_array(2).unwrap();
    pair_enc.encode_bool(true).unwrap();
    pair_enc.encode_bstr(&[0xCC; 32]).unwrap();
    let pair_bytes = pair_enc.into_bytes();
    path_enc.encode_raw(&pair_bytes).unwrap();
    let path_bytes = path_enc.into_bytes();

    // Proof map
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap(); // key=1 (leaf)
    enc.encode_raw(&leaf_bytes).unwrap();
    enc.encode_i64(2).unwrap(); // key=2 (path)
    enc.encode_raw(&path_bytes).unwrap();
    let proof_blob = enc.into_bytes();

    let proof = MstCcfInclusionProof::parse(&proof_blob);
    assert!(proof.is_ok(), "parse failed: {:?}", proof.err());
    let proof = proof.unwrap();
    assert_eq!(proof.internal_txn_hash.len(), 32);
    assert_eq!(proof.data_hash.len(), 32);
    assert_eq!(proof.internal_evidence, "evidence_string");
    assert_eq!(proof.path.len(), 1);
    assert!(proof.path[0].0); // is_left = true
}

#[test]
fn test_inclusion_proof_parse_missing_leaf() {
    // Map with only path (key=2), missing leaf (key=1)
    let mut enc = cose_sign1_primitives::provider::encoder();
    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(0).unwrap();
    let path_bytes = path_enc.into_bytes();

    enc.encode_map(1).unwrap();
    enc.encode_i64(2).unwrap();
    enc.encode_raw(&path_bytes).unwrap();
    let blob = enc.into_bytes();

    let result = MstCcfInclusionProof::parse(&blob);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn test_inclusion_proof_parse_with_unknown_key() {
    // Map with keys 1, 2, and an unknown key 99 (exercises the skip branch)
    let mut enc = cose_sign1_primitives::provider::encoder();

    let mut leaf_enc = cose_sign1_primitives::provider::encoder();
    leaf_enc.encode_array(3).unwrap();
    leaf_enc.encode_bstr(&[0xAA; 32]).unwrap();
    leaf_enc.encode_tstr("ev").unwrap();
    leaf_enc.encode_bstr(&[0xBB; 32]).unwrap();
    let leaf_bytes = leaf_enc.into_bytes();

    let mut path_enc = cose_sign1_primitives::provider::encoder();
    path_enc.encode_array(0).unwrap();
    let path_bytes = path_enc.into_bytes();

    enc.encode_map(3).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_raw(&leaf_bytes).unwrap();
    enc.encode_i64(2).unwrap();
    enc.encode_raw(&path_bytes).unwrap();
    enc.encode_i64(99).unwrap(); // unknown key
    enc.encode_tstr("ignored").unwrap(); // value to skip
    let blob = enc.into_bytes();

    let result = MstCcfInclusionProof::parse(&blob);
    assert!(result.is_ok());
}

// ============================================================================
// Target: lines 508 — parse_path
// ============================================================================
#[test]
fn test_parse_path_empty_array() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(0).unwrap();
    let bytes = enc.into_bytes();

    let result = parse_path(&bytes);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

#[test]
fn test_parse_path_multiple_elements() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(2).unwrap();

    // Element 1: [true, hash]
    let mut pair1 = cose_sign1_primitives::provider::encoder();
    pair1.encode_array(2).unwrap();
    pair1.encode_bool(true).unwrap();
    pair1.encode_bstr(&[0x11; 32]).unwrap();
    let p1 = pair1.into_bytes();
    enc.encode_raw(&p1).unwrap();

    // Element 2: [false, hash]
    let mut pair2 = cose_sign1_primitives::provider::encoder();
    pair2.encode_array(2).unwrap();
    pair2.encode_bool(false).unwrap();
    pair2.encode_bstr(&[0x22; 32]).unwrap();
    let p2 = pair2.into_bytes();
    enc.encode_raw(&p2).unwrap();

    let bytes = enc.into_bytes();
    let result = parse_path(&bytes);
    assert!(result.is_ok());
    let path = result.unwrap();
    assert_eq!(path.len(), 2);
    assert!(path[0].0); // first is left
    assert!(!path[1].0); // second is right
}

// ============================================================================
// Target: line 171 — base64url_decode
// ============================================================================
#[test]
fn test_base64url_decode_valid() {
    let result = base64url_decode("SGVsbG8");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"Hello");
}

#[test]
fn test_base64url_decode_with_padding() {
    let result = base64url_decode("SGVsbG8=");
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), b"Hello");
}

#[test]
fn test_base64url_decode_invalid_char() {
    let result = base64url_decode("SGVsbG8!");
    assert!(result.is_err());
}

// ============================================================================
// Target: lines 577-586 — validate_cose_alg_supported
// ============================================================================
#[test]
fn test_ring_verifier_es256() {
    let result = validate_cose_alg_supported(-7);
    assert!(result.is_ok());
}

#[test]
fn test_ring_verifier_es384() {
    let result = validate_cose_alg_supported(-35);
    assert!(result.is_ok());
}

#[test]
fn test_ring_verifier_unsupported_alg() {
    let result = validate_cose_alg_supported(-999);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::UnsupportedAlg(-999)) => {}
        other => panic!("Expected UnsupportedAlg, got: {:?}", other),
    }
}

// ============================================================================
// Target: lines 588-607 — validate_receipt_alg_against_jwk
// ============================================================================
#[test]
fn test_validate_alg_against_jwk_p256_es256() {
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
fn test_validate_alg_against_jwk_p384_es384() {
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
fn test_validate_alg_against_jwk_mismatch() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: None,
    };
    let result = validate_receipt_alg_against_jwk(&jwk, -35); // P-256 vs ES384
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("alg_curve_mismatch"));
        }
        other => panic!("Expected JwkUnsupported, got: {:?}", other),
    }
}

#[test]
fn test_validate_alg_against_jwk_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = validate_receipt_alg_against_jwk(&jwk, -7);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("missing_crv"));
        }
        other => panic!("Expected JwkUnsupported, got: {:?}", other),
    }
}

// ============================================================================
// Target: lines 203-204 — local_jwk_to_ec_jwk
// ============================================================================
#[test]
fn test_local_jwk_to_ec_jwk_p256_valid() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".to_string()),
        y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".to_string()),
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_ok());
    let ec_jwk = result.unwrap();
    assert_eq!(ec_jwk.kty, "EC");
    assert_eq!(ec_jwk.crv, "P-256");
    assert_eq!(ec_jwk.x, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
    assert_eq!(ec_jwk.y, "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
    assert_eq!(ec_jwk.kid, None);
}

#[test]
fn test_local_jwk_to_ec_jwk_p384_valid() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: Some("my-p384-key".to_string()),
        x: Some("iA7lWQLzVrKGEFjfGMfMHfTEZ2KnLiKU7JuNT3E7ygsfE7ygsfE7ygsfE7ygsfE".to_string()),
        y: Some("mLgl1xH0TKP0VFl_0umg0Q6HBEUL0umg0Q6HBEUL0umg0Q6HBEUL0umg0Q6HBEUL".to_string()),
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_ok());
    let ec_jwk = result.unwrap();
    assert_eq!(ec_jwk.kty, "EC");
    assert_eq!(ec_jwk.crv, "P-384");
    assert_eq!(
        ec_jwk.x,
        "iA7lWQLzVrKGEFjfGMfMHfTEZ2KnLiKU7JuNT3E7ygsfE7ygsfE7ygsfE7ygsfE"
    );
    assert_eq!(
        ec_jwk.y,
        "mLgl1xH0TKP0VFl_0umg0Q6HBEUL0umg0Q6HBEUL0umg0Q6HBEUL0umg0Q6HBEUL"
    );
    assert_eq!(ec_jwk.kid, Some(Cow::Borrowed("my-p384-key")));
}

#[test]
fn test_local_jwk_to_ec_jwk_wrong_kty() {
    let jwk = Jwk {
        kty: "RSA".to_string(),
        crv: None,
        kid: None,
        x: None,
        y: None,
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwkUnsupported(msg)) => {
            assert!(msg.contains("kty=RSA"));
        }
        other => panic!("Expected JwkUnsupported, got: {:?}", other),
    }
}

#[test]
fn test_local_jwk_to_ec_jwk_unsupported_curve_accepted() {
    // local_jwk_to_ec_jwk does NOT validate curves — it just copies strings
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-521".to_string()),
        kid: None,
        x: Some("abc".to_string()),
        y: Some("def".to_string()),
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_ok());
    let ec_jwk = result.unwrap();
    assert_eq!(ec_jwk.crv, "P-521");
    assert_eq!(ec_jwk.x, "abc");
    assert_eq!(ec_jwk.y, "def");
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_x() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: None,
        y: Some("abc".to_string()),
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_err());
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_y() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: None,
        x: Some("abc".to_string()),
        y: None,
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_err());
}

#[test]
fn test_local_jwk_to_ec_jwk_missing_crv() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: None,
        kid: None,
        x: Some("abc".to_string()),
        y: Some("def".to_string()),
    };
    let result = local_jwk_to_ec_jwk(&jwk);
    assert!(result.is_err());
}

// ============================================================================
// Target: lines 657-668 — find_jwk_for_kid
// ============================================================================
#[test]
fn test_find_jwk_for_kid_found() {
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"my-kid","x":"abc","y":"def"}]}"#;
    let result = find_jwk_for_kid(jwks, "my-kid");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().kid.as_deref(), Some("my-kid"));
}

#[test]
fn test_find_jwk_for_kid_not_found() {
    let jwks = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"other","x":"abc","y":"def"}]}"#;
    let result = find_jwk_for_kid(jwks, "missing-kid");
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwkNotFound(kid)) => {
            assert_eq!(kid, "missing-kid");
        }
        other => panic!("Expected JwkNotFound, got: {:?}", other),
    }
}

#[test]
fn test_find_jwk_for_kid_invalid_json() {
    let result = find_jwk_for_kid("not json", "kid");
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::JwksParse(_)) => {}
        other => panic!("Expected JwksParse, got: {:?}", other),
    }
}

// ============================================================================
// Target: lines 613-641 — ccf_accumulator_sha256
// ============================================================================
#[test]
fn test_ccf_accumulator_matching_hash() {
    let data_hash = sha256(b"statement bytes");

    let proof = MstCcfInclusionProof {
        internal_txn_hash: [0xAA; 32],
        internal_evidence: "evidence".to_string(),
        data_hash,
        path: vec![],
    };

    let result = ccf_accumulator_sha256(&proof, data_hash);
    assert!(result.is_ok());
    let acc = result.unwrap();
    assert_eq!(acc.len(), 32);
}

#[test]
fn test_ccf_accumulator_mismatched_hash() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: [0xAA; 32],
        internal_evidence: "evidence".to_string(),
        data_hash: [0xBB; 32],
        path: vec![],
    };

    let result = ccf_accumulator_sha256(&proof, [0xCC; 32]);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::DataHashMismatch) => {}
        other => panic!("Expected DataHashMismatch, got: {:?}", other),
    }
}

// Wrong-length hash tests have been removed because MstCcfInclusionProof now
// uses [u8; 32] fixed arrays — invalid lengths are caught at parse time.

// ============================================================================
// Target: lines 533-574 — extract_proof_blobs
// ============================================================================
#[test]
fn test_extract_proof_blobs_valid() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

    let blob1 = vec![0x01, 0x02, 0x03];
    let blob2 = vec![0x04, 0x05, 0x06];

    let vdp = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(blob1.clone().into()),
            CoseHeaderValue::Bytes(blob2.clone().into()),
        ]),
    )]);

    let result = extract_proof_blobs(&vdp);
    assert!(result.is_ok());
    let blobs = result.unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(&*blobs[0], &blob1[..]);
    assert_eq!(&*blobs[1], &blob2[..]);
}

#[test]
fn test_extract_proof_blobs_not_a_map() {
    use cose_sign1_primitives::CoseHeaderValue;

    let vdp = CoseHeaderValue::Int(42);
    let result = extract_proof_blobs(&vdp);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("vdp_not_a_map"));
        }
        other => panic!("Expected ReceiptDecode, got: {:?}", other),
    }
}

#[test]
fn test_extract_proof_blobs_missing_proof_label() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

    let vdp = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(999), // not -1
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()),
    )]);

    let result = extract_proof_blobs(&vdp);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn test_extract_proof_blobs_proof_not_array() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

    let vdp = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()), // not an array
    )]);

    let result = extract_proof_blobs(&vdp);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("proof_not_array"));
        }
        other => panic!("Expected ReceiptDecode, got: {:?}", other),
    }
}

#[test]
fn test_extract_proof_blobs_empty_array() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

    let vdp = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![]), // empty
    )]);

    let result = extract_proof_blobs(&vdp);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::MissingProof) => {}
        other => panic!("Expected MissingProof, got: {:?}", other),
    }
}

#[test]
fn test_extract_proof_blobs_item_not_bstr() {
    use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};

    let vdp = CoseHeaderValue::Map(vec![(
        CoseHeaderLabel::Int(-1),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Int(42)]),
    )]);

    let result = extract_proof_blobs(&vdp);
    assert!(result.is_err());
    match result {
        Err(ReceiptVerifyError::ReceiptDecode(msg)) => {
            assert!(msg.contains("proof_item_not_bstr"));
        }
        other => panic!("Expected ReceiptDecode, got: {:?}", other),
    }
}

// ============================================================================
// Target: line 225 — parse_leaf
// ============================================================================
#[test]
fn test_parse_leaf_valid() {
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[0x11; 32]).unwrap();
    enc.encode_tstr("internal evidence text").unwrap();
    enc.encode_bstr(&[0x22; 32]).unwrap();
    let leaf_bytes = enc.into_bytes();

    let result = parse_leaf(&leaf_bytes);
    assert!(result.is_ok());
    let (txn_hash, evidence, data_hash) = result.unwrap();
    assert_eq!(txn_hash.len(), 32);
    assert_eq!(evidence, "internal evidence text");
    assert_eq!(data_hash.len(), 32);
}

#[test]
fn test_parse_leaf_invalid_cbor() {
    let result = parse_leaf(&[0xFF, 0xFF]);
    assert!(result.is_err());
}

// ============================================================================
// Additional error Display coverage
// ============================================================================
#[test]
fn test_receipt_verify_error_display_all_variants() {
    assert_eq!(format!("{}", ReceiptVerifyError::MissingVdp), "missing_vdp");
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingProof),
        "missing_proof"
    );
    assert_eq!(
        format!("{}", ReceiptVerifyError::MissingIssuer),
        "issuer_missing"
    );
    assert_eq!(
        format!("{}", ReceiptVerifyError::DataHashMismatch),
        "data_hash_mismatch"
    );
    assert_eq!(
        format!("{}", ReceiptVerifyError::SignatureInvalid),
        "signature_invalid"
    );
    assert_eq!(
        format!("{}", ReceiptVerifyError::UnsupportedVds(99)),
        "unsupported_vds: 99"
    );
    assert_eq!(
        format!(
            "{}",
            ReceiptVerifyError::SigStructureEncode(Cow::Borrowed("err"))
        ),
        "sig_structure_encode_failed: err"
    );
    assert_eq!(
        format!(
            "{}",
            ReceiptVerifyError::StatementReencode(Cow::Borrowed("re"))
        ),
        "statement_reencode_failed: re"
    );
    assert_eq!(
        format!(
            "{}",
            ReceiptVerifyError::JwkUnsupported(Cow::Borrowed("un"))
        ),
        "jwk_unsupported: un"
    );
    assert_eq!(
        format!("{}", ReceiptVerifyError::JwksFetch(Cow::Borrowed("fetch"))),
        "jwks_fetch_failed: fetch"
    );
}
