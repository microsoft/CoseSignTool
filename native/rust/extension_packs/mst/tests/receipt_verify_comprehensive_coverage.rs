// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for MST receipt_verify private helper functions.
//! Targets specific functions mentioned in the coverage gap task:
//! - validate_cose_alg_supported
//! - ccf_accumulator_sha256  
//! - extract_proof_blobs
//! - MstCcfInclusionProof parsing

use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue};
use cose_sign1_transparent_mst::validation::*;
use sha2::{Digest, Sha256};

// Test validate_cose_alg_supported function
#[test]
fn test_validate_cose_alg_supported_es256() {
    let result = validate_cose_alg_supported(-7); // ES256
    assert!(result.is_ok());
    let _verifier = result.unwrap();
    // Just verify we got a verifier - don't test the pointer value
}

#[test]
fn test_validate_cose_alg_supported_es384() {
    let result = validate_cose_alg_supported(-35); // ES384
    assert!(result.is_ok());
    let _verifier = result.unwrap();
    // Just verify we got a verifier - don't test the pointer value
}

#[test]
fn test_validate_cose_alg_supported_unsupported() {
    // Test unsupported algorithm
    let result = validate_cose_alg_supported(-999);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::UnsupportedAlg(alg) => assert_eq!(alg, -999),
        _ => panic!("Expected UnsupportedAlg error"),
    }
}

#[test]
fn test_validate_cose_alg_supported_common_unsupported() {
    // Test other common but unsupported algs
    let unsupported_algs = [
        -37,  // PS256
        -36,  // ES512
        -8,   // EdDSA
        1,    // A128GCM
        -257, // RS256
    ];

    for alg in unsupported_algs {
        let result = validate_cose_alg_supported(alg);
        assert!(result.is_err(), "Algorithm {} should be unsupported", alg);
        match result.unwrap_err() {
            ReceiptVerifyError::UnsupportedAlg(returned_alg) => assert_eq!(returned_alg, alg),
            _ => panic!("Expected UnsupportedAlg error for alg {}", alg),
        }
    }
}

// Test ccf_accumulator_sha256 function
#[test]
fn test_ccf_accumulator_sha256_valid() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![1u8; 32], // 32 bytes
        internal_evidence: "test_evidence".to_string(),
        data_hash: vec![2u8; 32], // 32 bytes
        path: vec![],             // Not used in accumulator calculation
    };

    let expected_data_hash = [2u8; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);

    assert!(result.is_ok());
    let accumulator = result.unwrap();
    assert_eq!(accumulator.len(), 32);

    // Verify the accumulator calculation manually
    let internal_evidence_hash = {
        let mut h = Sha256::new();
        h.update("test_evidence".as_bytes());
        h.finalize()
    };

    let expected_accumulator = {
        let mut h = Sha256::new();
        h.update(&proof.internal_txn_hash);
        h.update(internal_evidence_hash);
        h.update(expected_data_hash);
        h.finalize()
    };

    assert_eq!(&accumulator[..], &expected_accumulator[..]);
}

#[test]
fn test_ccf_accumulator_sha256_wrong_internal_txn_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![1u8; 31], // Wrong length (should be 32)
        internal_evidence: "test_evidence".to_string(),
        data_hash: vec![2u8; 32],
        path: vec![],
    };

    let expected_data_hash = [2u8; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_internal_txn_hash_len"));
            assert!(msg.contains("31"));
        }
        _ => panic!("Expected ReceiptDecode error"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_wrong_data_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![1u8; 32],
        internal_evidence: "test_evidence".to_string(),
        data_hash: vec![2u8; 31], // Wrong length (should be 32)
        path: vec![],
    };

    let expected_data_hash = [2u8; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_data_hash_len"));
            assert!(msg.contains("31"));
        }
        _ => panic!("Expected ReceiptDecode error"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_data_hash_mismatch() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![1u8; 32],
        internal_evidence: "test_evidence".to_string(),
        data_hash: vec![2u8; 32], // Different from expected
        path: vec![],
    };

    let expected_data_hash = [3u8; 32]; // Different from proof.data_hash
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::DataHashMismatch => {} // Expected
        _ => panic!("Expected DataHashMismatch error"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_edge_cases() {
    // Test with empty internal evidence
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "".to_string(), // Empty
        data_hash: vec![0u8; 32],
        path: vec![],
    };

    let expected_data_hash = [0u8; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert!(result.is_ok());

    // Test with very long internal evidence
    let proof2 = MstCcfInclusionProof {
        internal_txn_hash: vec![0u8; 32],
        internal_evidence: "x".repeat(10000), // Very long
        data_hash: vec![0u8; 32],
        path: vec![],
    };

    let result2 = ccf_accumulator_sha256(&proof2, expected_data_hash);
    assert!(result2.is_ok());
}

// Test extract_proof_blobs function
#[test]
fn test_extract_proof_blobs_valid() {
    // Create a valid VDP map with proof blobs
    let proof_blob1 = vec![1, 2, 3, 4];
    let proof_blob2 = vec![5, 6, 7, 8];

    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-1), // PROOF_LABEL
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(proof_blob1.clone().into()),
            CoseHeaderValue::Bytes(proof_blob2.clone().into()),
        ]),
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_ok());
    let blobs = result.unwrap();
    assert_eq!(blobs.len(), 2);
    assert_eq!(blobs[0], proof_blob1);
    assert_eq!(blobs[1], proof_blob2);
}

#[test]
fn test_extract_proof_blobs_not_a_map() {
    // Test with non-map VDP value
    let vdp_value = CoseHeaderValue::Bytes(vec![1, 2, 3].into());
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "vdp_not_a_map");
        }
        _ => panic!("Expected ReceiptDecode error"),
    }
}

#[test]
fn test_extract_proof_blobs_missing_proof_label() {
    // Create a map without the PROOF_LABEL (-1)
    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-2), // Wrong label
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(vec![1, 2, 3].into())]),
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof => {} // Expected
        _ => panic!("Expected MissingProof error"),
    }
}

#[test]
fn test_extract_proof_blobs_proof_not_array() {
    // Create a map with PROOF_LABEL but value is not an array
    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-1),                     // PROOF_LABEL
        CoseHeaderValue::Bytes(vec![1, 2, 3].into()), // Should be array, not bytes
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "proof_not_array");
        }
        _ => panic!("Expected ReceiptDecode error"),
    }
}

#[test]
fn test_extract_proof_blobs_array_item_not_bytes() {
    // Create an array with non-bytes items
    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-1), // PROOF_LABEL
        CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![1, 2, 3].into()), // Valid
            CoseHeaderValue::Int(42),                     // Invalid - should be bytes
        ]),
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "proof_item_not_bstr");
        }
        _ => panic!("Expected ReceiptDecode error"),
    }
}

#[test]
fn test_extract_proof_blobs_empty_array() {
    // Create an empty proof array
    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-1),       // PROOF_LABEL
        CoseHeaderValue::Array(vec![]), // Empty array
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof => {} // Expected
        _ => panic!("Expected MissingProof error"),
    }
}

#[test]
fn test_extract_proof_blobs_multiple_labels() {
    // Test map with multiple labels, including the correct one
    let proof_blob = vec![1, 2, 3, 4];

    let mut pairs = Vec::new();
    pairs.push((
        CoseHeaderLabel::Int(-2), // Wrong label
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(vec![9, 9, 9].into())]),
    ));
    pairs.push((
        CoseHeaderLabel::Int(-1), // Correct PROOF_LABEL
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(proof_blob.clone().into())]),
    ));
    pairs.push((
        CoseHeaderLabel::Int(-3), // Another wrong label
        CoseHeaderValue::Bytes(vec![8, 8, 8].into()),
    ));

    let vdp_value = CoseHeaderValue::Map(pairs);
    let result = extract_proof_blobs(&vdp_value);

    assert!(result.is_ok());
    let blobs = result.unwrap();
    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0], proof_blob);
}

// Test error types for comprehensive coverage
#[test]
fn test_receipt_verify_error_display() {
    let errors = vec![
        ReceiptVerifyError::ReceiptDecode("test decode".to_string()),
        ReceiptVerifyError::MissingAlg,
        ReceiptVerifyError::MissingKid,
        ReceiptVerifyError::UnsupportedAlg(-999),
        ReceiptVerifyError::UnsupportedVds(99),
        ReceiptVerifyError::MissingVdp,
        ReceiptVerifyError::MissingProof,
        ReceiptVerifyError::MissingIssuer,
        ReceiptVerifyError::JwksParse("parse error".to_string()),
        ReceiptVerifyError::JwksFetch("fetch error".to_string()),
        ReceiptVerifyError::JwkNotFound("test_kid".to_string()),
        ReceiptVerifyError::JwkUnsupported("unsupported".to_string()),
        ReceiptVerifyError::StatementReencode("reencode error".to_string()),
        ReceiptVerifyError::SigStructureEncode("sig error".to_string()),
        ReceiptVerifyError::DataHashMismatch,
        ReceiptVerifyError::SignatureInvalid,
    ];

    for error in errors {
        let display_str = format!("{}", error);
        assert!(!display_str.is_empty());

        // Verify each error type has expected content in display string
        match &error {
            ReceiptVerifyError::ReceiptDecode(msg) => assert!(display_str.contains(msg)),
            ReceiptVerifyError::MissingAlg => assert!(display_str.contains("missing_alg")),
            ReceiptVerifyError::UnsupportedAlg(alg) => {
                assert!(display_str.contains(&alg.to_string()))
            }
            ReceiptVerifyError::DataHashMismatch => {
                assert!(display_str.contains("data_hash_mismatch"))
            }
            _ => {} // Other cases covered by basic non-empty check
        }

        // Test Debug implementation
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.is_empty());
    }
}

// Test std::error::Error implementation
#[test]
fn test_receipt_verify_error_is_error() {
    let error = ReceiptVerifyError::MissingAlg;

    // Should implement std::error::Error
    let error_trait: &dyn std::error::Error = &error;
    assert!(error_trait.source().is_none()); // These errors don't have sources
}

// Test helper functions for edge cases
#[test]
fn test_validate_receipt_alg_against_jwk() {
    // Test valid combinations
    let jwk_p256 = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: Some("test".to_string()),
        x: Some("test_x".to_string()),
        y: Some("test_y".to_string()),
    };

    let result = validate_receipt_alg_against_jwk(&jwk_p256, -7); // ES256
    assert!(result.is_ok());

    let jwk_p384 = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        kid: Some("test".to_string()),
        x: Some("test_x".to_string()),
        y: Some("test_y".to_string()),
    };

    let result = validate_receipt_alg_against_jwk(&jwk_p384, -35); // ES384
    assert!(result.is_ok());

    // Test mismatched combinations
    let result = validate_receipt_alg_against_jwk(&jwk_p256, -35); // P-256 with ES384
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::JwkUnsupported(msg) => {
            assert!(msg.contains("alg_curve_mismatch"));
        }
        _ => panic!("Expected JwkUnsupported error"),
    }

    // Test missing crv
    let jwk_no_crv = Jwk {
        kty: "EC".to_string(),
        crv: None, // Missing
        kid: Some("test".to_string()),
        x: Some("test_x".to_string()),
        y: Some("test_y".to_string()),
    };

    let result = validate_receipt_alg_against_jwk(&jwk_no_crv, -7);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::JwkUnsupported(msg) => {
            assert_eq!(msg, "missing_crv");
        }
        _ => panic!("Expected JwkUnsupported error"),
    }
}

// Test MstCcfInclusionProof clone and debug
#[test]
fn test_mst_ccf_inclusion_proof_traits() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![1, 2, 3],
        internal_evidence: "test".to_string(),
        data_hash: vec![4, 5, 6],
        path: vec![(true, vec![7, 8]), (false, vec![9, 10])],
    };

    // Test Clone
    let cloned = proof.clone();
    assert_eq!(proof.internal_txn_hash, cloned.internal_txn_hash);
    assert_eq!(proof.internal_evidence, cloned.internal_evidence);
    assert_eq!(proof.data_hash, cloned.data_hash);
    assert_eq!(proof.path, cloned.path);

    // Test Debug
    let debug_str = format!("{:?}", proof);
    assert!(debug_str.contains("MstCcfInclusionProof"));
    assert!(debug_str.contains("test"));
}

// Test Jwk clone and debug
#[test]
fn test_jwk_traits() {
    let jwk = Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        kid: Some("test_kid".to_string()),
        x: Some("test_x".to_string()),
        y: Some("test_y".to_string()),
    };

    // Test Clone
    let cloned = jwk.clone();
    assert_eq!(jwk.kty, cloned.kty);
    assert_eq!(jwk.crv, cloned.crv);
    assert_eq!(jwk.kid, cloned.kid);

    // Test Debug
    let debug_str = format!("{:?}", jwk);
    assert!(debug_str.contains("Jwk"));
    assert!(debug_str.contains("test_kid"));
}
