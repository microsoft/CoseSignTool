// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct test coverage for MST receipt verification internal helper functions.
//! These tests target the pub helper functions to ensure full line coverage.

use cbor_primitives::CborEncoder;
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, ProtectedHeader};
use cose_sign1_transparent_mst::validation::receipt_verify::{
    ring_verifier_for_cose_alg, ccf_accumulator_sha256, extract_proof_blobs, get_cwt_issuer_host,
    MstCcfInclusionProof, reencode_statement_with_cleared_unprotected_headers,
    ReceiptVerifyError, is_cose_sign1_tagged_18, parse_leaf, parse_path,
};

#[test]
fn test_ring_verifier_for_cose_alg_es256() {
    let verifier = ring_verifier_for_cose_alg(-7).unwrap(); // ES256
    // Just check that we get a valid verifier - the actual verification
    // behavior is tested in integration tests
    let _ = verifier; // Ensure it compiles and doesn't panic
}

#[test]
fn test_ring_verifier_for_cose_alg_es384() {
    let verifier = ring_verifier_for_cose_alg(-35).unwrap(); // ES384
    // Just check that we get a valid verifier
    let _ = verifier; // Ensure it compiles and doesn't panic
}

#[test]
fn test_ring_verifier_for_cose_alg_unsupported() {
    let result = ring_verifier_for_cose_alg(-999);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::UnsupportedAlg(-999) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_ring_verifier_for_cose_alg_rs256() {
    // RS256 is not supported by MST
    let result = ring_verifier_for_cose_alg(-257);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::UnsupportedAlg(-257) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_valid() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0x42; 32], // 32 bytes
        internal_evidence: "test evidence".to_string(),
        data_hash: vec![0x01; 32], // 32 bytes  
        path: vec![(true, vec![0x02; 32])],
    };
    
    let expected_data_hash = [0x01; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert!(result.is_ok());
    
    // Result should be deterministic
    let result2 = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert_eq!(result.unwrap(), result2.unwrap());
}

#[test]
fn test_ccf_accumulator_sha256_wrong_internal_txn_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0x42; 31], // Wrong length
        internal_evidence: "test evidence".to_string(),
        data_hash: vec![0x01; 32],
        path: vec![],
    };
    
    let expected_data_hash = [0x01; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_internal_txn_hash_len: 31"));
        },
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_wrong_data_hash_len() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0x42; 32],
        internal_evidence: "test evidence".to_string(),
        data_hash: vec![0x01; 31], // Wrong length
        path: vec![],
    };
    
    let expected_data_hash = [0x01; 32];
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert!(msg.contains("unexpected_data_hash_len: 31"));
        },
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_ccf_accumulator_sha256_data_hash_mismatch() {
    let proof = MstCcfInclusionProof {
        internal_txn_hash: vec![0x42; 32],
        internal_evidence: "test evidence".to_string(),
        data_hash: vec![0x01; 32],
        path: vec![],
    };
    
    let expected_data_hash = [0x02; 32]; // Different from proof.data_hash
    let result = ccf_accumulator_sha256(&proof, expected_data_hash);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::DataHashMismatch => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_extract_proof_blobs_valid_map() {
    // Create a proper VDP header value (Map with proof array under label -1)
    let pairs = vec![
        (CoseHeaderLabel::Int(-1), CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![0x01, 0x02, 0x03]),
            CoseHeaderValue::Bytes(vec![0x04, 0x05, 0x06]),
        ])),
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Int(42)), // Other label
    ];
    let vdp_value = CoseHeaderValue::Map(pairs);
    
    let result = extract_proof_blobs(&vdp_value).unwrap();
    assert_eq!(result.len(), 2);
    assert_eq!(result[0], vec![0x01, 0x02, 0x03]);
    assert_eq!(result[1], vec![0x04, 0x05, 0x06]);
}

#[test]
fn test_extract_proof_blobs_not_map() {
    let vdp_value = CoseHeaderValue::Int(42); // Not a map
    let result = extract_proof_blobs(&vdp_value);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "vdp_not_a_map");
        },
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_extract_proof_blobs_missing_proof_label() {
    // Map without the proof label (-1)
    let pairs = vec![
        (CoseHeaderLabel::Int(1), CoseHeaderValue::Array(vec![
            CoseHeaderValue::Bytes(vec![0x01, 0x02, 0x03]),
        ])),
    ];
    let vdp_value = CoseHeaderValue::Map(pairs);
    
    let result = extract_proof_blobs(&vdp_value);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof => {},
        _ => panic!("Wrong error type"),
    }
}

#[test] 
fn test_extract_proof_blobs_proof_not_array() {
    let pairs = vec![
        (CoseHeaderLabel::Int(-1), CoseHeaderValue::Int(42)), // Not an array
    ];
    let vdp_value = CoseHeaderValue::Map(pairs);
    
    let result = extract_proof_blobs(&vdp_value);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "proof_not_array");
        },
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_extract_proof_blobs_empty_array() {
    let pairs = vec![
        (CoseHeaderLabel::Int(-1), CoseHeaderValue::Array(vec![])), // Empty array
    ];
    let vdp_value = CoseHeaderValue::Map(pairs);
    
    let result = extract_proof_blobs(&vdp_value);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_extract_proof_blobs_non_bytes_item() {
    let pairs = vec![
        (CoseHeaderLabel::Int(-1), CoseHeaderValue::Array(vec![
            CoseHeaderValue::Int(42), // Not bytes
        ])),
    ];
    let vdp_value = CoseHeaderValue::Map(pairs);
    
    let result = extract_proof_blobs(&vdp_value);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(msg) => {
            assert_eq!(msg, "proof_item_not_bstr");
        },
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_get_cwt_issuer_host_valid() {
    // Create a protected header with CWT claims containing issuer
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap(); // CWT claims label
    {
        let mut cwt_enc = cose_sign1_primitives::provider::encoder();
        cwt_enc.encode_map(2).unwrap();
        cwt_enc.encode_i64(1).unwrap(); // issuer label
        cwt_enc.encode_tstr("example.com").unwrap();
        cwt_enc.encode_i64(2).unwrap(); // other claim
        cwt_enc.encode_tstr("other").unwrap();
        enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
    }
    let protected_bytes = enc.into_bytes();
    
    let protected = ProtectedHeader::decode(protected_bytes).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, Some("example.com".to_string()));
}

#[test]
fn test_get_cwt_issuer_host_missing_cwt_claims() {
    // Protected header without CWT claims
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // alg label (not CWT claims)
    enc.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = enc.into_bytes();
    
    let protected = ProtectedHeader::decode(protected_bytes).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, None);
}

#[test]
fn test_get_cwt_issuer_host_missing_issuer_in_claims() {
    // CWT claims without issuer
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap(); // CWT claims label
    {
        let mut cwt_enc = cose_sign1_primitives::provider::encoder();
        cwt_enc.encode_map(1).unwrap();
        cwt_enc.encode_i64(2).unwrap(); // different claim (not issuer)
        cwt_enc.encode_tstr("other").unwrap();
        enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
    }
    let protected_bytes = enc.into_bytes();
    
    let protected = ProtectedHeader::decode(protected_bytes).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, None);
}

#[test]
fn test_get_cwt_issuer_host_non_map_cwt_claims() {
    // CWT claims that's not a map
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap(); // CWT claims label
    enc.encode_tstr("not-a-map").unwrap(); // String instead of map
    let protected_bytes = enc.into_bytes();
    
    let protected = ProtectedHeader::decode(protected_bytes).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, None);
}

#[test]
fn test_get_cwt_issuer_host_non_string_issuer() {
    // CWT claims with issuer that's not a string
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(15).unwrap(); // CWT claims label
    {
        let mut cwt_enc = cose_sign1_primitives::provider::encoder();
        cwt_enc.encode_map(1).unwrap();
        cwt_enc.encode_i64(1).unwrap(); // issuer label
        cwt_enc.encode_i64(42).unwrap(); // Int instead of string
        enc.encode_raw(&cwt_enc.into_bytes()).unwrap();
    }
    let protected_bytes = enc.into_bytes();
    
    let protected = ProtectedHeader::decode(protected_bytes).unwrap();
    let result = get_cwt_issuer_host(&protected, 15, 1);
    assert_eq!(result, None);
}

#[test]
fn test_mst_ccf_inclusion_proof_parse_valid() {
    // Create a valid proof blob (map with leaf and path)
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(2).unwrap();
    
    // Key 1: leaf (array with internal_txn_hash, evidence, data_hash)
    enc.encode_i64(1).unwrap();
    {
        let mut leaf_enc = cose_sign1_primitives::provider::encoder();
        leaf_enc.encode_array(3).unwrap();
        leaf_enc.encode_bstr(&[0x42; 32]).unwrap(); // internal_txn_hash
        leaf_enc.encode_tstr("test evidence").unwrap(); // internal_evidence  
        leaf_enc.encode_bstr(&[0x01; 32]).unwrap(); // data_hash
        enc.encode_raw(&leaf_enc.into_bytes()).unwrap();
    }
    
    // Key 2: path (array of [bool, bytes] pairs)
    enc.encode_i64(2).unwrap();
    {
        let mut path_enc = cose_sign1_primitives::provider::encoder();
        path_enc.encode_array(1).unwrap(); // One path element
        {
            let mut pair_enc = cose_sign1_primitives::provider::encoder();
            pair_enc.encode_array(2).unwrap();
            pair_enc.encode_bool(true).unwrap(); // direction
            pair_enc.encode_bstr(&[0x02; 32]).unwrap(); // sibling hash
            path_enc.encode_raw(&pair_enc.into_bytes()).unwrap();
        }
        enc.encode_raw(&path_enc.into_bytes()).unwrap();
    }
    
    let proof_blob = enc.into_bytes();
    let result = MstCcfInclusionProof::parse(&proof_blob).unwrap();
    
    assert_eq!(result.internal_txn_hash, vec![0x42; 32]);
    assert_eq!(result.internal_evidence, "test evidence");
    assert_eq!(result.data_hash, vec![0x01; 32]);
    assert_eq!(result.path.len(), 1);
    assert_eq!(result.path[0].0, true);
    assert_eq!(result.path[0].1, vec![0x02; 32]);
}

#[test]
fn test_mst_ccf_inclusion_proof_parse_missing_leaf() {
    // Map without leaf (key 1)
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(2).unwrap(); // Only path, no leaf
    enc.encode_bstr(&[]).unwrap(); // Empty path
    
    let proof_blob = enc.into_bytes();
    let result = MstCcfInclusionProof::parse(&proof_blob);
    assert!(result.is_err());
    // The error could be either MissingProof or ReceiptDecode depending on the exact failure
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof | ReceiptVerifyError::ReceiptDecode(_) => {},
        e => panic!("Expected MissingProof or ReceiptDecode, got: {:?}", e),
    }
}

#[test]
fn test_mst_ccf_inclusion_proof_parse_missing_path() {
    // Map without path (key 2)
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // Only leaf, no path
    {
        let mut leaf_enc = cose_sign1_primitives::provider::encoder();
        leaf_enc.encode_array(3).unwrap();
        leaf_enc.encode_bstr(&[0x42; 32]).unwrap();
        leaf_enc.encode_tstr("test").unwrap();
        leaf_enc.encode_bstr(&[0x01; 32]).unwrap();
        enc.encode_raw(&leaf_enc.into_bytes()).unwrap();
    }
    
    let proof_blob = enc.into_bytes();
    let result = MstCcfInclusionProof::parse(&proof_blob);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::MissingProof => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_mst_ccf_inclusion_proof_parse_invalid_cbor() {
    let proof_blob = &[0xFF, 0xFF]; // Invalid CBOR
    let result = MstCcfInclusionProof::parse(proof_blob);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(_) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_parse_leaf_valid() {
    // Create valid leaf bytes (array with 3 elements)
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(3).unwrap();
    enc.encode_bstr(&[0x42; 32]).unwrap(); // internal_txn_hash
    enc.encode_tstr("test evidence").unwrap(); // internal_evidence
    enc.encode_bstr(&[0x01; 32]).unwrap(); // data_hash
    
    let leaf_bytes = enc.into_bytes();
    let result = parse_leaf(&leaf_bytes).unwrap();
    
    assert_eq!(result.0, vec![0x42; 32]); // internal_txn_hash
    assert_eq!(result.1, "test evidence"); // internal_evidence
    assert_eq!(result.2, vec![0x01; 32]); // data_hash
}

#[test]
fn test_parse_leaf_invalid_cbor() {
    let leaf_bytes = &[0xFF, 0xFF]; // Invalid CBOR
    let result = parse_leaf(leaf_bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(_) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test] 
fn test_parse_path_valid() {
    // Create valid path bytes (array of arrays)
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(2).unwrap(); // Two path elements
    
    // First element [true, bytes]
    {
        let mut pair_enc = cose_sign1_primitives::provider::encoder();
        pair_enc.encode_array(2).unwrap();
        pair_enc.encode_bool(true).unwrap();
        pair_enc.encode_bstr(&[0x01; 32]).unwrap();
        enc.encode_raw(&pair_enc.into_bytes()).unwrap();
    }
    
    // Second element [false, bytes]
    {
        let mut pair_enc = cose_sign1_primitives::provider::encoder();
        pair_enc.encode_array(2).unwrap();
        pair_enc.encode_bool(false).unwrap(); 
        pair_enc.encode_bstr(&[0x02; 32]).unwrap();
        enc.encode_raw(&pair_enc.into_bytes()).unwrap();
    }
    
    let path_bytes = enc.into_bytes();
    let result = parse_path(&path_bytes).unwrap();
    
    assert_eq!(result.len(), 2);
    assert_eq!(result[0].0, true);
    assert_eq!(result[0].1, vec![0x01; 32]);
    assert_eq!(result[1].0, false);
    assert_eq!(result[1].1, vec![0x02; 32]);
}

#[test]
fn test_parse_path_invalid_cbor() {
    let path_bytes = &[0xFF, 0xFF]; // Invalid CBOR
    let result = parse_path(path_bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::ReceiptDecode(_) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_reencode_statement_tagged_cose_sign1() {
    // Create a tagged COSE_Sign1 message
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_tag(18).unwrap(); // COSE_Sign1 tag
    enc.encode_array(4).unwrap();
    
    // Create protected header as a proper CBOR-encoded map
    let mut prot_enc = cose_sign1_primitives::provider::encoder();
    prot_enc.encode_map(1).unwrap();
    prot_enc.encode_i64(1).unwrap(); // alg label
    prot_enc.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = prot_enc.into_bytes();
    
    enc.encode_bstr(&protected_bytes).unwrap(); // protected
    enc.encode_map(1).unwrap(); // unprotected with one header
    enc.encode_i64(42).unwrap();
    enc.encode_i64(123).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0x03, 0x04]).unwrap(); // signature
    
    let statement_bytes = enc.into_bytes();
    let result = reencode_statement_with_cleared_unprotected_headers(&statement_bytes).unwrap();
    
    // Should start with tag 18 and have empty unprotected headers
    assert!(result.len() > 0);
    
    // Verify it starts with tag 18
    assert!(is_cose_sign1_tagged_18(&result).unwrap());
}

#[test]
fn test_reencode_statement_untagged_cose_sign1() {
    // Create an untagged COSE_Sign1 message
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    
    // Create protected header as a proper CBOR-encoded map
    let mut prot_enc = cose_sign1_primitives::provider::encoder();
    prot_enc.encode_map(1).unwrap();
    prot_enc.encode_i64(1).unwrap(); // alg label
    prot_enc.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = prot_enc.into_bytes();
    
    enc.encode_bstr(&protected_bytes).unwrap(); // protected
    enc.encode_map(1).unwrap(); // unprotected with one header
    enc.encode_i64(42).unwrap();
    enc.encode_i64(123).unwrap();
    enc.encode_bstr(b"payload").unwrap();
    enc.encode_bstr(&[0x03, 0x04]).unwrap(); // signature
    
    let statement_bytes = enc.into_bytes();
    let result = reencode_statement_with_cleared_unprotected_headers(&statement_bytes).unwrap();
    
    // Should not have tag 18 and should have empty unprotected headers
    assert!(result.len() > 0);
    
    // Verify it doesn't start with tag 18
    assert!(!is_cose_sign1_tagged_18(&result).unwrap());
}

#[test]
fn test_reencode_statement_invalid_cbor() {
    let invalid_bytes = &[0xFF, 0xFF];
    let result = reencode_statement_with_cleared_unprotected_headers(invalid_bytes);
    assert!(result.is_err());
    match result.unwrap_err() {
        ReceiptVerifyError::StatementReencode(_) => {},
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_reencode_statement_null_payload() {
    // Create COSE_Sign1 with null payload
    let mut enc = cose_sign1_primitives::provider::encoder();
    enc.encode_array(4).unwrap();
    
    // Create protected header as a proper CBOR-encoded map
    let mut prot_enc = cose_sign1_primitives::provider::encoder();
    prot_enc.encode_map(1).unwrap();
    prot_enc.encode_i64(1).unwrap(); // alg label
    prot_enc.encode_i64(-7).unwrap(); // ES256
    let protected_bytes = prot_enc.into_bytes();
    
    enc.encode_bstr(&protected_bytes).unwrap(); // protected
    enc.encode_map(0).unwrap(); // empty unprotected
    enc.encode_null().unwrap(); // null payload
    enc.encode_bstr(&[0x03, 0x04]).unwrap(); // signature
    
    let statement_bytes = enc.into_bytes();
    let result = reencode_statement_with_cleared_unprotected_headers(&statement_bytes).unwrap();
    
    // Should handle null payload correctly
    assert!(result.len() > 0);
}
