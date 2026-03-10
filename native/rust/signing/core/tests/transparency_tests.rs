// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for transparency provider functionality.

use std::collections::HashMap;
use cose_sign1_signing::{
    TransparencyError, TransparencyValidationResult, extract_receipts, merge_receipts,
    add_proof_with_receipt_merge, TransparencyProvider, RECEIPTS_HEADER_LABEL,
};
use cose_sign1_primitives::{CoseSign1Message, CoseHeaderLabel, CoseHeaderValue, CoseHeaderMap, ProtectedHeader};

#[test]
fn test_transparency_error_display() {
    let submission_err = TransparencyError::SubmissionFailed("submit failed".to_string());
    assert!(submission_err.to_string().contains("transparency submission failed"));
    assert!(submission_err.to_string().contains("submit failed"));

    let verification_err = TransparencyError::VerificationFailed("verify failed".to_string());
    assert!(verification_err.to_string().contains("transparency verification failed"));
    assert!(verification_err.to_string().contains("verify failed"));

    let invalid_msg_err = TransparencyError::InvalidMessage("invalid msg".to_string());
    assert!(invalid_msg_err.to_string().contains("invalid message"));
    assert!(invalid_msg_err.to_string().contains("invalid msg"));

    let provider_err = TransparencyError::ProviderError("provider error".to_string());
    assert!(provider_err.to_string().contains("provider error"));
    assert!(provider_err.to_string().contains("provider error"));
}

#[test]
fn test_transparency_error_debug() {
    let err = TransparencyError::SubmissionFailed("test".to_string());
    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("SubmissionFailed"));
}

#[test]
fn test_transparency_validation_result_success() {
    let result = TransparencyValidationResult::success("test_provider");
    assert!(result.is_valid);
    assert!(result.errors.is_empty());
    assert_eq!(result.provider_name, "test_provider");
    assert!(result.metadata.is_none());
}

#[test]
fn test_transparency_validation_result_success_with_metadata() {
    let mut metadata = HashMap::new();
    metadata.insert("version".to_string(), "1.0".to_string());
    
    let result = TransparencyValidationResult::success_with_metadata("test_provider", metadata.clone());
    assert!(result.is_valid);
    assert!(result.errors.is_empty());
    assert_eq!(result.provider_name, "test_provider");
    assert_eq!(result.metadata, Some(metadata));
}

#[test]
fn test_transparency_validation_result_failure() {
    let errors = vec!["error1".to_string(), "error2".to_string()];
    let result = TransparencyValidationResult::failure("test_provider", errors.clone());
    assert!(!result.is_valid);
    assert_eq!(result.errors, errors);
    assert_eq!(result.provider_name, "test_provider");
    assert!(result.metadata.is_none());
}

fn create_test_message() -> CoseSign1Message {
    CoseSign1Message {
        protected: ProtectedHeader::encode(CoseHeaderMap::new()).expect("Failed to encode protected header"),
        unprotected: CoseHeaderMap::new(),
        payload: Some(b"test payload".to_vec()),
        signature: b"fake signature".to_vec(),
    }
}

fn create_test_message_with_unprotected(unprotected: CoseHeaderMap) -> CoseSign1Message {
    CoseSign1Message {
        protected: ProtectedHeader::encode(CoseHeaderMap::new()).expect("Failed to encode protected header"),
        unprotected,
        payload: Some(b"test payload".to_vec()),
        signature: b"fake signature".to_vec(),
    }
}

#[test]
fn test_extract_receipts_empty_message() {
    let msg = create_test_message();
    let receipts = extract_receipts(&msg);
    assert!(receipts.is_empty());
}

#[test]
fn test_extract_receipts_missing_header() {
    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        CoseHeaderLabel::Int(123),
        CoseHeaderValue::Text("some other header".to_string()),
    );
    
    let msg = create_test_message_with_unprotected(unprotected);
    
    let receipts = extract_receipts(&msg);
    assert!(receipts.is_empty());
}

#[test]
fn test_extract_receipts_with_receipts() {
    let mut unprotected = CoseHeaderMap::new();
    let receipt1 = b"receipt1".to_vec();
    let receipt2 = b"receipt2".to_vec();
    
    let receipts_array = vec![
        CoseHeaderValue::Bytes(receipt1.clone()),
        CoseHeaderValue::Bytes(receipt2.clone()),
        CoseHeaderValue::Text("not a receipt".to_string()), // Should be filtered out
    ];
    
    unprotected.insert(
        CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL),
        CoseHeaderValue::Array(receipts_array),
    );
    
    let msg = create_test_message_with_unprotected(unprotected);
    
    let receipts = extract_receipts(&msg);
    assert_eq!(receipts.len(), 2);
    assert!(receipts.contains(&receipt1));
    assert!(receipts.contains(&receipt2));
}

#[test]
fn test_merge_receipts_empty_additional() {
    let mut msg = create_test_message();
    
    merge_receipts(&mut msg, &[]);
    
    // Should not have added any receipts header
    let receipts = extract_receipts(&msg);
    assert!(receipts.is_empty());
}

#[test]
fn test_merge_receipts_with_duplicates() {
    let receipt1 = b"receipt1".to_vec();
    let receipt2 = b"receipt2".to_vec();
    
    // Start with one receipt
    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(receipt1.clone())]),
    );
    
    let mut msg = create_test_message_with_unprotected(unprotected);
    
    // Try to add the same receipt plus a new one
    let additional = vec![receipt1.clone(), receipt2.clone()];
    merge_receipts(&mut msg, &additional);
    
    let receipts = extract_receipts(&msg);
    assert_eq!(receipts.len(), 2); // Should deduplicate
    assert!(receipts.contains(&receipt1));
    assert!(receipts.contains(&receipt2));
}

#[test]
fn test_merge_receipts_skip_empty() {
    let mut msg = create_test_message();
    
    let additional = vec![vec![], b"valid".to_vec(), vec![]];
    merge_receipts(&mut msg, &additional);
    
    let receipts = extract_receipts(&msg);
    assert_eq!(receipts.len(), 1);
    assert!(receipts.contains(&b"valid".to_vec()));
}

// Mock transparency provider for testing
struct MockTransparencyProvider {
    name: String,
    should_fail: bool,
    add_receipt: bool,
}

impl MockTransparencyProvider {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            should_fail: false,
            add_receipt: true,
        }
    }
    
    fn with_failure(mut self) -> Self {
        self.should_fail = true;
        self
    }
    
    fn without_receipt(mut self) -> Self {
        self.add_receipt = false;
        self
    }
}

impl TransparencyProvider for MockTransparencyProvider {
    fn provider_name(&self) -> &str {
        &self.name
    }
    
    fn add_transparency_proof(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, TransparencyError> {
        if self.should_fail {
            return Err(TransparencyError::SubmissionFailed("Mock failure".to_string()));
        }
        
        if !self.add_receipt {
            return Ok(cose_bytes.to_vec());
        }
        
        // Parse the message and add a fake receipt
        let mut msg = CoseSign1Message::parse(cose_bytes)
            .map_err(|e| TransparencyError::InvalidMessage(e.to_string()))?;
            
        let fake_receipt = format!("receipt-{}", self.name).into_bytes();
        merge_receipts(&mut msg, &[fake_receipt]);
        
        msg.encode(true)
            .map_err(|e| TransparencyError::InvalidMessage(e.to_string()))
    }
    
    fn verify_transparency_proof(&self, _cose_bytes: &[u8]) -> Result<TransparencyValidationResult, TransparencyError> {
        if self.should_fail {
            return Err(TransparencyError::VerificationFailed("Mock verification failure".to_string()));
        }
        
        Ok(TransparencyValidationResult::success(&self.name))
    }
}

#[test]
fn test_add_proof_with_receipt_merge_success() {
    let provider = MockTransparencyProvider::new("test");
    
    // Create a simple COSE message
    let msg = create_test_message();
    
    let original_bytes = msg.encode(true).expect("Failed to encode message");
    let result = add_proof_with_receipt_merge(&provider, &original_bytes);
    
    assert!(result.is_ok());
    let result_bytes = result.unwrap();
    
    // Parse the result and check that a receipt was added
    let result_msg = CoseSign1Message::parse(&result_bytes).expect("Failed to parse result");
    let receipts = extract_receipts(&result_msg);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0], b"receipt-test".to_vec());
}

#[test]
fn test_add_proof_with_receipt_merge_preserve_existing() {
    let provider = MockTransparencyProvider::new("test");
    
    // Create a message with an existing receipt
    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(b"existing-receipt".to_vec())]),
    );
    
    let msg = create_test_message_with_unprotected(unprotected);
    
    let original_bytes = msg.encode(true).expect("Failed to encode message");
    let result = add_proof_with_receipt_merge(&provider, &original_bytes);
    
    assert!(result.is_ok());
    let result_bytes = result.unwrap();
    
    // Parse the result and check that both receipts are present
    let result_msg = CoseSign1Message::parse(&result_bytes).expect("Failed to parse result");
    let receipts = extract_receipts(&result_msg);
    assert_eq!(receipts.len(), 2);
    assert!(receipts.contains(&b"existing-receipt".to_vec()));
    assert!(receipts.contains(&b"receipt-test".to_vec()));
}

#[test]
fn test_add_proof_with_receipt_merge_provider_error() {
    let provider = MockTransparencyProvider::new("test").with_failure();
    
    let msg = create_test_message();
    
    let original_bytes = msg.encode(true).expect("Failed to encode message");
    let result = add_proof_with_receipt_merge(&provider, &original_bytes);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        TransparencyError::SubmissionFailed(msg) => assert!(msg.contains("Mock failure")),
        _ => panic!("Expected SubmissionFailed error"),
    }
}

#[test]
fn test_add_proof_with_receipt_merge_invalid_input() {
    let provider = MockTransparencyProvider::new("test");
    
    // Use invalid COSE bytes
    let invalid_bytes = b"not a valid cose message";
    let result = add_proof_with_receipt_merge(&provider, invalid_bytes);
    
    // Should fail because the provider will try to parse the invalid message
    assert!(result.is_err());
    match result.unwrap_err() {
        TransparencyError::InvalidMessage(_) => {},
        _ => panic!("Expected InvalidMessage error"),
    }
}

#[test] 
fn test_add_proof_with_receipt_merge_no_new_receipt() {
    let provider = MockTransparencyProvider::new("test").without_receipt();
    
    // Create a message with an existing receipt
    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL),
        CoseHeaderValue::Array(vec![CoseHeaderValue::Bytes(b"existing-receipt".to_vec())]),
    );
    
    let msg = create_test_message_with_unprotected(unprotected);
    
    let original_bytes = msg.encode(true).expect("Failed to encode message");
    let result = add_proof_with_receipt_merge(&provider, &original_bytes);
    
    assert!(result.is_ok());
    // Should preserve the existing receipt even if provider doesn't add new ones
    let result_bytes = result.unwrap();
    let result_msg = CoseSign1Message::parse(&result_bytes).expect("Failed to parse result");
    let receipts = extract_receipts(&result_msg);
    assert_eq!(receipts.len(), 1);
    assert!(receipts.contains(&b"existing-receipt".to_vec()));
}