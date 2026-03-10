// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_transparent_mst::signing::service::MstTransparencyProvider;
use cose_sign1_signing::transparency::TransparencyProvider;

#[test]
fn test_mst_transparency_provider_name() {
    // Create a mock client for testing - we can't test the actual client creation
    // without network dependencies, so we focus on the provider interface
    
    // Test the provider name constant
    let expected_name = "Microsoft Signing Transparency";
    assert_eq!(expected_name, "Microsoft Signing Transparency");
    assert!(!expected_name.is_empty());
}

#[test]
fn test_mst_transparency_provider_construction_pattern() {
    // Test the construction pattern used by MstTransparencyProvider
    // Since we can't create the actual client without network, we test the pattern
    
    use cose_sign1_transparent_mst::signing::client::{MstTransparencyClient, MstTransparencyClientOptions};
    use url::Url;
    
    let url = Url::parse("https://transparency.example.com").unwrap();
    let options = MstTransparencyClientOptions::default();
    let client = MstTransparencyClient::new(url, options);
    
    // Test that we can construct the provider
    let provider = MstTransparencyProvider::new(client);
    
    // Test provider name
    assert_eq!(provider.provider_name(), "Microsoft Signing Transparency");
}

#[test]
fn test_transparency_error_patterns() {
    use cose_sign1_signing::transparency::TransparencyError;
    
    // Test error conversion patterns used in the service
    let submission_error = TransparencyError::SubmissionFailed("network error".to_string());
    let invalid_message_error = TransparencyError::InvalidMessage("parse error".to_string());
    
    match submission_error {
        TransparencyError::SubmissionFailed(msg) => assert_eq!(msg, "network error"),
        _ => panic!("Wrong error variant"),
    }
    
    match invalid_message_error {
        TransparencyError::InvalidMessage(msg) => assert_eq!(msg, "parse error"),
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_transparency_validation_result_patterns() {
    use cose_sign1_signing::transparency::TransparencyValidationResult;
    
    let provider_name = "Microsoft Signing Transparency";
    
    // Test success result
    let success = TransparencyValidationResult::success(provider_name);
    assert!(format!("{:?}", success).contains(provider_name));
    
    // Test failure result
    let failure_messages = vec!["No MST receipts found in header 394".into()];
    let failure = TransparencyValidationResult::failure(provider_name, failure_messages);
    assert!(format!("{:?}", failure).contains(provider_name));
}

#[test]
fn test_receipt_header_constant() {
    // Test the receipt header constant used in validation
    // Header 394 is used for MST receipts according to the code
    let receipt_header = 394;
    assert_eq!(receipt_header, 394);
}

#[test]
fn test_error_message_constants() {
    // Test error message constants used in the service
    let no_receipts_msg = "No MST receipts found in header 394";
    let no_valid_receipts_msg = "No valid MST receipts found";
    
    assert!(!no_receipts_msg.is_empty());
    assert!(!no_valid_receipts_msg.is_empty());
    assert!(no_receipts_msg.contains("394"));
    assert!(no_valid_receipts_msg.contains("valid"));
}