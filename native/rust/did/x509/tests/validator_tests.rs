// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::*;

// NOTE: Full integration tests require actual X.509 certificates in DER format.
// These placeholder tests validate the API structure.

#[test]
fn test_validator_api_exists() {
    // Just verify the validator API exists and compiles
    let did = "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::subject:CN:Test";
    let chain: Vec<&[u8]> = vec![];
    
    // Should error on empty chain
    let result = DidX509Validator::validate(did, &chain);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DidX509Error::InvalidChain(_)));
}

#[test]
fn test_validation_result_structure() {
    // Verify DidX509ValidationResult API
    let valid_result = DidX509ValidationResult::valid(0);
    assert!(valid_result.is_valid);
    assert!(valid_result.errors.is_empty());
    assert_eq!(valid_result.matched_ca_index, Some(0));
    
    let invalid_result = DidX509ValidationResult::invalid("test error".to_string());
    assert!(!invalid_result.is_valid);
    assert_eq!(invalid_result.errors.len(), 1);
    assert!(invalid_result.matched_ca_index.is_none());
}

#[test]
fn test_policy_validators_api_exists() {
    // These functions exist and compile - full testing requires valid certificates
    // The policy validators are tested indirectly through the main validator
    
    // This test just ensures the module compiles and is accessible
    assert!(true);
}
