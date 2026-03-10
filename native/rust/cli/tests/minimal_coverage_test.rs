// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal test to verify CLI test framework.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::providers::signing::{available_providers, find_provider};

#[test]
fn test_basic_provider_functionality() {
    let providers = available_providers();
    assert!(!providers.is_empty(), "Should have providers available");
    
    let der_provider = find_provider("der");
    assert!(der_provider.is_some(), "DER provider should be available");
}

#[test]  
fn test_nonexistent_provider() {
    let provider = find_provider("nonexistent");
    assert!(provider.is_none(), "Nonexistent provider should not be found");
}