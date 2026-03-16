// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for provider registry functions.

#[cfg(any(feature = "crypto-openssl", feature = "certificates", feature = "akv", feature = "ats", feature = "mst"))]
use cose_sign1_cli::providers::signing;

#[cfg(any(feature = "certificates", feature = "akv", feature = "mst"))]
use cose_sign1_cli::providers::verification;

#[cfg(any(feature = "crypto-openssl", feature = "certificates", feature = "akv", feature = "ats"))]
#[test]
fn test_signing_available_providers_contains_expected() {
    let providers = signing::available_providers();
    let provider_names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    
    // With default features, we should have at least these OpenSSL-based providers
    #[cfg(feature = "crypto-openssl")]
    {
        assert!(provider_names.contains(&"der"));
        assert!(provider_names.contains(&"pfx"));
        assert!(provider_names.contains(&"pem"));
    }
    
    #[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
    {
        assert!(provider_names.contains(&"ephemeral"));
    }
    
    #[cfg(feature = "akv")]
    {
        assert!(provider_names.contains(&"akv-cert"));
        assert!(provider_names.contains(&"akv-key"));
    }
    
    #[cfg(feature = "ats")]
    {
        assert!(provider_names.contains(&"ats"));
    }
    
    // Should not be empty with default features
    assert!(!providers.is_empty(), "Should have at least one signing provider");
}

#[cfg(any(feature = "crypto-openssl", feature = "akv", feature = "ats"))]
#[test]
fn test_signing_find_provider_existing() {
    #[cfg(feature = "crypto-openssl")]
    {
        let provider = signing::find_provider("der");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "der");
        
        let provider = signing::find_provider("pfx");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "pfx");
        
        let provider = signing::find_provider("pem");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "pem");
    }
    
    #[cfg(feature = "akv")]
    {
        let provider = signing::find_provider("akv-cert");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "akv-cert");
        
        let provider = signing::find_provider("akv-key");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "akv-key");
    }
    
    #[cfg(feature = "ats")]
    {
        let provider = signing::find_provider("ats");
        assert!(provider.is_some());
        assert_eq!(provider.unwrap().name(), "ats");
    }
}

#[cfg(any(feature = "crypto-openssl", feature = "akv", feature = "ats"))]
#[test]
fn test_signing_find_provider_nonexistent() {
    let provider = signing::find_provider("nonexistent");
    assert!(provider.is_none());
    
    let provider = signing::find_provider("invalid-provider");
    assert!(provider.is_none());
    
    let provider = signing::find_provider("");
    assert!(provider.is_none());
}

#[cfg(any(feature = "certificates", feature = "akv", feature = "mst"))]
#[test]
fn test_verification_available_providers_contains_expected() {
    let providers = verification::available_providers();
    let provider_names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    
    #[cfg(feature = "certificates")]
    {
        assert!(provider_names.contains(&"certificates"));
    }
    
    #[cfg(feature = "akv")]
    {
        assert!(provider_names.contains(&"akv"));
    }
    
    #[cfg(feature = "mst")]
    {
        assert!(provider_names.contains(&"mst"));
    }
    
    // Should not be empty with default features
    assert!(!providers.is_empty(), "Should have at least one verification provider");
}

#[cfg(any(feature = "crypto-openssl", feature = "certificates", feature = "akv", feature = "ats", feature = "mst"))]
#[test]
fn test_provider_names_are_unique() {
    let signing_providers = signing::available_providers();
    let signing_names: Vec<&str> = signing_providers.iter().map(|p| p.name()).collect();
    let mut unique_signing_names = signing_names.clone();
    unique_signing_names.sort();
    unique_signing_names.dedup();
    assert_eq!(signing_names.len(), unique_signing_names.len(), "Signing provider names should be unique");
    
    let verification_providers = verification::available_providers();
    let verification_names: Vec<&str> = verification_providers.iter().map(|p| p.name()).collect();
    let mut unique_verification_names = verification_names.clone();
    unique_verification_names.sort();
    unique_verification_names.dedup();
    assert_eq!(verification_names.len(), unique_verification_names.len(), "Verification provider names should be unique");
}

// Test crypto provider functionality
#[cfg(feature = "crypto-openssl")]
#[test]
fn test_crypto_active_provider() {
    use cose_sign1_cli::providers::crypto;
    
    let provider = crypto::active_provider();
    assert!(!provider.name().is_empty(), "Provider should have a name");
}

#[test]
fn test_output_format_display() {
    use cose_sign1_cli::providers::output::OutputFormat;
    
    // Test Debug trait
    assert!(!format!("{:?}", OutputFormat::Text).is_empty());
    assert!(!format!("{:?}", OutputFormat::Json).is_empty());
    assert!(!format!("{:?}", OutputFormat::Quiet).is_empty());
}

#[test]
fn test_provider_validation_edge_cases() {
    // Test empty string provider lookup
    #[cfg(any(feature = "crypto-openssl", feature = "akv", feature = "ats"))]
    {
        let provider = signing::find_provider("");
        assert!(provider.is_none());
    }
    
    // Test case sensitivity
    #[cfg(feature = "crypto-openssl")]
    {
        let provider = signing::find_provider("DER"); // uppercase
        assert!(provider.is_none(), "Provider lookup should be case sensitive");
    }
}
