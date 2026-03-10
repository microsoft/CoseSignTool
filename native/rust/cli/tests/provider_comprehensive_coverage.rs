// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive provider coverage tests covering uncovered lines.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::providers::signing::{available_providers, find_provider};

#[test]
fn test_available_providers_comprehensive() {
    let providers = available_providers();
    
    // Should have at least one provider with crypto-openssl feature
    assert!(!providers.is_empty(), "Should have at least one provider available");
    
    // Check that all providers have valid names
    for provider in &providers {
        let name = provider.name();
        assert!(!name.is_empty(), "Provider name should not be empty");
        assert!(name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), 
                "Provider name should be alphanumeric with dashes/underscores");
        
        let description = provider.description();
        assert!(!description.is_empty(), "Provider description should not be empty");
    }
    
    // With crypto-openssl feature, we should have DER, PFX, PEM providers
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    assert!(provider_names.contains(&"der"), "Should have DER provider");
    assert!(provider_names.contains(&"pfx"), "Should have PFX provider");  
    assert!(provider_names.contains(&"pem"), "Should have PEM provider");
    
    // Check provider uniqueness
    let mut unique_names = std::collections::HashSet::new();
    for name in &provider_names {
        assert!(unique_names.insert(*name), "Provider names should be unique: {}", name);
    }
}

#[test]
fn test_find_provider_existing() {
    // Test finding each provider that should exist with crypto-openssl
    let der_provider = find_provider("der");
    assert!(der_provider.is_some(), "DER provider should be findable");
    assert_eq!(der_provider.unwrap().name(), "der");
    
    let pfx_provider = find_provider("pfx");
    assert!(pfx_provider.is_some(), "PFX provider should be findable");
    assert_eq!(pfx_provider.unwrap().name(), "pfx");
    
    let pem_provider = find_provider("pem");
    assert!(pem_provider.is_some(), "PEM provider should be findable");
    assert_eq!(pem_provider.unwrap().name(), "pem");
}

#[test]
fn test_find_provider_nonexistent() {
    let result = find_provider("nonexistent");
    assert!(result.is_none(), "Nonexistent provider should not be found");
    
    let result = find_provider("");
    assert!(result.is_none(), "Empty provider name should not be found");
    
    let result = find_provider("invalid-provider-name");
    assert!(result.is_none(), "Invalid provider name should not be found");
    
    let result = find_provider("DER"); // Case sensitive
    assert!(result.is_none(), "Case-sensitive lookup should not find 'DER' vs 'der'");
}

#[test]
fn test_find_provider_case_sensitivity() {
    // Provider names should be case sensitive
    assert!(find_provider("der").is_some());
    assert!(find_provider("DER").is_none());
    assert!(find_provider("Der").is_none());
    assert!(find_provider("dEr").is_none());
    
    assert!(find_provider("pfx").is_some());
    assert!(find_provider("PFX").is_none());
    
    assert!(find_provider("pem").is_some());
    assert!(find_provider("PEM").is_none());
}

#[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
#[test]
fn test_ephemeral_provider_availability() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // With both crypto-openssl and certificates features, ephemeral should be available
    assert!(provider_names.contains(&"ephemeral"), "Should have ephemeral provider with certificates feature");
    
    let ephemeral_provider = find_provider("ephemeral");
    assert!(ephemeral_provider.is_some(), "Ephemeral provider should be findable");
    assert_eq!(ephemeral_provider.unwrap().name(), "ephemeral");
}

#[cfg(not(all(feature = "crypto-openssl", feature = "certificates")))]
#[test]
fn test_ephemeral_provider_unavailable() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // Without both crypto-openssl and certificates features, ephemeral should not be available
    assert!(!provider_names.contains(&"ephemeral"), "Should not have ephemeral provider without certificates feature");
    
    let ephemeral_provider = find_provider("ephemeral");
    assert!(ephemeral_provider.is_none(), "Ephemeral provider should not be findable without certificates feature");
}

#[cfg(feature = "akv")]
#[test]
fn test_akv_providers_availability() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // With AKV feature, should have AKV providers
    assert!(provider_names.contains(&"akv-cert"), "Should have AKV cert provider with akv feature");
    assert!(provider_names.contains(&"akv-key"), "Should have AKV key provider with akv feature");
    
    let akv_cert_provider = find_provider("akv-cert");
    assert!(akv_cert_provider.is_some(), "AKV cert provider should be findable");
    assert_eq!(akv_cert_provider.unwrap().name(), "akv-cert");
    
    let akv_key_provider = find_provider("akv-key");
    assert!(akv_key_provider.is_some(), "AKV key provider should be findable");
    assert_eq!(akv_key_provider.unwrap().name(), "akv-key");
}

#[cfg(not(feature = "akv"))]
#[test]
fn test_akv_providers_unavailable() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // Without AKV feature, should not have AKV providers
    assert!(!provider_names.contains(&"akv-cert"), "Should not have AKV cert provider without akv feature");
    assert!(!provider_names.contains(&"akv-key"), "Should not have AKV key provider without akv feature");
    
    let akv_cert_provider = find_provider("akv-cert");
    assert!(akv_cert_provider.is_none(), "AKV cert provider should not be findable without akv feature");
    
    let akv_key_provider = find_provider("akv-key");
    assert!(akv_key_provider.is_none(), "AKV key provider should not be findable without akv feature");
}

#[cfg(feature = "ats")]
#[test]
fn test_ats_provider_availability() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // With ATS feature, should have ATS provider
    assert!(provider_names.contains(&"ats"), "Should have ATS provider with ats feature");
    
    let ats_provider = find_provider("ats");
    assert!(ats_provider.is_some(), "ATS provider should be findable");
    assert_eq!(ats_provider.unwrap().name(), "ats");
}

#[cfg(not(feature = "ats"))]
#[test]
fn test_ats_provider_unavailable() {
    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();
    
    // Without ATS feature, should not have ATS provider
    assert!(!provider_names.contains(&"ats"), "Should not have ATS provider without ats feature");
    
    let ats_provider = find_provider("ats");
    assert!(ats_provider.is_none(), "ATS provider should not be findable without ats feature");
}

#[test]
fn test_provider_descriptions_meaningful() {
    let providers = available_providers();
    
    for provider in &providers {
        let description = provider.description();
        
        // Descriptions should be meaningful
        assert!(description.len() > 10, "Provider description should be descriptive: {}", provider.name());
        assert!(description.contains("Sign") || description.contains("sign"), 
                "Provider description should mention signing: {}", provider.name());
        
        // Check specific expected descriptions
        match provider.name() {
            "der" => assert!(description.contains("DER") && description.contains("PKCS#8"), 
                            "DER provider should mention DER and PKCS#8"),
            "pfx" => assert!(description.contains("PFX") || description.contains("PKCS#12"), 
                            "PFX provider should mention PFX or PKCS#12"),
            "pem" => assert!(description.contains("PEM"), 
                            "PEM provider should mention PEM"),
            "ephemeral" => assert!(description.contains("ephemeral") && description.contains("testing"), 
                                  "Ephemeral provider should mention ephemeral and testing"),
            "akv-cert" => assert!(description.contains("Azure Key Vault") && description.contains("certificate"), 
                                 "AKV cert provider should mention Azure Key Vault and certificate"),
            "akv-key" => assert!(description.contains("Azure Key Vault") && description.contains("key"), 
                                "AKV key provider should mention Azure Key Vault and key"),
            "ats" => assert!(description.contains("Azure Trusted Signing"), 
                            "ATS provider should mention Azure Trusted Signing"),
            _ => {} // Unknown provider, skip specific checks
        }
    }
}

#[test]
fn test_provider_registry_consistency() {
    // Test that available_providers() and find_provider() are consistent
    let providers = available_providers();
    
    for provider in &providers {
        let name = provider.name();
        
        // Each provider from available_providers should be findable by name
        let found_provider = find_provider(name);
        assert!(found_provider.is_some(), "Provider '{}' from available_providers should be findable", name);
        
        let found = found_provider.unwrap();
        assert_eq!(found.name(), name, "Found provider should have same name");
        assert_eq!(found.description(), provider.description(), "Found provider should have same description");
    }
}

#[test]
fn test_provider_count_expectations() {
    let providers = available_providers();
    let count = providers.len();
    
    // With just crypto-openssl, should have at least 3 providers (der, pfx, pem)
    assert!(count >= 3, "Should have at least 3 providers with crypto-openssl feature");
    
    // Should not have an unreasonably large number of providers
    assert!(count <= 20, "Should not have more than 20 providers (sanity check)");
    
    // Count expectations based on features
    let mut expected_min = 3; // der, pfx, pem
    
    #[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
    {
        expected_min += 1; // ephemeral
    }
    
    #[cfg(feature = "akv")]
    {
        expected_min += 2; // akv-cert, akv-key
    }
    
    #[cfg(feature = "ats")]
    {
        expected_min += 1; // ats
    }
    
    assert!(count >= expected_min, 
           "Should have at least {} providers based on enabled features, got {}", 
           expected_min, count);
}

#[test]
fn test_provider_name_format() {
    let providers = available_providers();
    
    for provider in &providers {
        let name = provider.name();
        
        // Names should follow kebab-case convention
        assert!(!name.is_empty(), "Provider name should not be empty");
        assert!(!name.starts_with('-'), "Provider name should not start with hyphen");
        assert!(!name.ends_with('-'), "Provider name should not end with hyphen");
        assert!(!name.contains("--"), "Provider name should not have consecutive hyphens");
        
        // Should be ASCII lowercase with hyphens only
        for ch in name.chars() {
            assert!(ch.is_ascii_lowercase() || ch == '-', 
                   "Provider name should be lowercase ASCII with hyphens only: '{}'", name);
        }
        
        // Should not be too long or too short
        assert!(name.len() >= 2, "Provider name should be at least 2 characters");
        assert!(name.len() <= 20, "Provider name should not exceed 20 characters");
    }
}

#[test]
fn test_find_provider_multiple_calls() {
    // Test that find_provider() returns consistent results across multiple calls
    let provider_names = ["der", "pfx", "pem"];
    
    for name in &provider_names {
        let first_result = find_provider(name);
        let second_result = find_provider(name);
        
        // Both calls should return the same result
        match (first_result, second_result) {
            (Some(first), Some(second)) => {
                assert_eq!(first.name(), second.name());
                assert_eq!(first.description(), second.description());
            }
            (None, None) => {
                // Consistent None result is also valid (if provider not available)
            }
            _ => panic!("find_provider('{}') returned inconsistent results", name)
        }
    }
}

#[test]
fn test_provider_registry_immutable() {
    // Test that provider registry doesn't change between calls
    let first_providers = available_providers();
    let second_providers = available_providers();
    
    assert_eq!(first_providers.len(), second_providers.len(), 
              "Provider count should be consistent between calls");
    
    let first_names: Vec<_> = first_providers.iter().map(|p| p.name()).collect();
    let second_names: Vec<_> = second_providers.iter().map(|p| p.name()).collect();
    
    // Names should be in the same order (assuming deterministic iteration)
    assert_eq!(first_names, second_names, "Provider names should be consistent between calls");
}