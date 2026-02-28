// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for verification provider implementations.

#[cfg(any(feature = "certificates", feature = "akv", feature = "mst"))]
use cose_sign1_cli::providers::VerificationProvider;

#[cfg(feature = "certificates")]
use cose_sign1_cli::providers::verification::CertificateVerificationProvider;

#[cfg(feature = "akv")]
use cose_sign1_cli::providers::verification::AkvVerificationProvider;

#[cfg(feature = "mst")]
use cose_sign1_cli::providers::verification::MstVerificationProvider;

#[cfg(feature = "certificates")]
#[test]
fn test_certificate_verification_provider() {
    let provider = CertificateVerificationProvider;
    assert_eq!(provider.name(), "certificates");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("X.509") || provider.description().contains("certificate"));
}

#[cfg(feature = "akv")]
#[test]
fn test_akv_verification_provider() {
    let provider = AkvVerificationProvider;
    assert_eq!(provider.name(), "akv");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("Azure") && provider.description().contains("Key Vault"));
    assert!(provider.description().contains("KID") || provider.description().contains("kid"));
}

#[cfg(feature = "mst")]
#[test]
fn test_mst_verification_provider() {
    let provider = MstVerificationProvider;
    assert_eq!(provider.name(), "mst");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("Microsoft") && provider.description().contains("Transparency"));
    assert!(provider.description().contains("receipt"));
}

#[cfg(any(feature = "certificates", feature = "akv", feature = "mst"))]
#[test]
fn test_all_verification_providers_have_non_empty_names_and_descriptions() {
    let providers = cose_sign1_cli::providers::verification::available_providers();
    
    for provider in providers {
        assert!(!provider.name().is_empty(), "Provider name should not be empty");
        assert!(!provider.description().is_empty(), "Provider description should not be empty");
        
        // Names should be lowercase and contain no spaces (CLI-friendly)
        let name = provider.name();
        assert!(name.chars().all(|c| c.is_ascii_lowercase() || c == '-'), 
                "Provider name '{}' should be lowercase with hyphens only", name);
    }
}

#[cfg(any(feature = "certificates", feature = "mst"))]
#[test]
fn test_verification_provider_names_match_expected_set() {
    let providers = cose_sign1_cli::providers::verification::available_providers();
    let provider_names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    
    // Check that only expected names are present
    for name in &provider_names {
        assert!(
            matches!(*name, "certificates" | "akv" | "mst"),
            "Unexpected verification provider name: {}",
            name
        );
    }
    
    // With default features (certificates, mst), we should have at least these
    #[cfg(feature = "certificates")]
    assert!(provider_names.contains(&"certificates"));
    
    #[cfg(feature = "mst")]
    assert!(provider_names.contains(&"mst"));
}