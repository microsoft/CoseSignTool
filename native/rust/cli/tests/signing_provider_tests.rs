// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signing provider implementations.

#[cfg(any(feature = "crypto-openssl", feature = "akv", feature = "ats"))]
use cose_sign1_cli::providers::SigningProvider;

#[cfg(feature = "crypto-openssl")]
use cose_sign1_cli::providers::signing::*;

#[cfg(feature = "crypto-openssl")]
#[test]
fn test_der_key_signing_provider() {
    let provider = DerKeySigningProvider;
    assert_eq!(provider.name(), "der");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("DER"));
    assert!(provider.description().contains("PKCS#8"));
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn test_pfx_signing_provider() {
    let provider = PfxSigningProvider;
    assert_eq!(provider.name(), "pfx");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("PFX") || provider.description().contains("PKCS#12"));
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn test_pem_signing_provider() {
    let provider = PemSigningProvider;
    assert_eq!(provider.name(), "pem");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("PEM"));
}

#[cfg(all(feature = "crypto-openssl", feature = "certificates"))]
#[test]
fn test_ephemeral_signing_provider() {
    let provider = EphemeralSigningProvider;
    assert_eq!(provider.name(), "ephemeral");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("ephemeral") || provider.description().contains("auto-generated"));
}

#[cfg(feature = "akv")]
#[test]
fn test_akv_cert_signing_provider() {
    let provider = AkvCertSigningProvider;
    assert_eq!(provider.name(), "akv-cert");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("Azure") && provider.description().contains("Key Vault"));
}

#[cfg(feature = "akv")]
#[test]
fn test_akv_key_signing_provider() {
    let provider = AkvKeySigningProvider;
    assert_eq!(provider.name(), "akv-key");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("Azure") && provider.description().contains("Key Vault"));
    assert!(provider.description().contains("kid"));
}

#[cfg(feature = "ats")]
#[test]
fn test_ats_signing_provider() {
    let provider = AtsSigningProvider;
    assert_eq!(provider.name(), "ats");
    assert!(!provider.description().is_empty());
    assert!(provider.description().contains("Azure") && provider.description().contains("Trusted Signing"));
}

#[cfg(any(feature = "crypto-openssl", feature = "akv", feature = "ats"))]
#[test]
fn test_all_providers_have_non_empty_names_and_descriptions() {
    let providers = cose_sign1_cli::providers::signing::available_providers();
    
    for provider in providers {
        assert!(!provider.name().is_empty(), "Provider name should not be empty");
        assert!(!provider.description().is_empty(), "Provider description should not be empty");
        
        // Names should be lowercase and contain no spaces (CLI-friendly)
        let name = provider.name();
        assert!(name.chars().all(|c| c.is_ascii_lowercase() || c == '-'), 
                "Provider name '{}' should be lowercase with hyphens only", name);
    }
}