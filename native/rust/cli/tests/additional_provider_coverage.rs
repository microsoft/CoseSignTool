// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for CLI provider traits and argument structures

use cose_sign1_cli::providers::{SigningProvider, SigningProviderArgs, VerificationProvider, VerificationProviderArgs};

#[test]
fn test_signing_provider_args_default() {
    let args = SigningProviderArgs::default();
    
    // Verify all fields are None/default
    assert!(args.key_path.is_none());
    assert!(args.pfx_path.is_none());
    assert!(args.pfx_password.is_none());
    assert!(args.cert_file.is_none());
    assert!(args.key_file.is_none());
    assert!(args.thumbprint.is_none());
    assert!(args.store_location.is_none());
    assert!(args.store_name.is_none());
    assert!(args.subject.is_none());
    assert!(args.algorithm.is_none());
    assert!(args.key_size.is_none());
    assert!(args.validity_days.is_none());
    assert!(!args.minimal);
    assert!(!args.pqc);
    assert!(args.vault_url.is_none());
    assert!(args.cert_name.is_none());
    assert!(args.cert_version.is_none());
    assert!(args.key_name.is_none());
    assert!(args.key_version.is_none());
    assert!(args.aas_endpoint.is_none());
    assert!(args.aas_account.is_none());
    assert!(args.aas_profile.is_none());
}

#[test]
fn test_signing_provider_args_debug() {
    let args = SigningProviderArgs::default();
    let debug_str = format!("{:?}", args);
    
    // Verify debug output contains field names
    assert!(debug_str.contains("SigningProviderArgs"));
    assert!(debug_str.contains("key_path"));
    assert!(debug_str.contains("pfx_path"));
    assert!(debug_str.contains("cert_file"));
    assert!(debug_str.contains("thumbprint"));
    assert!(debug_str.contains("vault_url"));
    assert!(debug_str.contains("aas_endpoint"));
}

#[test]
fn test_signing_provider_args_cert_store_fields() {
    let mut args = SigningProviderArgs::default();
    
    // Test certificate store provider fields
    args.thumbprint = Some("ABC123DEF456".to_string());
    args.store_location = Some("CurrentUser".to_string());
    args.store_name = Some("My".to_string());
    
    assert_eq!(args.thumbprint, Some("ABC123DEF456".to_string()));
    assert_eq!(args.store_location, Some("CurrentUser".to_string()));
    assert_eq!(args.store_name, Some("My".to_string()));
}

#[test]
fn test_signing_provider_args_ephemeral_fields() {
    let mut args = SigningProviderArgs::default();
    
    // Test ephemeral provider fields
    args.subject = Some("CN=Test Certificate".to_string());
    args.algorithm = Some("ECDSA".to_string());
    args.key_size = Some(256);
    args.validity_days = Some(365);
    args.minimal = true;
    args.pqc = true;
    
    assert_eq!(args.subject, Some("CN=Test Certificate".to_string()));
    assert_eq!(args.algorithm, Some("ECDSA".to_string()));
    assert_eq!(args.key_size, Some(256));
    assert_eq!(args.validity_days, Some(365));
    assert!(args.minimal);
    assert!(args.pqc);
}

#[test]
fn test_signing_provider_args_akv_fields() {
    let mut args = SigningProviderArgs::default();
    
    // Test Azure Key Vault provider fields
    args.vault_url = Some("https://test-vault.vault.azure.net/".to_string());
    args.cert_name = Some("test-cert".to_string());
    args.cert_version = Some("v1.0".to_string());
    args.key_name = Some("test-key".to_string());
    args.key_version = Some("v2.0".to_string());
    
    assert_eq!(args.vault_url, Some("https://test-vault.vault.azure.net/".to_string()));
    assert_eq!(args.cert_name, Some("test-cert".to_string()));
    assert_eq!(args.cert_version, Some("v1.0".to_string()));
    assert_eq!(args.key_name, Some("test-key".to_string()));
    assert_eq!(args.key_version, Some("v2.0".to_string()));
}

#[test]
fn test_signing_provider_args_ats_fields() {
    let mut args = SigningProviderArgs::default();
    
    // Test Azure Artifact Signing provider fields
    args.aas_endpoint = Some("https://test.codesigning.azure.net".to_string());
    args.aas_account = Some("test-account".to_string());
    args.aas_profile = Some("test-profile".to_string());
    
    assert_eq!(args.aas_endpoint, Some("https://test.codesigning.azure.net".to_string()));
    assert_eq!(args.aas_account, Some("test-account".to_string()));
    assert_eq!(args.aas_profile, Some("test-profile".to_string()));
}

#[test]
fn test_signing_provider_args_pem_fields() {
    let mut args = SigningProviderArgs::default();
    
    // Test PEM provider fields
    args.cert_file = Some(std::path::PathBuf::from("/path/to/cert.pem"));
    args.key_file = Some(std::path::PathBuf::from("/path/to/key.pem"));
    
    assert_eq!(args.cert_file, Some(std::path::PathBuf::from("/path/to/cert.pem")));
    assert_eq!(args.key_file, Some(std::path::PathBuf::from("/path/to/key.pem")));
}

#[test]
fn test_verification_provider_args_default() {
    let args = VerificationProviderArgs::default();
    
    // Verify all fields are default
    assert!(!args.allow_embedded);
    assert!(args.trust_roots.is_empty());
    assert!(args.allowed_thumbprints.is_empty());
    assert!(!args.require_mst_receipt);
    assert!(args.akv_kid_patterns.is_empty());
    assert!(args.mst_offline_jwks.is_none());
    assert!(args.mst_ledger_instances.is_empty());
}

#[test]
fn test_verification_provider_args_debug() {
    let args = VerificationProviderArgs::default();
    let debug_str = format!("{:?}", args);
    
    // Verify debug output contains field names
    assert!(debug_str.contains("VerificationProviderArgs"));
    assert!(debug_str.contains("allow_embedded"));
    assert!(debug_str.contains("trust_roots"));
    assert!(debug_str.contains("allowed_thumbprints"));
    assert!(debug_str.contains("require_mst_receipt"));
    assert!(debug_str.contains("akv_kid_patterns"));
    assert!(debug_str.contains("mst_ledger_instances"));
}

#[test]
fn test_verification_provider_args_trust_roots() {
    let mut args = VerificationProviderArgs::default();
    
    // Test trust roots field
    args.trust_roots.push(std::path::PathBuf::from("/path/to/root1.pem"));
    args.trust_roots.push(std::path::PathBuf::from("/path/to/root2.pem"));
    
    assert_eq!(args.trust_roots.len(), 2);
    assert_eq!(args.trust_roots[0], std::path::PathBuf::from("/path/to/root1.pem"));
    assert_eq!(args.trust_roots[1], std::path::PathBuf::from("/path/to/root2.pem"));
}

#[test]
fn test_verification_provider_args_allowed_thumbprints() {
    let mut args = VerificationProviderArgs::default();
    
    // Test allowed thumbprints field
    args.allowed_thumbprints.push("ABC123".to_string());
    args.allowed_thumbprints.push("DEF456".to_string());
    
    assert_eq!(args.allowed_thumbprints.len(), 2);
    assert_eq!(args.allowed_thumbprints[0], "ABC123");
    assert_eq!(args.allowed_thumbprints[1], "DEF456");
}

#[test]
fn test_verification_provider_args_mst_fields() {
    let mut args = VerificationProviderArgs::default();
    
    // Test MST-related fields
    args.require_mst_receipt = true;
    args.mst_offline_jwks = Some("{}".to_string());
    args.mst_ledger_instances.push("instance1".to_string());
    args.mst_ledger_instances.push("instance2".to_string());
    
    assert!(args.require_mst_receipt);
    assert_eq!(args.mst_offline_jwks, Some("{}".to_string()));
    assert_eq!(args.mst_ledger_instances.len(), 2);
    assert_eq!(args.mst_ledger_instances[0], "instance1");
    assert_eq!(args.mst_ledger_instances[1], "instance2");
}

#[test]
fn test_verification_provider_args_akv_fields() {
    let mut args = VerificationProviderArgs::default();
    
    // Test AKV KID patterns field
    args.akv_kid_patterns.push("pattern1".to_string());
    args.akv_kid_patterns.push("pattern2".to_string());
    
    assert_eq!(args.akv_kid_patterns.len(), 2);
    assert_eq!(args.akv_kid_patterns[0], "pattern1");
    assert_eq!(args.akv_kid_patterns[1], "pattern2");
}

#[test]
fn test_verification_provider_args_allow_embedded() {
    let mut args = VerificationProviderArgs::default();
    
    // Test allow_embedded flag
    assert!(!args.allow_embedded);
    
    args.allow_embedded = true;
    assert!(args.allow_embedded);
}

// Mock implementations to test the trait methods that are currently unused
struct MockSigningProvider;

impl SigningProvider for MockSigningProvider {
    fn name(&self) -> &str {
        "mock"
    }
    
    fn description(&self) -> &str {
        "Mock signing provider for testing"
    }
    
    fn create_signer(&self, _args: &SigningProviderArgs) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error> {
        Err(anyhow::anyhow!("Mock provider not implemented"))
    }
}

struct MockVerificationProvider;

impl VerificationProvider for MockVerificationProvider {
    fn name(&self) -> &str {
        "mock"
    }
    
    fn description(&self) -> &str {
        "Mock verification provider for testing"
    }
    
    fn create_trust_pack(
        &self,
        _args: &VerificationProviderArgs,
    ) -> Result<std::sync::Arc<dyn cose_sign1_validation::fluent::CoseSign1TrustPack>, anyhow::Error> {
        Err(anyhow::anyhow!("Mock provider not implemented"))
    }
}

#[test]
fn test_signing_provider_description_method() {
    let provider = MockSigningProvider;
    assert_eq!(provider.description(), "Mock signing provider for testing");
}

#[test]
fn test_verification_provider_description_method() {
    let provider = MockVerificationProvider;
    assert_eq!(provider.description(), "Mock verification provider for testing");
}

#[test]
fn test_provider_names() {
    let signing_provider = MockSigningProvider;
    let verification_provider = MockVerificationProvider;
    
    assert_eq!(signing_provider.name(), "mock");
    assert_eq!(verification_provider.name(), "mock");
}
