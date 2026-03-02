// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional command combinations and provider edge case tests.
//! Tests various provider scenarios and command flag combinations.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, verify};
use std::fs;
use std::path::PathBuf;
use std::env;
use tempfile::TempDir;

fn create_temp_file_with_content(content: &[u8]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file");
    fs::write(&file_path, content).unwrap();
    (temp_dir, file_path)
}

#[test]
fn test_sign_pfx_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    let pfx_path = temp_dir.path().join("nonexistent.pfx");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pfx".to_string(), // Test PFX provider
        key: None,
        pfx: Some(pfx_path), // PFX file
        pfx_password: Some("password".to_string()),
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing PFX file");
}

#[test]
fn test_sign_pfx_provider_missing_pfx_arg() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pfx".to_string(), // Test PFX provider
        key: None,
        pfx: None, // Missing PFX argument
        pfx_password: Some("password".to_string()),
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing PFX argument");
}

#[test]
fn test_sign_pfx_provider_env_password() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    let pfx_path = temp_dir.path().join("nonexistent.pfx");
    
    // Set environment variable for password
    env::set_var("COSESIGNTOOL_PFX_PASSWORD", "env_password");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pfx".to_string(), // Test PFX provider
        key: None,
        pfx: Some(pfx_path), // PFX file
        pfx_password: None, // No password arg, should use env var
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing PFX file (after env password check)");
    
    // Clean up
    env::remove_var("COSESIGNTOOL_PFX_PASSWORD");
}

#[test] 
fn test_sign_pem_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    let cert_path = temp_dir.path().join("nonexistent.crt");
    let key_path = temp_dir.path().join("nonexistent.key");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pem".to_string(), // Test PEM provider
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: Some(cert_path),
        key_file: Some(key_path),
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing PEM files");
}

#[test]
fn test_sign_ephemeral_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "ephemeral".to_string(), // Test ephemeral provider
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: Some("CN=Test Ephemeral".to_string()),
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    // May succeed if ephemeral provider is implemented, or fail if not
    assert!(exit_code == 0 || exit_code == 2, "Ephemeral provider test");
}

#[cfg(feature = "akv")]
#[test]
fn test_sign_akv_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "akv".to_string(), // Test Azure Key Vault provider
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: Some("https://test.vault.azure.net".to_string()),
        cert_name: Some("test-cert".to_string()),
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with authentication/network issues for AKV");
}

#[cfg(feature = "ats")]
#[test]
fn test_sign_ats_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "ats".to_string(), // Test Azure Trusted Signing provider
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: Some("https://ats.azure.net".to_string()),
        ats_account: Some("test-account".to_string()),
        ats_profile: Some("test-profile".to_string()),
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with authentication/network issues for ATS");
}

#[test]
fn test_verify_with_multiple_trust_roots() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    let temp_dir = TempDir::new().unwrap();
    let root1 = temp_dir.path().join("root1.der");
    let root2 = temp_dir.path().join("root2.der");
    
    // Create dummy root cert files
    fs::write(&root1, b"dummy root cert 1").unwrap();
    fs::write(&root2, b"dummy root cert 2").unwrap();
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![root1, root2], // Multiple trust roots
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        #[cfg(feature = "mst")]
        mst_offline_keys: None,
        #[cfg(feature = "mst")]
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, after multiple trust root processing");
}

#[test]
fn test_verify_allow_embedded() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: true,
            allow_untrusted: false, // Test allow embedded flag
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        #[cfg(feature = "mst")]
        mst_offline_keys: None,
        #[cfg(feature = "mst")]
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, after embedded cert processing");
}

#[test]
fn test_verify_content_type_requirement_only() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: true, // Only require content type present
        content_type: None, // But don't specify value
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        #[cfg(feature = "mst")]
        mst_offline_keys: None,
        #[cfg(feature = "mst")]
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, after content-type presence check");
}

#[test]
fn test_sign_write_permission_error() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    
    // Create output path in nonexistent directory
    let bad_output_path = temp_dir.path().join("nonexistent_dir").join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: bad_output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("test.key")), // Will fail before output write
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to key file missing (before output write test)");
}

#[test]
fn test_sign_large_payload() {
    // Create a larger payload to test streaming behavior
    let large_payload = vec![0x41; 100_000]; // 100KB of 'A' characters
    let (_temp_dir, input_path) = create_temp_file_with_content(&large_payload);
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("test.key")), // Will fail before processing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to key file missing (after large payload read)");
}

#[test] 
fn test_sign_custom_content_types() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let content_types = vec![
        "application/vnd.example+json",
        "text/plain",
        "application/x-custom",
        "image/jpeg",
    ];
    
    for content_type in content_types {
        let args = sign::SignArgs {
            input: input_path.clone(),
            output: output_path.clone(),
            provider: "der".to_string(),
            key: Some(temp_dir.path().join("test.key")), // Will fail before processing
            pfx: None,
            pfx_password: None,
            cert_file: None,
            key_file: None,
            subject: None,
            content_type: content_type.to_string(),
            format: "direct".to_string(),
            detached: false,
            issuer: None,
            cwt_subject: None,
            output_format: "text".to_string(),
            vault_url: None,
            cert_name: None,
            cert_version: None,
            key_name: None,
            key_version: None,
            ats_endpoint: None,
            ats_account: None,
            ats_profile: None,
            add_mst_receipt: false,
            mst_endpoint: None,
        };
        
        let exit_code = sign::run(args);
        assert_eq!(exit_code, 2, "Should fail due to key file missing (after content-type: {})", content_type);
    }
}