// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider and output formatting coverage tests for CLI.
//! Tests provider discovery, configuration, and various output scenarios.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, verify, inspect};
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

fn create_temp_file_with_content(content: &[u8]) -> (TempDir, PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test_file");
    fs::write(&file_path, content).unwrap();
    (temp_dir, file_path)
}

#[test]
fn test_sign_different_output_formats() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    // Test quiet output format
    let args = sign::SignArgs {
        input: input_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before output
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "quiet".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after quiet format selection");
    
    // Test json output format
    let args = sign::SignArgs {
        input: input_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before output
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "json".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after json format selection");
}

#[test]
fn test_sign_different_content_types() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before output
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/json".to_string(), // Different content type
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
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after content-type processing");
}

#[test]
fn test_sign_indirect_format() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "indirect".to_string(), // Test indirect format
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after format selection");
}

#[test]
fn test_sign_with_cwt_claims() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: Some("test-issuer".to_string()), // Test CWT claims
        cwt_subject: Some("test-subject".to_string()),
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after CWT claims processing");
}

#[test]
fn test_sign_only_issuer_cwt_claim() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: Some("test-issuer".to_string()), // Only issuer, no subject
        cwt_subject: None,
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after issuer-only CWT processing");
}

#[test]
fn test_sign_only_subject_cwt_claim() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: Some("test-subject".to_string()), // Only subject, no issuer
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after subject-only CWT processing");
}

#[cfg(feature = "mst")]
#[test]
fn test_sign_with_mst_receipt() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
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
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: true, // Test MST transparency
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after MST flag processing");
}

#[cfg(feature = "mst")]
#[test]
fn test_sign_with_custom_mst_endpoint() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Will fail before signing
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
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
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: true, // Test MST transparency
        mst_endpoint: Some("https://custom.mst.endpoint.com".to_string()),
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key, after custom MST endpoint processing");
}

#[test]
fn test_verify_with_content_type_requirements() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: true, // Test content-type requirement
        content_type: Some("application/json".to_string()),
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
    assert_eq!(exit_code, 2, "Should fail parsing, after content-type requirement processing");
}

#[test]
fn test_verify_with_cwt_requirements() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: true, // Test CWT requirement
        require_issuer: Some("expected-issuer".to_string()),
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
    assert_eq!(exit_code, 2, "Should fail parsing, after CWT requirements processing");
}

#[test]
fn test_verify_with_thumbprint_allowlist() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec!["abcd1234".to_string(), "efgh5678".to_string()], // Test thumbprint allowlist
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
    assert_eq!(exit_code, 2, "Should fail parsing, after thumbprint processing");
}

#[cfg(feature = "akv")]
#[test]
fn test_verify_with_akv_vault_patterns() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        require_akv_kid: true,
        akv_allowed_vault: vec!["https://vault1.vault.azure.net".to_string()], // Test AKV patterns
        #[cfg(feature = "mst")]
        mst_offline_keys: None,
        #[cfg(feature = "mst")]
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, after AKV vault processing");
}

#[cfg(feature = "mst")]
#[test]
fn test_verify_with_mst_ledger_instances() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE data");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
            allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        require_mst_receipt: true, // Test MST requirement
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        mst_offline_keys: None,
        mst_ledger_instance: vec!["ledger1".to_string(), "ledger2".to_string()], // Test MST ledger instances
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, after MST ledger processing");
}
