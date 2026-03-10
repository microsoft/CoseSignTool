// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive test coverage for CLI sign.rs command.
//! 
//! Targets remaining uncovered lines in sign.rs (30 uncov) with focus on:
//! - DER key signing
//! - Indirect signing format  
//! - Detached signature mode
//! - CWT claims handling
//! - MST transparency (stub)
//! - Output formatting

#![cfg(feature = "crypto-openssl")]
use std::fs;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};
use cose_sign1_cli::commands::sign::{run, SignArgs};
use openssl::pkey::{PKey, Private};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;

fn generate_test_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    PKey::from_ec_key(key).unwrap()
}

fn create_temp_file_with_content(content: &[u8]) -> NamedTempFile {
    let temp = NamedTempFile::new().unwrap();
    fs::write(temp.path(), content).unwrap();
    temp
}

fn create_test_der_key() -> Vec<u8> {
    let pkey = generate_test_key();
    pkey.private_key_to_der().unwrap()
}

#[test]
fn test_sign_unknown_provider() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path,
        provider: "unknown_provider".to_string(),
        key: None,
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Unknown provider error
}

#[test]
fn test_sign_input_file_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: PathBuf::from("nonexistent_file.bin"),
        output: output_path,
        provider: "der".to_string(),
        key: None,
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Error reading payload
}

#[test]
fn test_sign_der_provider_no_key() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path,
        provider: "der".to_string(),
        key: None, // No key provided
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Error creating signer
}

#[test]
fn test_sign_der_key_not_found() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path,
        provider: "der".to_string(),
        key: Some(PathBuf::from("nonexistent_key.der")),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Error creating signer
}

#[test]
fn test_sign_der_key_direct_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(), // Test direct format
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists()); // Verify output file created
}

#[test]
fn test_sign_der_key_indirect_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_detached_signature() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload for detached signature");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: true, // Test detached mode
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_with_cwt_claims() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/json".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: Some("https://example.com".to_string()), // Test CWT issuer
        cwt_subject: Some("test-subject".to_string()), // Test CWT subject
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success - tests CWT claims encoding path
    assert!(output_path.exists());
}

#[test]
fn test_sign_issuer_only() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        issuer: Some("https://test-issuer.com".to_string()), // Only issuer
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_cwt_subject_only() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        cwt_subject: Some("test-only-subject".to_string()), // Only subject
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[cfg(feature = "mst")]
#[test]
fn test_sign_with_mst_receipt() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: true, // Test MST transparency (stub)
        mst_endpoint: Some("https://test.mst.endpoint.net".to_string()),
    };
    
    let result = run(args);
    assert_eq!(result, 0); // Success (stub implementation)
    assert!(output_path.exists());
}

#[cfg(feature = "mst")]
#[test]
fn test_sign_mst_default_endpoint() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: true, // Test MST with default endpoint
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_json_output_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        output_format: "json".to_string(), // Test JSON output format
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_quiet_output_format() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    let output_path = temp_dir.path().join("output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        output_format: "quiet".to_string(), // Test quiet output format
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
    
    let result = run(args);
    assert_eq!(result, 0); // Success
    assert!(output_path.exists());
}

#[test]
fn test_sign_pfx_password_env_var() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let output_path = temp_dir.path().join("output.cose");
    
    // Set environment variable
    std::env::set_var("COSESIGNTOOL_PFX_PASSWORD", "test_password");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path,
        provider: "pfx".to_string(),
        key: None,
        pfx: Some(PathBuf::from("nonexistent.pfx")), // Will fail, but tests env var path
        pfx_password: None, // Should pick up from env var
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Will fail due to missing PFX file, but tests env var code path
    
    // Clean up
    std::env::remove_var("COSESIGNTOOL_PFX_PASSWORD");
}

#[test]
fn test_sign_write_output_error() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = create_temp_file_with_content(b"test payload");
    let key_der = create_test_der_key();
    let key_file = create_temp_file_with_content(&key_der);
    
    // Use invalid output path (directory that doesn't exist)
    let output_path = PathBuf::from("/nonexistent/directory/output.cose");
    
    let args = SignArgs {
        input: input_file.path().to_path_buf(),
        output: output_path,
        provider: "der".to_string(),
        key: Some(key_file.path().to_path_buf()),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = run(args);
    assert_eq!(result, 2); // Error writing output
}