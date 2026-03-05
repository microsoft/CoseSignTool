// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error path coverage tests for CLI commands.
//! Focuses on error conditions that don't require actual crypto operations.

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
fn test_sign_missing_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_input = temp_dir.path().join("nonexistent.txt");
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: nonexistent_input,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("dummy.key")),
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing input file");
}

#[test]
fn test_sign_invalid_provider() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "invalid_provider_name".to_string(),
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with invalid provider");
}

#[test]
fn test_sign_empty_payload() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b""); // Empty payload
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("nonexistent.key")), // Missing key will fail first
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key");
}

#[test]
fn test_verify_missing_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_input = temp_dir.path().join("nonexistent.cose");
    
    let args = verify::VerifyArgs {
        input: nonexistent_input,
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
    assert_eq!(exit_code, 2, "Should fail with missing input file");
}

#[test]
fn test_verify_invalid_cose_data() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"not a valid COSE message");
    
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
    assert_eq!(exit_code, 2, "Should fail parsing invalid COSE data");
}

// NOTE: test_verify_missing_detached_payload removed because verify::run() calls
// std::process::exit(2) for missing payloads, which terminates the test process.

#[cfg(feature = "mst")]
#[test]
fn test_verify_invalid_mst_offline_keys_file() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"dummy COSE data");
    let temp_dir = TempDir::new().unwrap();
    let invalid_keys_file = temp_dir.path().join("nonexistent_keys.json");
    
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
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        mst_offline_keys: Some(invalid_keys_file),
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    };
    
    let exit_code = verify::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing MST offline keys file");
}

#[test]
fn test_inspect_missing_input_file() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent_input = temp_dir.path().join("nonexistent.cose");
    
    let args = inspect::InspectArgs {
        input: nonexistent_input,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing input file");
}

#[test]
fn test_inspect_invalid_cose_data() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"not a valid COSE message");
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing invalid COSE data");
}

#[test]
fn test_inspect_json_format() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE but test format selection");
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, but after json format selection");
}

#[test]
fn test_inspect_quiet_format() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE but test format selection");
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "quiet".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, but after quiet format selection");
}

#[test]
fn test_inspect_all_flags_enabled() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE but test all flags");
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: true,
        show_certs: true,
        show_signature: true,
        show_cwt: true,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 2, "Should fail parsing, but after flag processing");
}