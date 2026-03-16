// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional test coverage for CLI sign/verify/inspect run() functions.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, verify, inspect};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use std::fs;
use tempfile::TempDir;

// Helper to create temporary test files
fn setup_test_env() -> (TempDir, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let payload_file = temp_dir.path().join("test_payload.txt");
    let signature_file = temp_dir.path().join("test_signature.cose");
    let key_file = temp_dir.path().join("test_key.der");

    // Create test payload
    fs::write(&payload_file, b"Hello, COSE!").unwrap();
    
    // Create test key
    let key_der = generate_test_key_der();
    fs::write(&key_file, &key_der).unwrap();
    
    (temp_dir, payload_file, signature_file, key_file)
}

// Generate a P-256 test key
fn generate_test_key_der() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    pkey.private_key_to_der().unwrap()
}

#[test]
fn test_sign_command_basic() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    let args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
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
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = sign::run(args);
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test] 
fn test_sign_command_detached() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    let args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: true,
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
    
    let result = sign::run(args);
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test]
fn test_sign_command_indirect() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    let args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "indirect".to_string(),
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
    
    let result = sign::run(args);
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test]
fn test_sign_command_invalid_file() {
    let (_temp_dir, _payload_file, signature_file, key_file) = setup_test_env();
    
    let args = sign::SignArgs {
        input: "nonexistent_payload.txt".into(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
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
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let result = sign::run(args);
    assert_ne!(result, 0); // Should fail for nonexistent file
}

#[test]
fn test_verify_command_basic() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // First sign
    let sign_args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
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
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let sign_result = sign::run(sign_args);
    assert_eq!(sign_result, 0);
    
    // Now verify it
    let verify_args = verify::VerifyArgs {
        input: signature_file.clone(),
        payload: None, // Embedded payload
        trust_root: vec![],
        allow_embedded: true,
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
    
    let result = verify::run(verify_args);
    
    // Should fail verification because no trust root was provided and DER keys don't embed certs
    assert_eq!(result, 1);
}

#[test]
fn test_verify_command_nonexistent_signature() {
    let verify_args = verify::VerifyArgs {
        input: "nonexistent_signature.cose".into(),
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
    
    let result = verify::run(verify_args);
    
    // Should fail with non-zero exit code
    assert_ne!(result, 0);
}

#[test]
fn test_inspect_command_basic() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // First sign
    let sign_args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
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
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let sign_result = sign::run(sign_args);
    assert_eq!(sign_result, 0);
    
    // Now inspect it
    let inspect_args = inspect::InspectArgs {
        input: signature_file.clone(),
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let result = inspect::run(inspect_args);
    
    // Should inspect successfully
    assert_eq!(result, 0);
}

#[test]
fn test_inspect_command_json_output() {
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // First sign
    let sign_args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some(key_file.clone()),
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
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let sign_result = sign::run(sign_args);
    assert_eq!(sign_result, 0);
    
    // Now inspect with JSON output
    let inspect_args = inspect::InspectArgs {
        input: signature_file.clone(),
        output_format: "json".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let result = inspect::run(inspect_args);
    
    // Should inspect successfully
    assert_eq!(result, 0);
}

#[test]
fn test_inspect_command_nonexistent_signature() {
    let inspect_args = inspect::InspectArgs {
        input: "nonexistent_signature.cose".into(),
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let result = inspect::run(inspect_args);
    
    // Should fail with non-zero exit code
    assert_ne!(result, 0);
}
