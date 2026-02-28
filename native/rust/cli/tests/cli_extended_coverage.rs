// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for CLI sign/verify/inspect run() functions.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, verify, inspect};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Name, X509};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use std::fs;
use tempfile::TempDir;

// Helper to create temporary test files
fn setup_test_env() -> (TempDir, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let temp_dir = TempDir::new().unwrap();
    let payload_file = temp_dir.path().join("test_payload.txt");
    let signature_file = temp_dir.path().join("test_signature.cose");
    let key_file = temp_dir.path().join("test_key.der");
    
    // Write test payload
    fs::write(&payload_file, b"Hello, COSE Sign1 CLI test!").unwrap();
    
    // Create test key
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let key_der = pkey.private_key_to_der().unwrap();
    fs::write(&key_file, key_der).unwrap();
    
    (temp_dir, payload_file, signature_file, key_file)
}

#[test]
fn test_sign_command_with_der_provider() {
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
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should create signature file successfully
    assert_eq!(result, 0);
    assert!(signature_file.exists());
    
    let signature_bytes = fs::read(&signature_file).unwrap();
    assert!(!signature_bytes.is_empty());
}

#[test]
fn test_sign_command_with_detached_signature() {
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
        content_type: "application/json".to_string(),
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should create detached signature successfully
    assert_eq!(result, 0);
    assert!(signature_file.exists());
    
    let signature_bytes = fs::read(&signature_file).unwrap();
    assert!(!signature_bytes.is_empty());
}

#[test] 
fn test_sign_command_with_cwt_claims() {
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
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: Some("test-issuer".to_string()),
        cwt_subject: Some("test-subject".to_string()),
        output_format: "text".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should create signature with CWT claims
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test]
fn test_sign_command_with_invalid_key_file() {
    let (_temp_dir, payload_file, signature_file, _key_file) = setup_test_env();
    
    let args = sign::SignArgs {
        input: payload_file.clone(),
        output: signature_file.clone(),
        provider: "der".to_string(),
        key: Some("nonexistent_key.der".into()),
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
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should fail with non-zero exit code
    assert_ne!(result, 0);
}

#[test]
fn test_sign_command_with_invalid_payload_file() {
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
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should fail with non-zero exit code
    assert_ne!(result, 0);
}

#[test]
fn test_verify_command_basic() {
    // First create a signature
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // Create signature
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
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    let sign_result = sign::run(sign_args);
    assert_eq!(sign_result, 0);
    
    // Now verify it
    let verify_args = verify::VerifyArgs {
        input: signature_file.clone(),
        payload: None, // Embedded payload
        trust_root: vec![],
        allow_embedded: true,
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
fn test_verify_command_with_detached_payload() {
    // First create a detached signature
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // Create detached signature
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    let sign_result = sign::run(sign_args);
    assert_eq!(sign_result, 0);
    
    // Now verify with detached payload
    let verify_args = verify::VerifyArgs {
        input: signature_file.clone(),
        payload: Some(payload_file.clone()), // Detached payload
        trust_root: vec![],
        allow_embedded: true,
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
fn test_inspect_command_basic() {
    // First create a signature
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // Create signature
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
        mst_endpoint: None,
        add_mst_receipt: false,
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
fn test_inspect_command_with_json_output() {
    // First create a signature
    let (_temp_dir, payload_file, signature_file, key_file) = setup_test_env();
    
    // Create signature
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
        mst_endpoint: None,
        add_mst_receipt: false,
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
fn test_inspect_command_with_nonexistent_signature() {
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

#[test]
fn test_sign_command_with_indirect_format() {
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should create indirect signature successfully
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test]
fn test_sign_command_with_quiet_output() {
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
        ats_endpoint: None,
        ats_account: None,
        ats_profile: None,
        mst_endpoint: None,
        add_mst_receipt: false,
    };
    
    let result = sign::run(args);
    
    // Should create signature successfully
    assert_eq!(result, 0);
    assert!(signature_file.exists());
}

#[test]
fn test_verify_command_with_nonexistent_signature() {
    let verify_args = verify::VerifyArgs {
        input: "nonexistent_signature.cose".into(),
        payload: None,
        trust_root: vec![],
        allow_embedded: false,
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
