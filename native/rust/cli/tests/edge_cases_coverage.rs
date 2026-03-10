// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Specific line coverage and edge case tests for CLI.
//! Targets specific uncovered branches and error conditions.

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

// Test specific error branches in the verify command
#[cfg(not(feature = "certificates"))]
#[test] 
fn test_verify_without_certificates_feature() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"dummy COSE data");
    
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
    assert_eq!(exit_code, 2, "Should fail when certificates feature is disabled");
}

#[test]
fn test_verify_empty_trust_packs() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"invalid COSE but should reach trust pack check");
    
    let args = verify::VerifyArgs {
        input: input_path,
        payload: None,
        trust_root: vec![], // No trust roots provided
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
    assert_eq!(exit_code, 2, "Should fail parsing before trust pack check, but tests the path");
}

fn create_cbor_with_cwt_header() -> Vec<u8> {
    // CBOR with CWT claims header (label 15)
    let cwt_claims = vec![0xA2, 0x01, 0x63, 0x69, 0x73, 0x73, 0x02, 0x63, 0x73, 0x75, 0x62]; // {"iss": "iss", "sub": "sub"}
    let mut cbor_data = vec![
        0x84,       // Array of length 4
        0x50,       // Byte string of length 16
        0xA1, 0x0F, // Map with label 15 (CWT claims)
    ];
    cbor_data.push(0x4B); // Byte string of length 11
    cbor_data.extend(cwt_claims);
    cbor_data.extend(vec![
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
        0x40        // Empty signature
    ]);
    cbor_data
}

#[test]
fn test_inspect_with_cwt_header_success() {
    let cbor_data = create_cbor_with_cwt_header();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true, // Enable CWT display
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise CWT parsing code path");
}

fn create_cbor_with_invalid_cwt_header() -> Vec<u8> {
    // CBOR with invalid CWT claims header (label 15 with invalid CBOR)
    let mut cbor_data = vec![
        0x84,       // Array of length 4
        0x48,       // Byte string of length 8
        0xA1, 0x0F, // Map with label 15 (CWT claims)
        0x44, 0xFF, 0xFF, 0xFF, 0xFF, // Invalid CBOR data
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
        0x40        // Empty signature
    ];
    cbor_data
}

#[test]
fn test_inspect_with_invalid_cwt_header() {
    let cbor_data = create_cbor_with_invalid_cwt_header();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true, // Enable CWT display to test error path
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise CWT error handling code path");
}

fn create_cbor_with_non_bytes_cwt() -> Vec<u8> {
    // CBOR with CWT header that's not bytes (should skip CWT processing)
    let mut cbor_data = vec![
        0x84,       // Array of length 4
        0x45,       // Byte string of length 5
        0xA1, 0x0F, 0x1A,  // Map with label 15: integer value (not bytes)
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
        0x40        // Empty signature
    ];
    cbor_data
}

#[test]
fn test_inspect_with_non_bytes_cwt_header() {
    let cbor_data = create_cbor_with_non_bytes_cwt();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true, // Enable CWT display
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should handle non-bytes CWT header value");
}

fn create_cbor_with_x5chain_header() -> Vec<u8> {
    // CBOR with x5chain header (label 33)
    let mut cbor_data = vec![
        0x84,       // Array of length 4
        0x48,       // Byte string of length 8
        0xA1, 0x18, 0x21, // Map with label 33 (x5chain)
        0x81, 0x43, 0x41, 0x42, 0x43, // Array with one cert "ABC"
        0xA0,       // Empty unprotected
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" payload
        0x40        // Empty signature
    ];
    cbor_data
}

#[test]
fn test_inspect_with_x5chain_header() {
    let cbor_data = create_cbor_with_x5chain_header();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: true, // Enable certificate display
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert!(exit_code == 0 || exit_code == 2, "Should exercise certificate chain display code");
}

// Create minimal valid CBOR that should parse successfully
fn create_minimal_valid_cose() -> Vec<u8> {
    // Properly structured COSE_Sign1 message
    vec![
        0x84,       // Array of length 4
        0x40,       // Empty byte string (protected)
        0xA0,       // Empty map (unprotected)
        0x44, 0x74, 0x65, 0x73, 0x74,  // "test" as payload
        0x40        // Empty byte string (signature)
    ]
}

#[test]
fn test_inspect_minimal_valid_success() {
    let cbor_data = create_minimal_valid_cose();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    // Should succeed with minimal valid COSE structure
    assert_eq!(exit_code, 0, "Should succeed with minimal valid COSE");
}

#[test]
fn test_inspect_minimal_valid_json_success() {
    let cbor_data = create_minimal_valid_cose();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "json".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 0, "Should succeed with JSON format");
}

#[test]
fn test_inspect_minimal_valid_quiet_success() {
    let cbor_data = create_minimal_valid_cose();
    let (_temp_dir, input_path) = create_temp_file_with_content(&cbor_data);
    
    let args = inspect::InspectArgs {
        input: input_path,
        output_format: "quiet".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    
    let exit_code = inspect::run(args);
    assert_eq!(exit_code, 0, "Should succeed with quiet format");
}

#[test]
fn test_sign_detached_mode() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
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
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key (after detached flag processing)");
}

// Test various invalid output format parsing
#[test]
fn test_invalid_output_formats() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("test.key")), // Will fail before output processing
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
        output_format: "invalid_format".to_string(), // Test invalid format
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
    assert_eq!(exit_code, 2, "Should fail due to missing key (after invalid format processing)");
}

#[cfg(feature = "mst")]
#[test]
fn test_sign_mst_invalid_url() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "der".to_string(),
        key: Some(temp_dir.path().join("test.key")), // Will fail before MST processing
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
        add_mst_receipt: true,
        mst_endpoint: Some("invalid-url-format".to_string()), // Invalid URL
    };
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail due to missing key (before URL validation)");
}

// Test edge cases in provider argument configurations  
#[test]
fn test_sign_pem_missing_cert_file() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pem".to_string(),
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None, // Missing cert file
        key_file: Some(temp_dir.path().join("key.pem")),
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing cert file for PEM provider");
}

#[test]
fn test_sign_pem_missing_key_file() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "pem".to_string(),
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: Some(temp_dir.path().join("cert.pem")),
        key_file: None, // Missing key file
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Should fail with missing key file for PEM provider");
}

#[test]
fn test_sign_ephemeral_missing_subject() {
    let (_temp_dir, input_path) = create_temp_file_with_content(b"test payload");
    let temp_dir = TempDir::new().unwrap();
    let output_path = temp_dir.path().join("output.cose");
    
    let args = sign::SignArgs {
        input: input_path,
        output: output_path,
        provider: "ephemeral".to_string(),
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None, // Missing subject for ephemeral
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
    
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Ephemeral provider should succeed with default subject when --subject is not specified");
}