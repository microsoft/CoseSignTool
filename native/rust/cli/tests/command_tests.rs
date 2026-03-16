// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests for CLI commands.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, verify, inspect};
use std::fs;
use std::env;

// Helper to create a temporary directory for test files
fn create_temp_dir() -> std::path::PathBuf {
    let mut temp_dir = env::temp_dir();
    // Add a unique component to avoid conflicts
    temp_dir.push(format!("cosesigntool_test_{}_{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    
    // Create directory if it doesn't exist
    if !temp_dir.exists() {
        fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");
    }
    temp_dir
}

// Helper to generate a P-256 private key and write it as DER
fn create_test_key_der(path: &std::path::Path) {
    use openssl::pkey::PKey;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;

    // Generate P-256 key
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    
    // Write as PKCS#8 DER
    let der_bytes = pkey.private_key_to_der().unwrap();
    fs::write(path, der_bytes).unwrap();
}

// Helper to create a test payload file
fn create_test_payload(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).unwrap();
}

#[test]
fn test_sign_command_with_der_provider() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let output_path = temp_dir.join("test_output.cose");

    // Set up test files
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Hello, COSE_Sign1!");

    // Create SignArgs
    let args = sign::SignArgs {
        input: payload_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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

    // Run sign command
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Sign command should succeed");

    // Verify output file was created
    assert!(output_path.exists(), "Output file should be created");
    let cose_bytes = fs::read(&output_path).unwrap();
    assert!(!cose_bytes.is_empty(), "Output file should not be empty");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_detached() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let output_path = temp_dir.join("test_output_detached.cose");

    // Set up test files
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Detached payload test");

    // Create SignArgs for detached signature
    let args = sign::SignArgs {
        input: payload_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/json".to_string(),
        format: "direct".to_string(),
        detached: true, // This is the key difference
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

    // Run sign command
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Detached sign command should succeed");

    // Verify output file was created
    assert!(output_path.exists(), "Output file should be created");
    let cose_bytes = fs::read(&output_path).unwrap();
    assert!(!cose_bytes.is_empty(), "Output file should not be empty");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_with_cwt_claims() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let output_path = temp_dir.join("test_output_cwt.cose");

    // Set up test files
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"CWT claims test");

    // Create SignArgs with CWT claims
    let args = sign::SignArgs {
        input: payload_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/spdx+json".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: Some("test-issuer".to_string()),
        cwt_subject: Some("test-subject".to_string()),
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

    // Run sign command
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Sign command with CWT claims should succeed");

    // Verify output file was created
    assert!(output_path.exists(), "Output file should be created");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_missing_key() {
    let temp_dir = create_temp_dir();
    let payload_path = temp_dir.join("test_payload.txt");
    let output_path = temp_dir.join("test_output.cose");

    // Set up test files (but no key file)
    create_test_payload(&payload_path, b"Test payload");

    // Create SignArgs without key
    let args = sign::SignArgs {
        input: payload_path.clone(),
        output: output_path.clone(),
        provider: "der".to_string(),
        key: None, // Missing key
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

    // Run sign command - should fail
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Sign command should fail with missing key");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_invalid_provider() {
    let temp_dir = create_temp_dir();
    let payload_path = temp_dir.join("test_payload.txt");
    let output_path = temp_dir.join("test_output.cose");

    // Set up test files
    create_test_payload(&payload_path, b"Test payload");

    // Create SignArgs with invalid provider
    let args = sign::SignArgs {
        input: payload_path.clone(),
        output: output_path.clone(),
        provider: "nonexistent".to_string(), // Invalid provider
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
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    };

    // Run sign command - should fail
    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Sign command should fail with invalid provider");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_basic() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_message.cose");

    // First create a COSE message to inspect
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Inspect test payload");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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
        issuer: Some("test-issuer".to_string()),
        cwt_subject: Some("test-subject".to_string()),
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Now test inspect with text format
    let inspect_args = inspect::InspectArgs {
        input: cose_path.clone(),
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 0, "Inspect command should succeed");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_json_format() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_message.cose");

    // First create a COSE message to inspect
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"JSON inspect test");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test inspect with JSON format
    let inspect_args = inspect::InspectArgs {
        input: cose_path.clone(),
        output_format: "json".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: true,
        show_cwt: false,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 0, "Inspect command with JSON format should succeed");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_quiet_format() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_message.cose");

    // First create a COSE message to inspect
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Quiet inspect test");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test inspect with quiet format
    let inspect_args = inspect::InspectArgs {
        input: cose_path.clone(),
        output_format: "quiet".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 0, "Inspect command with quiet format should succeed");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_with_cwt_claims() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_message.cose");

    // First create a COSE message with CWT claims to inspect
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"CWT inspect test");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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
        issuer: Some("cwt-test-issuer".to_string()),
        cwt_subject: Some("cwt-test-subject".to_string()),
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test inspect with CWT claims enabled
    let inspect_args = inspect::InspectArgs {
        input: cose_path.clone(),
        output_format: "text".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: false,
        show_cwt: true, // Enable CWT claims inspection
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 0, "Inspect command with CWT claims should succeed");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_invalid_input_file() {
    let temp_dir = create_temp_dir();
    let invalid_path = temp_dir.join("nonexistent.cose");

    // Test inspect with non-existent file
    let inspect_args = inspect::InspectArgs {
        input: invalid_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 2, "Inspect command should fail with non-existent file");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(feature = "certificates")]
#[test]
fn test_verify_command_no_trust_root() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_message.cose");

    // First create a COSE message to verify
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Verify test payload");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test verify without trust roots (should fail)
    let verify_args = verify::VerifyArgs {
        input: cose_path.clone(),
        payload: None,
        trust_root: vec![], // No trust roots
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

    let exit_code = verify::run(verify_args);
    assert_eq!(exit_code, 1, "Verify command should fail without trust roots");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(feature = "certificates")]
#[test]
fn test_verify_command_with_detached_payload() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("test_key.der");
    let payload_path = temp_dir.join("test_payload.txt");
    let cose_path = temp_dir.join("test_detached.cose");

    // First create a detached COSE message
    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Detached verify test");

    let sign_args = sign::SignArgs {
        input: payload_path.clone(),
        output: cose_path.clone(),
        provider: "der".to_string(),
        key: Some(key_path),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: true, // Create detached signature
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

    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test verify with detached payload
    let verify_args = verify::VerifyArgs {
        input: cose_path.clone(),
        payload: Some(payload_path), // Provide detached payload
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
        output_format: "json".to_string(),
    };

    let exit_code = verify::run(verify_args);
    assert_eq!(exit_code, 1, "Verify command should fail (no trust roots, but detached payload parsing should work)");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[cfg(feature = "certificates")]
#[test]
fn test_verify_command_invalid_cose_bytes() {
    let temp_dir = create_temp_dir();
    let invalid_cose_path = temp_dir.join("invalid.cose");

    // Create a file with invalid COSE content
    fs::write(&invalid_cose_path, b"This is not COSE data").unwrap();

    // Test verify with invalid COSE bytes
    let verify_args = verify::VerifyArgs {
        input: invalid_cose_path,
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

    let exit_code = verify::run(verify_args);
    assert_eq!(exit_code, 2, "Verify command should fail with invalid COSE bytes");

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_signing_providers_available() {
    use cose_sign1_cli::providers::signing::{available_providers, find_provider};

    // Test that we have providers available
    let providers = available_providers();
    assert!(!providers.is_empty(), "Should have at least one signing provider available");

    // Test find_provider function
    let der_provider = find_provider("der");
    assert!(der_provider.is_some(), "DER provider should be available with crypto-openssl feature");

    let nonexistent_provider = find_provider("nonexistent");
    assert!(nonexistent_provider.is_none(), "Non-existent provider should return None");
}

#[cfg(feature = "crypto-openssl")]
#[test]
fn test_signing_providers_der_pfx_pem() {
    use cose_sign1_cli::providers::signing::{available_providers, find_provider};

    let providers = available_providers();
    let provider_names: Vec<_> = providers.iter().map(|p| p.name()).collect();

    // With crypto-openssl feature, we should have these providers
    assert!(provider_names.contains(&"der"), "Should have DER provider");
    assert!(provider_names.contains(&"pfx"), "Should have PFX provider");
    assert!(provider_names.contains(&"pem"), "Should have PEM provider");

    // Test individual lookups
    assert!(find_provider("der").is_some());
    assert!(find_provider("pfx").is_some());
    assert!(find_provider("pem").is_some());
}
