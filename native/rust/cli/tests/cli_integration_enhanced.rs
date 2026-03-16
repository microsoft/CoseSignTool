// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enhanced CLI integration tests for comprehensive coverage.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::{sign, inspect};
use std::fs;
use std::env;
use openssl::{pkey::PKey, ec::{EcGroup, EcKey}, nid::Nid, pkcs12::Pkcs12, rsa::Rsa};

// Helper to create a temporary directory for test files
fn create_temp_dir() -> std::path::PathBuf {
    let mut temp_dir = env::temp_dir();
    temp_dir.push(format!("cosesigntool_enhanced_{}_{}", 
        std::process::id(), 
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    
    if !temp_dir.exists() {
        fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");
    }
    temp_dir
}

// Helper to generate a P-256 private key and write it as DER
fn create_test_key_der(path: &std::path::Path) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let der_bytes = pkey.private_key_to_der().unwrap();
    fs::write(path, der_bytes).unwrap();
}

// Helper to generate an RSA private key and write it as DER
fn create_rsa_key_der(path: &std::path::Path, bits: u32) {
    let rsa = Rsa::generate(bits).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let der_bytes = pkey.private_key_to_der().unwrap();
    fs::write(path, der_bytes).unwrap();
}

// Helper to create a PFX file for testing
fn create_test_pfx(path: &std::path::Path, password: &str) -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    
    // Create a self-signed certificate for the PFX
    let mut cert_builder = openssl::x509::X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    cert_builder.set_pubkey(&pkey).unwrap();
    
    let mut name = openssl::x509::X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Certificate").unwrap();
    let name = name.build();
    cert_builder.set_subject_name(&name).unwrap();
    cert_builder.set_issuer_name(&name).unwrap();
    
    // Set validity period
    let not_before = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let not_after = openssl::asn1::Asn1Time::days_from_now(365).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();
    
    cert_builder.sign(&pkey, openssl::hash::MessageDigest::sha256()).unwrap();
    let cert = cert_builder.build();
    
    // Create PKCS#12 structure
    let pkcs12 = Pkcs12::builder()
        .name("Test Certificate")
        .pkey(&pkey)
        .cert(&cert)
        .build2(password)
        .unwrap();
    
    let pfx_bytes = pkcs12.to_der().unwrap();
    fs::write(path, &pfx_bytes).unwrap();
    pfx_bytes
}

// Helper to create a test payload file
fn create_test_payload(path: &std::path::Path, content: &[u8]) {
    fs::write(path, content).unwrap();
}

// Helper to create default SignArgs
fn default_sign_args(
    input: std::path::PathBuf,
    output: std::path::PathBuf,
    provider: String,
) -> sign::SignArgs {
    sign::SignArgs {
        input,
        output,
        provider,
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
    }
}

#[test]
fn test_sign_command_rsa_key() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("rsa_key.der");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    // Create RSA-2048 key
    create_rsa_key_der(&key_path, 2048);
    create_test_payload(&payload_path, b"RSA signature test");

    let mut args = default_sign_args(payload_path, output_path.clone(), "der".to_string());
    args.key = Some(key_path);
    args.content_type = "application/json".to_string();

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "RSA sign command should succeed");
    assert!(output_path.exists(), "Output file should be created");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_pfx_provider() {
    let temp_dir = create_temp_dir();
    let pfx_path = temp_dir.join("test.pfx");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    let password = "test123";
    create_test_pfx(&pfx_path, password);
    create_test_payload(&payload_path, b"PFX signature test");

    let mut args = default_sign_args(payload_path, output_path.clone(), "pfx".to_string());
    args.pfx = Some(pfx_path);
    args.pfx_password = Some(password.to_string());
    args.content_type = "application/vnd.example+json".to_string();

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "PFX sign command should succeed");
    assert!(output_path.exists(), "Output file should be created");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_pfx_wrong_password() {
    let temp_dir = create_temp_dir();
    let pfx_path = temp_dir.join("test.pfx");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    create_test_pfx(&pfx_path, "correct123");
    create_test_payload(&payload_path, b"PFX wrong password test");

    let mut args = default_sign_args(payload_path, output_path.clone(), "pfx".to_string());
    args.pfx = Some(pfx_path);
    args.pfx_password = Some("wrong123".to_string());

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "PFX sign with wrong password should fail");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_indirect_format() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("key.der");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Indirect signature test");

    let mut args = default_sign_args(payload_path, output_path.clone(), "der".to_string());
    args.key = Some(key_path);
    args.format = "indirect".to_string();
    args.content_type = "application/spdx+json".to_string();

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Indirect sign command should succeed");
    assert!(output_path.exists(), "Output file should be created");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_all_cwt_claims() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("key.der");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"CWT claims test payload");

    let mut args = default_sign_args(payload_path, output_path.clone(), "der".to_string());
    args.key = Some(key_path);
    args.issuer = Some("urn:example:issuer".to_string());
    args.cwt_subject = Some("urn:example:subject".to_string());
    args.output_format = "json".to_string();

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "Sign with CWT claims should succeed");
    assert!(output_path.exists(), "Output file should be created");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_sign_command_invalid_input_file() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("key.der");
    let payload_path = temp_dir.join("nonexistent.txt");
    let output_path = temp_dir.join("output.cose");

    create_test_key_der(&key_path);

    let mut args = default_sign_args(payload_path, output_path, "der".to_string());
    args.key = Some(key_path);

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 2, "Sign with invalid input should fail");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_all_options() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("key.der");
    let payload_path = temp_dir.join("payload.txt");
    let cose_path = temp_dir.join("message.cose");

    create_test_key_der(&key_path);
    create_test_payload(&payload_path, b"Comprehensive inspect test");

    // First create a COSE message with CWT claims
    let mut sign_args = default_sign_args(payload_path, cose_path.clone(), "der".to_string());
    sign_args.key = Some(key_path);
    sign_args.issuer = Some("test-issuer".to_string());
    sign_args.cwt_subject = Some("test-subject".to_string());
    
    let sign_exit = sign::run(sign_args);
    assert_eq!(sign_exit, 0, "Sign step should succeed");

    // Test inspect with all options enabled
    let inspect_args = inspect::InspectArgs {
        input: cose_path,
        output_format: "text".to_string(),
        all_headers: true,
        show_certs: true,
        show_signature: true,
        show_cwt: true,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 0, "Inspect with all options should succeed");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_inspect_command_invalid_cose_bytes() {
    let temp_dir = create_temp_dir();
    let invalid_path = temp_dir.join("invalid.cose");

    // Write invalid COSE data
    fs::write(&invalid_path, b"not a valid COSE message").unwrap();

    let inspect_args = inspect::InspectArgs {
        input: invalid_path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };

    let exit_code = inspect::run(inspect_args);
    assert_eq!(exit_code, 2, "Inspect with invalid COSE should fail");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_providers_available_coverage() {
    use cose_sign1_cli::providers::signing::{available_providers, find_provider};

    let providers = available_providers();
    assert!(!providers.is_empty(), "Should have providers available");

    // Test each provider name and description
    for provider in &providers {
        let name = provider.name();
        let description = provider.description();
        
        assert!(!name.is_empty(), "Provider name should not be empty");
        assert!(!description.is_empty(), "Provider description should not be empty");
        
        // Test find_provider with each available provider
        let found = find_provider(name);
        assert!(found.is_some(), "Should find provider by name: {}", name);
        assert_eq!(found.unwrap().name(), name, "Found provider should match");
    }

    // Test nonexistent provider
    assert!(find_provider("definitely_not_a_real_provider").is_none());
}

#[test] 
fn test_output_format_parsing() {
    use cose_sign1_cli::providers::output::OutputFormat;
    
    assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!("quiet".parse::<OutputFormat>().unwrap(), OutputFormat::Quiet);
    
    // Case insensitive
    assert_eq!("TEXT".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!("QUIET".parse::<OutputFormat>().unwrap(), OutputFormat::Quiet);
    
    // Invalid format
    assert!("xml".parse::<OutputFormat>().is_err());
}

#[test]
fn test_output_rendering() {
    use cose_sign1_cli::providers::output::{OutputFormat, render};
    use std::collections::BTreeMap;
    
    let mut section = BTreeMap::new();
    section.insert("Key1".to_string(), "Value1".to_string());
    section.insert("Key2".to_string(), "Value2".to_string());
    
    let sections = vec![("Test Section".to_string(), section)];
    
    // Test text rendering
    let text_output = render(OutputFormat::Text, &sections);
    assert!(text_output.contains("Test Section"));
    assert!(text_output.contains("Key1: Value1"));
    assert!(text_output.contains("Key2: Value2"));
    
    // Test JSON rendering
    let json_output = render(OutputFormat::Json, &sections);
    assert!(json_output.contains("Test Section"));
    assert!(json_output.contains("Key1"));
    assert!(json_output.contains("Value1"));
    
    // Test quiet rendering
    let quiet_output = render(OutputFormat::Quiet, &sections);
    assert!(quiet_output.is_empty());
}

// Test with environment variable fallback for PFX password
#[test]
fn test_pfx_password_env_fallback() {
    let temp_dir = create_temp_dir();
    let pfx_path = temp_dir.join("test.pfx");
    let payload_path = temp_dir.join("payload.txt");
    let output_path = temp_dir.join("output.cose");

    let password = "env_test123";
    create_test_pfx(&pfx_path, password);
    create_test_payload(&payload_path, b"PFX env password test");

    // Set environment variable
    env::set_var("COSESIGNTOOL_PFX_PASSWORD", password);

    let mut args = default_sign_args(payload_path, output_path.clone(), "pfx".to_string());
    args.pfx = Some(pfx_path);
    // Don't set pfx_password - should use env var

    let exit_code = sign::run(args);
    assert_eq!(exit_code, 0, "PFX sign with env password should succeed");
    assert!(output_path.exists(), "Output file should be created");

    // Clean up environment
    env::remove_var("COSESIGNTOOL_PFX_PASSWORD");
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_content_type_variations() {
    let temp_dir = create_temp_dir();
    let key_path = temp_dir.join("key.der");
    create_test_key_der(&key_path);

    let test_cases = vec![
        ("application/octet-stream", "binary data".as_bytes(), "binary.cose"),
        ("application/json", "{\"test\": true}".as_bytes(), "json.cose"),
        ("application/spdx+json", "{\"spdxVersion\": \"2.3\"}".as_bytes(), "spdx.cose"),
        ("text/plain", "plain text content".as_bytes(), "text.cose"),
        ("application/vnd.example+custom", "custom content".as_bytes(), "custom.cose"),
    ];

    for (content_type, payload_data, output_file) in test_cases {
        let payload_path = temp_dir.join(format!("payload_{}", output_file));
        let output_path = temp_dir.join(output_file);

        create_test_payload(&payload_path, payload_data);

        let mut args = default_sign_args(payload_path, output_path.clone(), "der".to_string());
        args.key = Some(key_path.clone());
        args.content_type = content_type.to_string();

        let exit_code = sign::run(args);
        assert_eq!(exit_code, 0, "Sign with content type '{}' should succeed", content_type);
        assert!(output_path.exists(), "Output file should be created for {}", content_type);
    }

    let _ = fs::remove_dir_all(&temp_dir);
}
