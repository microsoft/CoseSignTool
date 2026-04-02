// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for PFX (PKCS#12) certificate loading.

use cose_sign1_certificates_local::error::CertLocalError;
use cose_sign1_certificates_local::loaders::pfx::*;
use std::path::PathBuf;

// Mock Pkcs12Parser for testing
struct MockPkcs12Parser {
    should_fail: bool,
    parsed_result: Option<ParsedPkcs12>,
}

impl MockPkcs12Parser {
    fn new_success() -> Self {
        let parsed_result = ParsedPkcs12 {
            cert_der: vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05], // Mock DER cert
            private_key_der: Some(vec![0x30, 0x82, 0x01, 0x11, 0x02, 0x01]), // Mock private key
            chain_ders: vec![
                vec![0x30, 0x82, 0x01, 0x33, 0x04, 0x06], // Mock chain cert 1
                vec![0x30, 0x82, 0x01, 0x44, 0x04, 0x07], // Mock chain cert 2
            ],
        };
        Self {
            should_fail: false,
            parsed_result: Some(parsed_result),
        }
    }

    fn new_failure() -> Self {
        Self {
            should_fail: true,
            parsed_result: None,
        }
    }

    fn new_no_private_key() -> Self {
        let parsed_result = ParsedPkcs12 {
            cert_der: vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05],
            private_key_der: None,
            chain_ders: vec![],
        };
        Self {
            should_fail: false,
            parsed_result: Some(parsed_result),
        }
    }

    fn new_empty_private_key() -> Self {
        let parsed_result = ParsedPkcs12 {
            cert_der: vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05],
            private_key_der: Some(vec![]), // Empty key
            chain_ders: vec![],
        };
        Self {
            should_fail: false,
            parsed_result: Some(parsed_result),
        }
    }

    fn new_empty_cert() -> Self {
        let parsed_result = ParsedPkcs12 {
            cert_der: vec![], // Empty cert
            private_key_der: Some(vec![0x30, 0x82, 0x01, 0x11]),
            chain_ders: vec![],
        };
        Self {
            should_fail: false,
            parsed_result: Some(parsed_result),
        }
    }
}

impl Pkcs12Parser for MockPkcs12Parser {
    fn parse_pkcs12(&self, _bytes: &[u8], _password: &str) -> Result<ParsedPkcs12, CertLocalError> {
        if self.should_fail {
            Err(CertLocalError::LoadFailed(
                "Mock parser failure".to_string(),
            ))
        } else {
            Ok(self.parsed_result.as_ref().unwrap().clone())
        }
    }
}

#[test]
fn test_pfx_password_source_default() {
    let source = PfxPasswordSource::default();
    match source {
        PfxPasswordSource::EnvironmentVariable(var_name) => {
            assert_eq!(var_name, PFX_PASSWORD_ENV_VAR);
        }
        _ => panic!("Expected EnvironmentVariable source"),
    }
}

#[test]
fn test_pfx_password_source_env_var() {
    let source = PfxPasswordSource::EnvironmentVariable("CUSTOM_PFX_PASSWORD".to_string());
    match source {
        PfxPasswordSource::EnvironmentVariable(var_name) => {
            assert_eq!(var_name, "CUSTOM_PFX_PASSWORD");
        }
        _ => panic!("Expected EnvironmentVariable source"),
    }
}

#[test]
fn test_pfx_password_source_empty() {
    let source = PfxPasswordSource::Empty;
    match source {
        PfxPasswordSource::Empty => {
            // Expected
        }
        _ => panic!("Expected Empty source"),
    }
}

#[test]
fn test_resolve_password_empty() {
    let source = PfxPasswordSource::Empty;
    let result = resolve_password(&source);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "");
}

#[test]
fn test_resolve_password_missing_env_var() {
    let source = PfxPasswordSource::EnvironmentVariable("NONEXISTENT_PFX_PASSWORD".to_string());
    let result = resolve_password(&source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("NONEXISTENT_PFX_PASSWORD"));
            assert!(msg.contains("is not set"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_resolve_password_existing_env_var() {
    // Set a test environment variable
    let test_var = "TEST_PFX_PASSWORD_12345";
    let test_password = "test-password-value";
    std::env::set_var(test_var, test_password);

    let source = PfxPasswordSource::EnvironmentVariable(test_var.to_string());
    let result = resolve_password(&source);

    // Clean up
    std::env::remove_var(test_var);

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), test_password);
}

#[test]
fn test_load_with_parser_success() {
    let parser = MockPkcs12Parser::new_success();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC]; // Mock PFX bytes
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_ok());

    let cert = result.unwrap();
    assert_eq!(cert.cert_der, vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05]);
    assert!(cert.has_private_key());
    assert_eq!(cert.chain.len(), 2);
}

#[test]
fn test_load_with_parser_empty_bytes() {
    let parser = MockPkcs12Parser::new_success();
    let bytes = vec![];
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("PFX data is empty"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_with_parser_password_resolution_failure() {
    let parser = MockPkcs12Parser::new_success();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let source = PfxPasswordSource::EnvironmentVariable("NONEXISTENT_VAR".to_string());

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("NONEXISTENT_VAR"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_with_parser_parse_failure() {
    let parser = MockPkcs12Parser::new_failure();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Mock parser failure"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_with_parser_empty_certificate() {
    let parser = MockPkcs12Parser::new_empty_cert();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("PFX contained no certificate"));
        }
        _ => panic!("Expected LoadFailed error"),
    }
}

#[test]
fn test_load_with_parser_no_private_key() {
    let parser = MockPkcs12Parser::new_no_private_key();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_ok());

    let cert = result.unwrap();
    assert!(!cert.has_private_key());
    assert_eq!(cert.cert_der, vec![0x30, 0x82, 0x01, 0x23, 0x04, 0x05]);
}

#[test]
fn test_load_with_parser_empty_private_key() {
    let parser = MockPkcs12Parser::new_empty_private_key();
    let bytes = vec![0xFF, 0xFE, 0xFD, 0xFC];
    let source = PfxPasswordSource::Empty;

    let result = load_with_parser(&parser, &bytes, &source);
    assert!(result.is_ok());

    let cert = result.unwrap();
    // Empty private key should be treated as no private key
    assert!(!cert.has_private_key());
}

#[test]
fn test_load_file_with_parser() {
    let parser = MockPkcs12Parser::new_success();
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("test_pfx_file.pfx");

    // Write test data to file
    let test_data = vec![0xFF, 0xFE, 0xFD, 0xFC];
    std::fs::write(&temp_file, &test_data).unwrap();

    let source = PfxPasswordSource::Empty;
    let result = load_file_with_parser(&parser, &temp_file, &source);

    // Clean up
    std::fs::remove_file(&temp_file).ok();

    assert!(result.is_ok());
    let cert = result.unwrap();
    assert!(cert.has_private_key());
}

#[test]
fn test_load_file_with_parser_nonexistent_file() {
    let parser = MockPkcs12Parser::new_success();
    let nonexistent_file = PathBuf::from("/nonexistent/path/file.pfx");
    let source = PfxPasswordSource::Empty;

    let result = load_file_with_parser(&parser, nonexistent_file, &source);
    assert!(result.is_err());
    match result {
        Err(CertLocalError::IoError(_)) => {
            // Expected I/O error for nonexistent file
        }
        _ => panic!("Expected IoError"),
    }
}

#[test]
fn test_pfx_password_env_var_constant() {
    assert_eq!(PFX_PASSWORD_ENV_VAR, "COSESIGNTOOL_PFX_PASSWORD");
}

#[test]
fn test_parsed_pkcs12_structure() {
    let parsed = ParsedPkcs12 {
        cert_der: vec![1, 2, 3],
        private_key_der: Some(vec![4, 5, 6]),
        chain_ders: vec![vec![7, 8, 9], vec![10, 11, 12]],
    };

    assert_eq!(parsed.cert_der, vec![1, 2, 3]);
    assert_eq!(parsed.private_key_der, Some(vec![4, 5, 6]));
    assert_eq!(parsed.chain_ders.len(), 2);
    assert_eq!(parsed.chain_ders[0], vec![7, 8, 9]);
    assert_eq!(parsed.chain_ders[1], vec![10, 11, 12]);
}

#[test]
fn test_parsed_pkcs12_clone() {
    let original = ParsedPkcs12 {
        cert_der: vec![1, 2, 3],
        private_key_der: None,
        chain_ders: vec![],
    };

    let cloned = original.clone();
    assert_eq!(cloned.cert_der, original.cert_der);
    assert_eq!(cloned.private_key_der, original.private_key_der);
    assert_eq!(cloned.chain_ders, original.chain_ders);
}

#[cfg(not(feature = "pfx"))]
#[test]
fn test_pfx_functions_without_feature() {
    // Test that PFX functions return appropriate errors when feature is disabled
    let result = load_from_pfx("test.pfx");
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("PFX support not enabled"));
        }
        _ => panic!("Expected LoadFailed error"),
    }

    let result = load_from_pfx_bytes(&[1, 2, 3]);
    assert!(result.is_err());

    let result = load_from_pfx_with_env_var("test.pfx", "TEST_VAR");
    assert!(result.is_err());

    let result = load_from_pfx_no_password("test.pfx");
    assert!(result.is_err());
}
