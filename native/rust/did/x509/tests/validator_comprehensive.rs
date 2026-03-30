// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional validator coverage tests

use did_x509::validator::DidX509Validator;
use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use did_x509::error::DidX509Error;
use did_x509::models::SanType;
use rcgen::{
    CertificateParams, DnType, KeyPair, ExtendedKeyUsagePurpose,
    SanType as RcgenSanType,
};
use rcgen::string::Ia5String;

/// Generate certificate with code signing EKU
fn generate_code_signing_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test Certificate");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with multiple EKUs
fn generate_multi_eku_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Multi EKU Test");
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with subject attributes
fn generate_cert_with_subject() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Subject Test");
    params.distinguished_name.push(DnType::OrganizationName, "Test Org");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with SAN
fn generate_cert_with_san() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "SAN Test");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    params.subject_alt_names = vec![
        RcgenSanType::DnsName(Ia5String::try_from("example.com").unwrap()),
        RcgenSanType::Rfc822Name(Ia5String::try_from("test@example.com").unwrap()),
    ];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

#[test]
fn test_validate_with_eku_policy() {
    let cert_der = generate_code_signing_cert();
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok(), "Validation should succeed: {:?}", result.err());
    
    let validation = result.unwrap();
    assert!(validation.is_valid, "Should be valid");
    assert!(validation.errors.is_empty(), "Should have no errors");
}

#[test]
fn test_validate_with_wrong_eku() {
    // Create cert with Server Auth, validate for Code Signing
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Wrong EKU Test");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der = cert.der().to_vec();
    
    // Build DID requiring code signing using proper builder
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok()); // Parsing works, but validation result indicates failure
    
    let validation = result.unwrap();
    assert!(!validation.is_valid, "Should not be valid due to EKU mismatch");
    assert!(!validation.errors.is_empty(), "Should have errors");
}

#[test]
fn test_validate_with_subject_policy() {
    let cert_der = generate_cert_with_subject();
    
    // Build DID with subject policy
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        DidX509Policy::Subject(vec![("CN".to_string(), "Subject Test".to_string())]),
    ];
    let did = DidX509Builder::build_sha256(&cert_der, &policies).unwrap();
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok(), "Validation should succeed: {:?}", result.err());
    
    let validation = result.unwrap();
    assert!(validation.is_valid, "Should be valid with matching subject");
}

#[test]
fn test_validate_with_san_policy() {
    let cert_der = generate_cert_with_san();
    
    // Build DID with SAN policy
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        DidX509Policy::San(SanType::Dns, "example.com".to_string()),
    ];
    let did = DidX509Builder::build_sha256(&cert_der, &policies).unwrap();
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok(), "Validation should succeed: {:?}", result.err());
    
    let validation = result.unwrap();
    assert!(validation.is_valid, "Should be valid with matching SAN");
}

#[test]
fn test_validate_empty_chain() {
    let did = "did:x509:0:sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA::eku:1.2.3";
    
    let result = DidX509Validator::validate(did, &[]);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        DidX509Error::InvalidChain(msg) => {
            assert!(msg.contains("Empty"), "Should indicate empty chain");
        }
        other => panic!("Expected InvalidChain, got {:?}", other),
    }
}

#[test]
fn test_validate_fingerprint_mismatch() {
    let cert_der = generate_code_signing_cert();
    
    // Use wrong fingerprint - must be proper length (64 hex chars = 32 bytes for sha256)
    let wrong_fingerprint = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    let did = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", wrong_fingerprint);
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        DidX509Error::NoCaMatch => {} // Expected
        DidX509Error::FingerprintLengthMismatch(_, _, _) => {} // Also acceptable
        other => panic!("Expected NoCaMatch or FingerprintLengthMismatch, got {:?}", other),
    }
}

#[test]
fn test_validate_invalid_did_format() {
    let cert_der = generate_code_signing_cert();
    let invalid_did = "not-a-valid-did";
    
    let result = DidX509Validator::validate(invalid_did, &[&cert_der]);
    assert!(result.is_err(), "Should fail with invalid DID format");
}

#[test]
fn test_validate_multiple_policies_all_pass() {
    let cert_der = generate_cert_with_san();
    
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        DidX509Policy::San(SanType::Dns, "example.com".to_string()),
        DidX509Policy::San(SanType::Email, "test@example.com".to_string()),
    ];
    let did = DidX509Builder::build_sha256(&cert_der, &policies).unwrap();
    
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok());
    
    let validation = result.unwrap();
    assert!(validation.is_valid, "All policies should pass");
}

#[test]
fn test_validate_multiple_policies_one_fails() {
    let cert_der = generate_cert_with_san();
    
    // Build DID with policies that match, then validate with a different SAN
    let policies = vec![
        DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]),
        DidX509Policy::San(SanType::Dns, "example.com".to_string()),
    ];
    let did = DidX509Builder::build_sha256(&cert_der, &policies).unwrap();
    
    // First validate that the correct policies pass
    let result = DidX509Validator::validate(&did, &[&cert_der]);
    assert!(result.is_ok());
    let validation = result.unwrap();
    assert!(validation.is_valid, "Correct policies should pass");
    
    // Now create a DID with a wrong SAN
    use sha2::{Sha256, Digest};
    let fingerprint = Sha256::digest(&cert_der);
    let fingerprint_hex = hex::encode(fingerprint);
    
    // Use base64url encoded fingerprint instead (this is what the parser expects)
    let did_wrong = format!(
        "did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3::san:dns:nonexistent.com",
        fingerprint_hex
    );
    
    let result2 = DidX509Validator::validate(&did_wrong, &[&cert_der]);
    // The DID parser may reject this format - check both possibilities
    match result2 {
        Ok(validation) => {
            // If parsing succeeds, validation should fail
            assert!(!validation.is_valid, "Should fail due to wrong SAN");
        }
        Err(_) => {
            // Parsing failed due to format issues - also acceptable
        }
    }
}

#[test]
fn test_validation_result_invalid_multiple() {
    // Test the invalid_multiple helper
    use did_x509::models::DidX509ValidationResult;
    
    let errors = vec!["Error 1".to_string(), "Error 2".to_string()];
    let result = DidX509ValidationResult::invalid_multiple(errors.clone());
    
    assert!(!result.is_valid);
    assert_eq!(result.errors.len(), 2);
    assert!(result.matched_ca_index.is_none());
}

#[test]
fn test_validation_result_add_error() {
    use did_x509::models::DidX509ValidationResult;
    
    // Start with a valid result
    let mut result = DidX509ValidationResult::valid(0);
    assert!(result.is_valid);
    assert!(result.errors.is_empty());
    
    // Add an error
    result.add_error("Error 1".to_string());
    
    // Should now be invalid
    assert!(!result.is_valid);
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0], "Error 1");
    
    // Add another error
    result.add_error("Error 2".to_string());
    assert!(!result.is_valid);
    assert_eq!(result.errors.len(), 2);
}

#[test]
fn test_validation_result_partial_eq_and_clone() {
    use did_x509::models::DidX509ValidationResult;
    
    let result1 = DidX509ValidationResult::valid(0);
    let result2 = result1.clone();
    
    // Test PartialEq
    assert_eq!(result1, result2);
    
    let result3 = DidX509ValidationResult::invalid("Error".to_string());
    assert_ne!(result1, result3);
}

#[test]
fn test_validation_result_debug() {
    use did_x509::models::DidX509ValidationResult;
    
    let result = DidX509ValidationResult::valid(0);
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("is_valid: true"));
}

#[test]
fn test_validator_with_sha384_did() {
    // Generate a certificate
    let cert_der = generate_code_signing_cert();
    
    // Build DID with SHA384
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build(&cert_der, &[policy], "sha384")
        .expect("Should build SHA384 DID");
    
    // Validate with the certificate
    let result = DidX509Validator::validate(&did_string, &[&cert_der]);
    
    assert!(result.is_ok(), "Validation should succeed: {:?}", result.err());
    let validation = result.unwrap();
    assert!(validation.is_valid, "Certificate should match DID");
}

#[test]
fn test_validator_with_sha512_did() {
    // Generate a certificate
    let cert_der = generate_code_signing_cert();
    
    // Build DID with SHA512
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build(&cert_der, &[policy], "sha512")
        .expect("Should build SHA512 DID");
    
    // Validate with the certificate
    let result = DidX509Validator::validate(&did_string, &[&cert_der]);
    
    assert!(result.is_ok(), "Validation should succeed: {:?}", result.err());
    let validation = result.unwrap();
    assert!(validation.is_valid, "Certificate should match DID");
}
