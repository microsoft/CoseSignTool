// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended test coverage for pem.rs module in certificates local.

use cose_sign1_certificates_local::loaders::pem::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::KeyUsage;
use openssl::x509::{X509Name, X509};
use std::fs;

// Helper to create certificate and private key as PEM
fn create_cert_and_key_pem() -> (String, String) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509Name::builder().unwrap();
    name_builder
        .append_entry_by_text("CN", "test.example.com")
        .unwrap();
    let name = name_builder.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    let key_usage = KeyUsage::new().digital_signature().build().unwrap();
    builder.append_extension(key_usage).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();
    let key_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();

    (cert_pem, key_pem)
}

// Helper to create RSA certificate as PEM
fn create_rsa_cert_pem() -> String {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name_builder = X509Name::builder().unwrap();
    name_builder
        .append_entry_by_text("CN", "rsa.example.com")
        .unwrap();
    let name = name_builder.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    String::from_utf8(cert.to_pem().unwrap()).unwrap()
}

// Create temporary directory for test files
fn create_temp_dir() -> std::path::PathBuf {
    // Try to use a temp directory that's accessible in orchestrator environments
    let base_temp = if let Ok(cargo_target_tmpdir) = std::env::var("CARGO_TARGET_TMPDIR") {
        // Cargo provides this in some contexts
        std::path::PathBuf::from(cargo_target_tmpdir)
    } else if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        // Use target/tmp relative to the workspace root
        // CARGO_MANIFEST_DIR points to the crate directory
        // We need to go up to native/rust, then up to workspace root
        let mut path = std::path::PathBuf::from(manifest_dir);
        // Go up from local -> certificates -> extension_packs -> rust -> native -> workspace root
        for _ in 0..5 {
            path = path.parent().unwrap().to_path_buf();
        }
        path.join("target").join("tmp")
    } else {
        // Fall back to system temp (may not work in orchestrator)
        std::env::temp_dir()
    };

    // Use thread ID and timestamp to avoid collisions when tests run in parallel
    let thread_id = std::thread::current().id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp_dir = base_temp.join(format!("pem_test_{}_{:?}", timestamp, thread_id));
    std::fs::create_dir_all(&temp_dir).unwrap();
    temp_dir
}

#[test]
fn test_load_cert_from_pem_bytes_single_cert() {
    let (cert_pem, _key_pem) = create_cert_and_key_pem();

    let result = load_cert_from_pem_bytes(cert_pem.as_bytes());
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.chain.is_empty()); // No chain for single cert
}

#[test]
fn test_load_cert_from_pem_bytes_cert_with_private_key() {
    let (cert_pem, key_pem) = create_cert_and_key_pem();
    let combined_pem = format!("{}\n{}", cert_pem, key_pem);

    let result = load_cert_from_pem_bytes(combined_pem.as_bytes());
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.private_key_der.is_some());
}

#[test]
fn test_load_cert_from_pem_bytes_multiple_certs() {
    let (cert1_pem, _) = create_cert_and_key_pem();
    let cert2_pem = create_rsa_cert_pem();
    let combined_pem = format!("{}\n{}", cert1_pem, cert2_pem);

    let result = load_cert_from_pem_bytes(combined_pem.as_bytes());
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert_eq!(certificate.chain.len(), 1); // Second cert becomes chain
}

#[test]
fn test_load_cert_from_pem_file() {
    let temp_dir = create_temp_dir();
    let cert_file = temp_dir.join("test_cert.pem");

    let (cert_pem, _key_pem) = create_cert_and_key_pem();

    // Write PEM to file
    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();

    let result = load_cert_from_pem(&cert_file);
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());

    // Cleanup
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_load_cert_from_pem_file_with_key() {
    let temp_dir = create_temp_dir();
    let cert_file = temp_dir.join("test_cert_with_key.pem");

    let (cert_pem, key_pem) = create_cert_and_key_pem();
    let combined_pem = format!("{}\n{}", cert_pem, key_pem);

    fs::write(&cert_file, combined_pem.as_bytes()).unwrap();

    let result = load_cert_from_pem(&cert_file);
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.private_key_der.is_some());

    // Cleanup
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_load_cert_from_pem_file_not_found() {
    let result = load_cert_from_pem("nonexistent_file.pem");
    assert!(result.is_err());

    if let Err(e) = result {
        match e {
            cose_sign1_certificates_local::error::CertLocalError::IoError(_) => {
                // Expected error type
            }
            _ => panic!("Expected IoError"),
        }
    }
}

#[test]
fn test_load_cert_from_pem_bytes_empty() {
    let result = load_cert_from_pem_bytes(b"");
    assert!(result.is_err());

    if let Err(e) = result {
        match e {
            cose_sign1_certificates_local::error::CertLocalError::LoadFailed(_) => {
                // Expected error type
            }
            _ => panic!("Expected LoadFailed"),
        }
    }
}

#[test]
fn test_load_cert_from_pem_bytes_invalid_pem() {
    let invalid_pem = "This is not a valid PEM file";

    let result = load_cert_from_pem_bytes(invalid_pem.as_bytes());
    assert!(result.is_err());

    if let Err(e) = result {
        match e {
            cose_sign1_certificates_local::error::CertLocalError::LoadFailed(_) => {
                // Expected error type
            }
            _ => panic!("Expected LoadFailed"),
        }
    }
}

#[test]
fn test_load_cert_from_pem_bytes_malformed_pem_header() {
    let malformed_pem = r#"
-----BEGIN CERTIFICATE---
MIICljCCAX4CCQDDHFxZNiUCbzANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJV
UzAeFw0yMzEyMDEwMDAwMDBaFw0yNDEyMDEwMDAwMDBaMA0xCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----
"#;

    let result = load_cert_from_pem_bytes(malformed_pem.as_bytes());
    assert!(result.is_err());
}

#[test]
fn test_load_cert_from_pem_bytes_invalid_utf8() {
    let invalid_utf8: &[u8] = &[0xff, 0xfe, 0xfd];

    let result = load_cert_from_pem_bytes(invalid_utf8);
    assert!(result.is_err());

    if let Err(e) = result {
        match e {
            cose_sign1_certificates_local::error::CertLocalError::LoadFailed(msg) => {
                assert!(msg.contains("invalid UTF-8"));
            }
            _ => panic!("Expected LoadFailed with UTF-8 error"),
        }
    }
}

#[test]
fn test_load_cert_from_pem_bytes_private_key_only() {
    let (_cert_pem, key_pem) = create_cert_and_key_pem();

    let result = load_cert_from_pem_bytes(key_pem.as_bytes());
    assert!(result.is_err());

    // Should fail because there's no certificate, only private key
    if let Err(e) = result {
        match e {
            cose_sign1_certificates_local::error::CertLocalError::LoadFailed(_) => {
                // Expected error type
            }
            _ => panic!("Expected LoadFailed"),
        }
    }
}

#[test]
fn test_load_cert_from_pem_bytes_multiple_private_keys() {
    let (cert_pem, key_pem) = create_cert_and_key_pem();
    let (_cert2_pem, key2_pem) = create_cert_and_key_pem();
    let combined_pem = format!("{}\n{}\n{}", cert_pem, key_pem, key2_pem);

    let result = load_cert_from_pem_bytes(combined_pem.as_bytes());
    assert!(result.is_ok());

    // Should handle multiple keys (probably uses first one)
    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.private_key_der.is_some());
}

#[test]
fn test_load_cert_from_pem_bytes_mixed_content() {
    let (cert_pem, key_pem) = create_cert_and_key_pem();
    let cert2_pem = create_rsa_cert_pem();

    let mixed_pem = format!("{}\n{}\n{}\n# Some comment\n", cert_pem, key_pem, cert2_pem);

    let result = load_cert_from_pem_bytes(mixed_pem.as_bytes());
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert!(certificate.private_key_der.is_some());
    assert_eq!(certificate.chain.len(), 1);
}

#[test]
fn test_load_cert_from_pem_bytes_whitespace_handling() {
    let (cert_pem, _key_pem) = create_cert_and_key_pem();

    // Add extra whitespace
    let whitespace_pem = format!("\n\n  {}\n\n  ", cert_pem);

    let result = load_cert_from_pem_bytes(whitespace_pem.as_bytes());
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
}

#[test]
fn test_load_cert_from_pem_file_path_as_str() {
    let temp_dir = create_temp_dir();
    let cert_file = temp_dir.join("path_test.pem");

    let (cert_pem, _key_pem) = create_cert_and_key_pem();
    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();

    // Test with &str path
    let path_str = cert_file.to_str().unwrap();
    let result = load_cert_from_pem(path_str);
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());

    // Cleanup
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_load_cert_from_pem_file_permissions() {
    let temp_dir = create_temp_dir();
    let cert_file = temp_dir.join("permissions_test.pem");

    let (cert_pem, _key_pem) = create_cert_and_key_pem();
    fs::write(&cert_file, cert_pem.as_bytes()).unwrap();

    // Test reading (should work on most systems)
    let result = load_cert_from_pem(&cert_file);
    assert!(result.is_ok());

    // Cleanup
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_load_cert_from_pem_large_file() {
    let temp_dir = create_temp_dir();
    let cert_file = temp_dir.join("large_test.pem");

    // Create a file with many certificates
    let mut large_pem = String::new();

    for _ in 0..5 {
        let cert_pem = create_rsa_cert_pem();
        large_pem.push_str(&cert_pem);
        large_pem.push('\n');
    }

    fs::write(&cert_file, large_pem.as_bytes()).unwrap();

    let result = load_cert_from_pem(&cert_file);
    assert!(result.is_ok());

    let certificate = result.unwrap();
    assert!(!certificate.cert_der.is_empty());
    assert_eq!(certificate.chain.len(), 4); // First cert + 4 in chain

    // Cleanup
    fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn test_load_cert_from_pem_different_key_types() {
    // Test with different private key formats
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509Name::builder().unwrap();
    name_builder
        .append_entry_by_text("CN", "keytype.example.com")
        .unwrap();
    let name = name_builder.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();

    let cert_pem = String::from_utf8(cert.to_pem().unwrap()).unwrap();

    // Try different key formats
    let key_pkcs8 = String::from_utf8(pkey.private_key_to_pem_pkcs8().unwrap()).unwrap();
    // For EC keys, extract the EC key to get traditional format
    let ec_key_ref = pkey.ec_key().unwrap();
    let key_traditional = String::from_utf8(ec_key_ref.private_key_to_pem().unwrap()).unwrap();

    // Test PKCS#8
    let combined_pkcs8 = format!("{}\n{}", cert_pem, key_pkcs8);
    let result = load_cert_from_pem_bytes(combined_pkcs8.as_bytes());
    assert!(result.is_ok());

    // Test traditional format
    let combined_traditional = format!("{}\n{}", cert_pem, key_traditional);
    let result = load_cert_from_pem_bytes(combined_traditional.as_bytes());
    assert!(result.is_ok());
}
