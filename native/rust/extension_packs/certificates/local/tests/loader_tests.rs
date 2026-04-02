// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for certificate loaders.

use cose_sign1_certificates_local::*;
use std::fs;
use std::path::PathBuf;

fn temp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join("cose_loader_tests");
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn cleanup_temp_dir() {
    let dir = temp_dir();
    let _ = fs::remove_dir_all(dir);
}

fn create_test_cert() -> Certificate {
    let provider = Box::new(SoftwareKeyProvider::new());
    let factory = EphemeralCertificateFactory::new(provider);

    let options = CertificateOptions::new()
        .with_subject_name("CN=Test Certificate")
        .with_key_algorithm(KeyAlgorithm::Ecdsa)
        .with_key_size(256);

    factory.create_certificate(options).unwrap()
}

#[test]
fn test_load_cert_from_der_bytes() {
    let cert = create_test_cert();

    let loaded = loaders::der::load_cert_from_der_bytes(&cert.cert_der).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);
    assert!(!loaded.has_private_key());
}

#[test]
fn test_load_cert_from_der_file() {
    let cert = create_test_cert();
    let temp = temp_dir();
    let cert_path = temp.join("test_cert.der");

    fs::write(&cert_path, &cert.cert_der).unwrap();

    let loaded = loaders::der::load_cert_from_der(&cert_path).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);
    assert!(!loaded.has_private_key());

    let _ = fs::remove_file(cert_path);
}

#[test]
fn test_load_cert_and_key_from_der() {
    let cert = create_test_cert();
    let temp = temp_dir();
    let cert_path = temp.join("test_cert_with_key.der");
    let key_path = temp.join("test_key.der");

    fs::write(&cert_path, &cert.cert_der).unwrap();
    fs::write(&key_path, cert.private_key_der.as_ref().unwrap()).unwrap();

    let loaded = loaders::der::load_cert_and_key_from_der(&cert_path, &key_path).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);
    assert!(loaded.has_private_key());
    assert_eq!(
        loaded.private_key_der.as_ref().unwrap(),
        cert.private_key_der.as_ref().unwrap()
    );

    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);
}

#[test]
fn test_load_cert_from_pem_single() {
    let cert = create_test_cert();

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode(&cert.cert_der)
    );

    let loaded = loaders::pem::load_cert_from_pem_bytes(pem_content.as_bytes()).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);
    assert!(!loaded.has_private_key());
}

#[test]
fn test_load_cert_from_pem_with_key() {
    let cert = create_test_cert();

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode(&cert.cert_der),
        base64_encode(cert.private_key_der.as_ref().unwrap())
    );

    let loaded = loaders::pem::load_cert_from_pem_bytes(pem_content.as_bytes()).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);
    assert!(loaded.has_private_key());
    assert_eq!(
        loaded.private_key_der.as_ref().unwrap(),
        cert.private_key_der.as_ref().unwrap()
    );
}

#[test]
fn test_load_cert_from_pem_with_chain() {
    let cert1 = create_test_cert();
    let cert2 = create_test_cert();

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode(&cert1.cert_der),
        base64_encode(&cert2.cert_der)
    );

    let loaded = loaders::pem::load_cert_from_pem_bytes(pem_content.as_bytes()).unwrap();

    assert_eq!(loaded.cert_der, cert1.cert_der);
    assert_eq!(loaded.chain.len(), 1);
    assert_eq!(loaded.chain[0], cert2.cert_der);
}

#[test]
fn test_load_cert_from_pem_file() {
    let cert = create_test_cert();
    let temp = temp_dir();
    let pem_path = temp.join("test_cert.pem");

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64_encode(&cert.cert_der)
    );

    fs::write(&pem_path, pem_content).unwrap();

    let loaded = loaders::pem::load_cert_from_pem(&pem_path).unwrap();

    assert_eq!(loaded.cert_der, cert.cert_der);

    let _ = fs::remove_file(pem_path);
}

#[test]
fn test_invalid_der_error() {
    let invalid_data = vec![0xFFu8; 100];

    let result = loaders::der::load_cert_from_der_bytes(&invalid_data);

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("invalid DER certificate"));
        }
        _ => panic!("expected LoadFailed error"),
    }
}

#[test]
fn test_missing_file_error() {
    let temp = temp_dir();
    let nonexistent = temp.join("nonexistent.der");

    let result = loaders::der::load_cert_from_der(&nonexistent);

    assert!(result.is_err());
    match result {
        Err(CertLocalError::IoError(_)) => {}
        _ => panic!("expected IoError"),
    }
}

#[test]
fn test_empty_pem_error() {
    let empty_pem = "";

    let result = loaders::pem::load_cert_from_pem_bytes(empty_pem.as_bytes());

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("no valid PEM blocks found"));
        }
        _ => panic!("expected LoadFailed error"),
    }
}

#[test]
fn test_pem_with_ec_private_key() {
    let cert = create_test_cert();

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
        base64_encode(&cert.cert_der),
        base64_encode(cert.private_key_der.as_ref().unwrap())
    );

    let loaded = loaders::pem::load_cert_from_pem_bytes(pem_content.as_bytes()).unwrap();

    assert!(loaded.has_private_key());
}

#[test]
fn test_pem_with_rsa_private_key() {
    let cert = create_test_cert();

    let pem_content = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n-----BEGIN RSA PRIVATE KEY-----\n{}\n-----END RSA PRIVATE KEY-----\n",
        base64_encode(&cert.cert_der),
        base64_encode(cert.private_key_der.as_ref().unwrap())
    );

    let loaded = loaders::pem::load_cert_from_pem_bytes(pem_content.as_bytes()).unwrap();

    assert!(loaded.has_private_key());
}

#[test]
fn test_loaded_certificate_wrapper() {
    let cert = create_test_cert();

    let loaded = LoadedCertificate::new(cert.clone(), CertificateFormat::Der);

    assert_eq!(loaded.certificate.cert_der, cert.cert_der);
    assert_eq!(loaded.source_format, CertificateFormat::Der);
}

#[test]
fn test_windows_store_returns_error_without_feature() {
    use cose_sign1_certificates_local::loaders::windows_store::{StoreLocation, StoreName};

    let result = loaders::windows_store::load_from_store_by_thumbprint(
        "abcd1234abcd1234abcd1234abcd1234abcd1234",
        StoreName::My,
        StoreLocation::CurrentUser,
    );

    // Without the windows-store feature (or on non-Windows), this should fail.
    // With the feature on Windows, it will fail because the thumbprint doesn't exist in the store.
    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("Windows") || msg.contains("not found") || msg.contains("not"));
        }
        _ => panic!("expected LoadFailed error"),
    }
}

#[test]
#[cfg(not(feature = "pfx"))]
fn test_pfx_without_feature_returns_error() {
    let result = loaders::pfx::load_from_pfx_bytes(&[0u8]);

    assert!(result.is_err());
    match result {
        Err(CertLocalError::LoadFailed(msg)) => {
            assert!(msg.contains("PFX support not enabled"));
        }
        _ => panic!("expected LoadFailed error"),
    }
}

fn base64_encode(data: &[u8]) -> String {
    const BASE64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;

    while i + 2 < data.len() {
        let b1 = data[i];
        let b2 = data[i + 1];
        let b3 = data[i + 2];

        result.push(BASE64_TABLE[(b1 >> 2) as usize] as char);
        result.push(BASE64_TABLE[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(BASE64_TABLE[(((b2 & 0x0F) << 2) | (b3 >> 6)) as usize] as char);
        result.push(BASE64_TABLE[(b3 & 0x3F) as usize] as char);

        if (i + 4) % 64 == 0 {
            result.push('\n');
        }

        i += 3;
    }

    let remaining = data.len() - i;
    if remaining == 1 {
        let b1 = data[i];
        result.push(BASE64_TABLE[(b1 >> 2) as usize] as char);
        result.push(BASE64_TABLE[((b1 & 0x03) << 4) as usize] as char);
        result.push_str("==");
    } else if remaining == 2 {
        let b1 = data[i];
        let b2 = data[i + 1];
        result.push(BASE64_TABLE[(b1 >> 2) as usize] as char);
        result.push(BASE64_TABLE[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(BASE64_TABLE[((b2 & 0x0F) << 2) as usize] as char);
        result.push('=');
    }

    result
}

#[test]
fn cleanup_after_tests() {
    cleanup_temp_dir();
}
