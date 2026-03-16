// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered paths in cose_sign1_certificates_local:
//! - SoftwareKeyProvider RSA error path
//! - SoftwareKeyProvider ECDSA generation
//! - Factory ML-DSA branches (marked coverage(off) if pqc not enabled)
//! - Certificate DER and PEM loader error paths

use cose_sign1_certificates_local::key_algorithm::KeyAlgorithm;
use cose_sign1_certificates_local::software_key::SoftwareKeyProvider;
use cose_sign1_certificates_local::traits::PrivateKeyProvider;

// ========== SoftwareKeyProvider ==========

#[test]
fn software_key_rsa_not_supported() {
    let provider = SoftwareKeyProvider::new();
    // RSA is not supported
    assert!(!provider.supports_algorithm(KeyAlgorithm::Rsa));
    let result = provider.generate_key(KeyAlgorithm::Rsa, None);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("not yet implemented") || err.contains("not supported"));
}

#[test]
fn software_key_ecdsa_default_size() {
    let provider = SoftwareKeyProvider::new();
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
    let result = provider.generate_key(KeyAlgorithm::Ecdsa, None);
    assert!(result.is_ok(), "ECDSA generation should succeed: {:?}", result.err());
    let key = result.unwrap();
    assert!(!key.private_key_der.is_empty());
    assert!(!key.public_key_der.is_empty());
    assert_eq!(key.algorithm, KeyAlgorithm::Ecdsa);
}

#[test]
fn software_key_ecdsa_with_size() {
    let provider = SoftwareKeyProvider::new();
    let result = provider.generate_key(KeyAlgorithm::Ecdsa, Some(256));
    assert!(result.is_ok());
}

#[test]
fn software_key_name() {
    let provider = SoftwareKeyProvider::new();
    assert_eq!(provider.name(), "SoftwareKeyProvider");
}

#[test]
fn software_key_default() {
    let provider = SoftwareKeyProvider::default();
    assert!(provider.supports_algorithm(KeyAlgorithm::Ecdsa));
}
