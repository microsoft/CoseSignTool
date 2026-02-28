// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple coverage tests for CoseSign1Builder focusing on uncovered paths.

use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::headers::{CoseHeaderMap, ContentType};
use crypto_primitives::{CryptoSigner, CryptoError};

// Minimal mock signer
struct TestSigner;

impl CryptoSigner for TestSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(format!("sig_{}_bytes", data.len()).into_bytes())
    }
    
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
    
    fn key_type(&self) -> &str {
        "test"
    }
}

#[test]
fn test_builder_new_and_default() {
    let builder1 = CoseSign1Builder::new();
    let builder2 = CoseSign1Builder::default();
    
    // Both should work (testing default impl)
    let signer = TestSigner;
    let result1 = builder1.sign(&signer, b"test");
    let result2 = builder2.sign(&signer, b"test");
    
    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

#[test]
fn test_builder_configuration() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_content_type(ContentType::Int(42));
    
    let builder = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .external_aad(b"test aad")
        .external_aad("string aad".to_string())  // Test string conversion
        .detached(true)
        .tagged(false)
        .max_embed_size(1024);
    
    let signer = TestSigner;
    let result = builder.sign(&signer, b"test payload");
    assert!(result.is_ok());
}

#[test]
fn test_builder_clone() {
    let builder1 = CoseSign1Builder::new().detached(true);
    let builder2 = builder1.clone();
    
    let signer = TestSigner;
    let result1 = builder1.sign(&signer, b"test");
    let result2 = builder2.sign(&signer, b"test");
    
    assert!(result1.is_ok());
    assert!(result2.is_ok());
}

#[test]
fn test_builder_debug() {
    let builder = CoseSign1Builder::new();
    let debug_str = format!("{:?}", builder);
    assert!(debug_str.contains("CoseSign1Builder"));
}

#[test]
fn test_builder_with_empty_protected_headers() {
    let builder = CoseSign1Builder::new(); // No protected headers set
    
    let signer = TestSigner;
    let result = builder.sign(&signer, b"test");
    assert!(result.is_ok());
}

#[test] 
fn test_builder_detached_vs_embedded() {
    let signer = TestSigner;
    
    // Test detached
    let detached_builder = CoseSign1Builder::new().detached(true);
    let detached_result = detached_builder.sign(&signer, b"payload");
    assert!(detached_result.is_ok());
    
    // Test embedded  
    let embedded_builder = CoseSign1Builder::new().detached(false);
    let embedded_result = embedded_builder.sign(&signer, b"payload");
    assert!(embedded_result.is_ok());
}

#[test]
fn test_builder_tagged_vs_untagged() {
    let signer = TestSigner;
    
    // Test tagged
    let tagged_builder = CoseSign1Builder::new().tagged(true);
    let tagged_result = tagged_builder.sign(&signer, b"payload");
    assert!(tagged_result.is_ok());
    
    // Test untagged
    let untagged_builder = CoseSign1Builder::new().tagged(false);
    let untagged_result = untagged_builder.sign(&signer, b"payload");
    assert!(untagged_result.is_ok());
}

#[test]
fn test_builder_with_unprotected_headers() {
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_content_type(ContentType::Text("application/cbor".to_string()));
    
    let builder = CoseSign1Builder::new().unprotected(unprotected);
    let signer = TestSigner;
    let result = builder.sign(&signer, b"payload");
    assert!(result.is_ok());
}

#[test]
fn test_builder_without_unprotected_headers() {
    let builder = CoseSign1Builder::new(); // No unprotected headers
    let signer = TestSigner;
    let result = builder.sign(&signer, b"payload");
    assert!(result.is_ok());
}

// Mock failing signer to test error paths
struct FailingSigner;

impl CryptoSigner for FailingSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::SigningFailed("test failure".to_string()))
    }
    
    fn algorithm(&self) -> i64 {
        -7
    }
    
    fn key_type(&self) -> &str {
        "failing"
    }
}

#[test]
fn test_builder_signing_failure() {
    let builder = CoseSign1Builder::new();
    let failing_signer = FailingSigner;
    
    let result = builder.sign(&failing_signer, b"test");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("test failure"));
}