// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional builder encoding variation coverage.

use cbor_primitives::{CborProvider, CborDecoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    CoseSign1Builder, CoseHeaderMap, algorithms,
    error::CoseSign1Error,
    headers::{CoseHeaderLabel, CoseHeaderValue},
};

// Mock signer for testing (doesn't need OpenSSL)
struct MockSigner {
    algorithm: i64,
}

impl MockSigner {
    fn new(algorithm: i64) -> Self {
        Self { algorithm }
    }
}

impl crypto_primitives::CryptoSigner for MockSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        Ok(vec![0x01, 0x02, 0x03, 0x04]) // Mock signature
    }
    
    fn algorithm(&self) -> i64 {
        self.algorithm
    }
    
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"mock_key_id")
    }
    
    fn key_type(&self) -> &str {
        "MOCK"
    }
    
    fn supports_streaming(&self) -> bool {
        false
    }
    
    fn sign_init(&self) -> Result<Box<dyn crypto_primitives::SigningContext>, crypto_primitives::CryptoError> {
        Err(crypto_primitives::CryptoError::UnsupportedAlgorithm(self.algorithm))
    }
}

#[test]
fn test_builder_untagged_output() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .tagged(false) // No CBOR tag
        .sign(&signer, b"test_payload")
        .unwrap();
    
    // Parse the result to verify it's untagged
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    // Should start with array, not tag
    let typ = decoder.peek_type().unwrap();
    assert_eq!(typ, cbor_primitives::CborType::Array);
}

#[test]
fn test_builder_tagged_output() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .tagged(true) // Include CBOR tag (default)
        .sign(&signer, b"test_payload")
        .unwrap();
    
    // Parse the result to verify it has tag
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    // Should start with tag
    let typ = decoder.peek_type().unwrap();
    assert_eq!(typ, cbor_primitives::CborType::Tag);
    
    let tag = decoder.decode_tag().unwrap();
    assert_eq!(tag, cose_sign1_primitives::algorithms::COSE_SIGN1_TAG);
}

#[test]
fn test_builder_detached_payload() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&signer, b"detached_payload")
        .unwrap();
    
    // Parse and verify payload is null
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    // Skip tag and array header
    let typ = decoder.peek_type().unwrap();
    if typ == cbor_primitives::CborType::Tag {
        decoder.decode_tag().unwrap();
    }
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    // Skip protected header
    decoder.decode_bstr().unwrap();
    // Skip unprotected header 
    decoder.decode_map_len().unwrap();
    
    // Check payload is null
    assert!(decoder.is_null().unwrap());
    decoder.decode_null().unwrap();
}

#[test]
fn test_builder_embedded_payload() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .detached(false) // Embedded (default)
        .sign(&signer, b"embedded_payload")
        .unwrap();
    
    // Parse and verify payload is embedded
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    // Skip tag and array header
    let typ = decoder.peek_type().unwrap();
    if typ == cbor_primitives::CborType::Tag {
        decoder.decode_tag().unwrap();
    }
    
    decoder.decode_array_len().unwrap();
    
    // Skip protected header
    decoder.decode_bstr().unwrap();
    // Skip unprotected header 
    decoder.decode_map_len().unwrap();
    
    // Check payload is embedded bstr
    let payload = decoder.decode_bstr().unwrap();
    assert_eq!(payload, b"embedded_payload");
}

#[test]
fn test_builder_with_external_aad() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"external_auth_data")
        .sign(&signer, b"payload_with_aad")
        .unwrap();
    
    // Should succeed with external AAD
    assert!(result.len() > 0);
}

#[test]
fn test_builder_with_unprotected_headers() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test_key_id");
    unprotected.insert(
        CoseHeaderLabel::Int(999),
        CoseHeaderValue::Text("custom_unprotected".to_string()),
    );
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .sign(&signer, b"payload_with_unprotected")
        .unwrap();
    
    // Parse and verify unprotected headers
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    
    // Skip tag and array header
    let typ = decoder.peek_type().unwrap();
    if typ == cbor_primitives::CborType::Tag {
        decoder.decode_tag().unwrap();
    }
    
    decoder.decode_array_len().unwrap();
    
    // Skip protected header
    decoder.decode_bstr().unwrap();
    
    // Check unprotected header map
    let unprotected_len = decoder.decode_map_len().unwrap();
    assert_eq!(unprotected_len, Some(2)); // kid + custom header
}

#[test]
fn test_builder_max_embed_size_limit() {
    // The max_embed_size limit only applies to streaming payloads
    // For the basic sign() method, the limit is not enforced
    // So let's just verify the setting works
    
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let large_payload = vec![0u8; 1000]; // 1KB payload
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .max_embed_size(500) // Set limit to 500 bytes
        .sign(&signer, &large_payload);
    
    // Should succeed because basic sign() doesn't enforce size limits
    assert!(result.is_ok());
}

#[test]
fn test_builder_max_embed_size_within_limit() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    let small_payload = vec![0u8; 100]; // 100 bytes payload
    
    let result = CoseSign1Builder::new()
        .protected(protected)
        .max_embed_size(500) // Set limit to 500 bytes
        .sign(&signer, &small_payload)
        .unwrap();
    
    assert!(result.len() > 0);
}

#[test]
fn test_builder_chaining() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"chained_key");
    
    let signer = MockSigner::new(algorithms::ES256);
    
    // Test method chaining
    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .external_aad(b"chained_aad")
        .detached(false)
        .tagged(true)
        .max_embed_size(1024)
        .sign(&signer, b"chained_payload")
        .unwrap();
    
    assert!(result.len() > 0);
}

#[test]
fn test_builder_clone_and_reuse() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let base_builder = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(false)
        .max_embed_size(2048);
    
    let signer = MockSigner::new(algorithms::ES256);
    
    // Clone and use for first message
    let result1 = base_builder.clone()
        .detached(false)
        .sign(&signer, b"first_payload")
        .unwrap();
    
    // Clone and use for second message  
    let result2 = base_builder.clone()
        .detached(true)
        .sign(&signer, b"second_payload")
        .unwrap();
    
    assert!(result1.len() > 0);
    assert!(result2.len() > 0);
    assert_ne!(result1, result2); // Should be different due to detached setting
}

#[test]
fn test_builder_debug_format() {
    let builder = CoseSign1Builder::new();
    let debug_str = format!("{:?}", builder);
    
    assert!(debug_str.contains("CoseSign1Builder"));
    assert!(debug_str.contains("protected"));
    assert!(debug_str.contains("tagged"));
    assert!(debug_str.contains("detached"));
}

#[test]
fn test_builder_default_implementation() {
    // Check what Default actually implements vs new()
    let builder1 = CoseSign1Builder::new();
    let builder2 = CoseSign1Builder::default();
    
    // Just check they're both valid builders
    let debug1 = format!("{:?}", builder1);
    let debug2 = format!("{:?}", builder2);
    
    // Both should contain the same structure fields
    assert!(debug1.contains("CoseSign1Builder"));
    assert!(debug2.contains("CoseSign1Builder"));
    
    // Default has different values than new(), so we can't compare them directly
    // Instead verify they both work
    let signer = MockSigner::new(algorithms::ES256);
    
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(algorithms::ES256);
    
    let result1 = builder1.protected(protected.clone()).sign(&signer, b"test").unwrap();
    let result2 = builder2.protected(protected).sign(&signer, b"test").unwrap();
    
    assert!(result1.len() > 0);
    assert!(result2.len() > 0);
}