// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for CoseSign1Builder.
//!
//! Tests uncovered paths in builder.rs including:
//! - Tagged/untagged building
//! - Detached payload building
//! - Content type and external AAD handling
//! - Builder method chaining

use cbor_primitives::{CborDecoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    algorithms::ES256, error::CoseSign1Error, CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue,
    CoseSign1Builder, CoseSign1Message, SizedRead,
};
use crypto_primitives::{CryptoError, CryptoSigner};

/// Mock signer for testing.
struct MockSigner {
    fail: bool,
}

impl CryptoSigner for MockSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.fail {
            Err(CryptoError::SigningFailed(
                "Mock signing failed".to_string(),
            ))
        } else {
            Ok(format!("signature_of_{}_bytes", data.len()).into_bytes())
        }
    }

    fn algorithm(&self) -> i64 {
        ES256
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn supports_streaming(&self) -> bool {
        false
    }

    fn sign_init(&self) -> Result<Box<dyn crypto_primitives::SigningContext>, CryptoError> {
        Err(CryptoError::UnsupportedOperation(
            "Streaming not supported in mock".to_string(),
        ))
    }
}

#[test]
fn test_builder_default_settings() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(protected)
        .sign(&signer, b"test payload")
        .unwrap();

    // Parse back to verify defaults
    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(msg.payload(), Some(b"test payload".as_slice()));
    assert!(!msg.is_detached());

    // Default is tagged (should have tag 18)
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    let tag = decoder.decode_tag().unwrap();
    assert_eq!(tag, 18u64); // COSE_SIGN1_TAG
}

#[test]
fn test_builder_untagged() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(protected)
        .tagged(false)
        .sign(&signer, b"test payload")
        .unwrap();

    // Should start with array, not tag
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
}

#[test]
fn test_builder_detached() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(protected)
        .detached(true)
        .sign(&signer, b"test payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(msg.payload(), None);
    assert!(msg.is_detached());
}

#[test]
fn test_builder_with_unprotected_headers() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test_kid_unprotected");
    unprotected.insert(
        CoseHeaderLabel::Text("custom".to_string()),
        CoseHeaderValue::Text("unprotected_value".to_string().into()),
    );

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(protected)
        .unprotected(unprotected)
        .sign(&signer, b"test payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"test_kid_unprotected".as_slice())
    );
    assert_eq!(
        msg.unprotected_headers()
            .get(&CoseHeaderLabel::Text("custom".to_string())),
        Some(&CoseHeaderValue::Text(
            "unprotected_value".to_string().into()
        ))
    );
}

#[test]
fn test_builder_with_external_aad() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let external_aad = b"additional authenticated data";

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(protected)
        .external_aad(external_aad)
        .sign(&signer, b"test payload")
        .unwrap();

    // The signature should be different with external AAD
    // (we can't easily verify this without a real signer, but ensure no error)
    let msg = CoseSign1Message::parse(&result).unwrap();
    assert!(msg.signature().len() > 0);
}

#[test]
fn test_builder_max_embed_size_default() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    // Default should allow large payloads (2GB)
    let large_payload = vec![0u8; 1024 * 1024]; // 1MB should be fine

    let signer = MockSigner { fail: false };
    let result = builder.protected(protected).sign(&signer, &large_payload);

    assert!(result.is_ok());
}

#[test]
fn test_builder_max_embed_size_custom() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let payload = vec![0u8; 100]; // 100 bytes

    let signer = MockSigner { fail: false };

    // Set limit to 50 bytes - should fail
    let result = builder
        .clone()
        .protected(protected.clone())
        .max_embed_size(50)
        .sign(&signer, &payload);

    // Note: max_embed_size only affects streaming, not regular sign()
    // So this should still work
    assert!(result.is_ok());
}

#[test]
fn test_builder_empty_protected_headers() {
    let builder = CoseSign1Builder::new();

    let empty_protected = CoseHeaderMap::new();

    let signer = MockSigner { fail: false };
    let result = builder
        .protected(empty_protected)
        .sign(&signer, b"test payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&result).unwrap();
    assert!(msg.protected_headers().is_empty());
    assert_eq!(msg.protected_header_bytes(), &[]);
}

#[test]
fn test_builder_signing_failure() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let failing_signer = MockSigner { fail: true };
    let result = builder
        .protected(protected)
        .sign(&failing_signer, b"test payload");

    assert!(result.is_err());
    // Signing failure is wrapped as IoError in CoseSign1Error
    let err = result.unwrap_err();
    let err_str = err.to_string();
    assert!(
        err_str.contains("signing failed") || err_str.contains("Mock signing failed"),
        "Expected signing error, got: {}",
        err_str
    );
}

#[test]
fn test_builder_method_chaining() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test_kid");

    let signer = MockSigner { fail: false };

    // Chain all builder methods
    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .external_aad(b"external_aad")
        .detached(false)
        .tagged(true)
        .max_embed_size(1024 * 1024)
        .sign(&signer, b"test payload")
        .unwrap();

    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(msg.alg(), Some(ES256));
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"test_kid".as_slice())
    );
    assert_eq!(msg.payload(), Some(b"test payload".as_slice()));
}

#[test]
fn test_builder_clone() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let builder1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .detached(true)
        .tagged(false);

    let builder2 = builder1.clone();

    let signer = MockSigner { fail: false };

    // Both builders should produce the same result
    let result1 = builder1.sign(&signer, b"payload1").unwrap();
    let result2 = builder2.sign(&signer, b"payload1").unwrap(); // Same payload for comparison

    let msg1 = CoseSign1Message::parse(&result1).unwrap();
    let msg2 = CoseSign1Message::parse(&result2).unwrap();

    assert_eq!(msg1.is_detached(), msg2.is_detached());
    assert_eq!(msg1.alg(), msg2.alg());
}

#[test]
fn test_builder_debug_formatting() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let builder = CoseSign1Builder::new().protected(protected).detached(true);

    let debug_str = format!("{:?}", builder);
    assert!(debug_str.contains("CoseSign1Builder"));
    assert!(debug_str.contains("detached"));
}

#[test]
fn test_builder_default_trait() {
    let builder = CoseSign1Builder::default();
    let new_builder = CoseSign1Builder::new();

    // Both should have same defaults (we can't easily compare directly,
    // but ensure both work the same way)
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let signer = MockSigner { fail: false };

    let result1 = builder
        .protected(protected.clone())
        .sign(&signer, b"test")
        .unwrap();
    let result2 = new_builder
        .protected(protected)
        .sign(&signer, b"test")
        .unwrap();

    let msg1 = CoseSign1Message::parse(&result1).unwrap();
    let msg2 = CoseSign1Message::parse(&result2).unwrap();

    assert_eq!(msg1.is_detached(), msg2.is_detached());
    assert_eq!(msg1.payload(), msg2.payload());
}

/// Test helper to create streaming payload mock.
struct MockStreamingPayload {
    data: Vec<u8>,
    size: u64,
}

impl MockStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        let size = data.len() as u64;
        Self { data, size }
    }
}

/// A wrapper around Cursor that implements SizedRead.
struct SizedCursor {
    cursor: std::io::Cursor<Vec<u8>>,
    len: u64,
}

impl std::io::Read for SizedCursor {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}

impl SizedRead for SizedCursor {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.len)
    }
}

impl cose_sign1_primitives::StreamingPayload for MockStreamingPayload {
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, cose_sign1_primitives::PayloadError> {
        Ok(Box::new(SizedCursor {
            cursor: std::io::Cursor::new(self.data.clone()),
            len: self.size,
        }))
    }

    fn size(&self) -> u64 {
        self.size
    }
}

use std::sync::Arc;

#[test]
fn test_builder_sign_streaming_not_supported() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let payload = Arc::new(MockStreamingPayload::new(
        b"test streaming payload".to_vec(),
    ));
    let signer = MockSigner { fail: false }; // Mock doesn't support streaming

    let result = builder
        .protected(protected)
        .sign_streaming(&signer, payload)
        .unwrap();

    // Should fallback to buffering
    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(msg.payload(), Some(b"test streaming payload".as_slice()));
}

#[test]
fn test_builder_sign_streaming_detached() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let payload = Arc::new(MockStreamingPayload::new(
        b"test streaming payload".to_vec(),
    ));
    let signer = MockSigner { fail: false };

    let result = builder
        .protected(protected)
        .detached(true)
        .sign_streaming(&signer, payload)
        .unwrap();

    let msg = CoseSign1Message::parse(&result).unwrap();
    assert_eq!(msg.payload(), None);
    assert!(msg.is_detached());
}

#[test]
fn test_builder_sign_streaming_too_large() {
    let builder = CoseSign1Builder::new();

    let mut protected = CoseHeaderMap::new();
    protected.set_alg(ES256);

    let large_payload = Arc::new(MockStreamingPayload {
        data: vec![0u8; 1000],
        size: 2000, // Pretend it's 2000 bytes
    });

    let signer = MockSigner { fail: false };

    let result = builder
        .protected(protected)
        .max_embed_size(1000) // Limit to 1000 bytes
        .sign_streaming(&signer, large_payload);

    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadTooLargeForEmbedding(actual, limit) => {
            assert_eq!(actual, 2000);
            assert_eq!(limit, 1000);
        }
        _ => panic!("Expected PayloadTooLargeForEmbedding error"),
    }
}
