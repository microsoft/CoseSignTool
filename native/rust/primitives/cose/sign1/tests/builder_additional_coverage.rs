// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for CoseSign1Builder to reach all uncovered code paths.

use std::io::Cursor;
use std::sync::Arc;

use cbor_primitives::{CborDecoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::error::{CoseKeyError, CoseSign1Error};
use cose_sign1_primitives::headers::{ContentType, CoseHeaderMap};
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::StreamingPayload;
use cose_sign1_primitives::sig_structure::SizedReader;
use crypto_primitives::{CryptoError, CryptoSigner, SigningContext};

/// Mock signer for testing
struct MockSigner {
    streaming_supported: bool,
    should_fail: bool,
}

impl MockSigner {
    fn new() -> Self {
        Self {
            streaming_supported: false,
            should_fail: false,
        }
    }

    fn with_streaming(streaming: bool) -> Self {
        Self {
            streaming_supported: streaming,
            should_fail: false,
        }
    }

    fn with_failure() -> Self {
        Self {
            streaming_supported: false,
            should_fail: true,
        }
    }
}

impl CryptoSigner for MockSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.should_fail {
            return Err(CryptoError::SigningFailed(
                "Mock signing failure".to_string(),
            ));
        }
        Ok(format!("sig_{}_bytes", data.len()).into_bytes())
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn supports_streaming(&self) -> bool {
        self.streaming_supported
    }

    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        if self.streaming_supported {
            Ok(Box::new(MockSigningContext::new()))
        } else {
            Err(CryptoError::UnsupportedOperation(
                "Streaming not supported".to_string(),
            ))
        }
    }
}

/// Mock streaming signing context
struct MockSigningContext {
    data: Vec<u8>,
}

impl MockSigningContext {
    fn new() -> Self {
        Self { data: Vec::new() }
    }
}

impl SigningContext for MockSigningContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.data.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        Ok(format!("streaming_sig_{}_bytes", self.data.len()).into_bytes())
    }
}

/// Mock streaming payload for testing
struct MockStreamingPayload {
    data: Vec<u8>,
}

impl MockStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl StreamingPayload for MockStreamingPayload {
    fn open(
        &self,
    ) -> Result<
        Box<dyn cose_sign1_primitives::sig_structure::SizedRead + Send>,
        cose_sign1_primitives::error::PayloadError,
    > {
        Ok(Box::new(SizedReader::new(
            Cursor::new(self.data.clone()),
            self.data.len() as u64,
        )))
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

#[test]
fn test_builder_external_aad() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let external_aad = b"additional_authenticated_data";
    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(external_aad.to_vec()) // Test external_aad method
        .sign(&signer, b"payload")
        .expect("should sign with external AAD");

    // The external AAD affects the signature but isn't stored in the message
    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(msg.payload(), Some(b"payload".as_slice()));
}

#[test]
fn test_builder_content_type_header() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    protected.set_content_type(ContentType::Text("application/json".to_string()));

    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign(&signer, b"{\"key\":\"value\"}")
        .expect("should sign with content type");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(
        msg.protected_headers().content_type(),
        Some(ContentType::Text("application/json".to_string()))
    );
}

#[test]
fn test_builder_max_embed_size() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();
    let large_payload = vec![0u8; 1000]; // 1KB payload

    // Set a small max embed size
    let result = CoseSign1Builder::new()
        .protected(protected)
        .max_embed_size(100) // Only allow 100 bytes
        .sign(&signer, &large_payload);

    // This should succeed for regular signing (max_embed_size only applies to streaming)
    assert!(result.is_ok());
}

#[test]
fn test_builder_max_embed_size_streaming() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();
    let large_payload = vec![0u8; 1000]; // 1KB payload
    let payload = Arc::new(MockStreamingPayload::new(large_payload));

    // Set a small max embed size for streaming
    let result = CoseSign1Builder::new()
        .protected(protected)
        .max_embed_size(100) // Only allow 100 bytes
        .sign_streaming(&signer, payload);

    // Should fail with PayloadTooLargeForEmbedding
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadTooLargeForEmbedding(actual, limit) => {
            assert_eq!(actual, 1000);
            assert_eq!(limit, 100);
        }
        _ => panic!("Expected PayloadTooLargeForEmbedding error"),
    }
}

#[test]
fn test_builder_streaming_with_streaming_signer() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    // Signer that supports streaming
    let signer = MockSigner::with_streaming(true);
    let payload_data = b"streaming_payload_data".to_vec();
    let payload = Arc::new(MockStreamingPayload::new(payload_data));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload)
        .expect("should sign with streaming signer");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(msg.payload(), Some(b"streaming_payload_data".as_slice()));
    // Signature should reflect streaming context
    assert!(String::from_utf8_lossy(msg.signature()).contains("streaming_sig"));
}

#[test]
fn test_builder_streaming_fallback_to_buffered() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    // Signer that does NOT support streaming (fallback path)
    let signer = MockSigner::new();
    let payload_data = b"fallback_payload".to_vec();
    let payload = Arc::new(MockStreamingPayload::new(payload_data));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload)
        .expect("should sign with fallback to buffered");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(msg.payload(), Some(b"fallback_payload".as_slice()));
    // Signature should NOT contain "streaming_sig" since we used fallback
    assert!(!String::from_utf8_lossy(msg.signature()).contains("streaming_sig"));
}

#[test]
fn test_builder_streaming_detached() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();
    let payload_data = b"detached_streaming_payload".to_vec();
    let payload = Arc::new(MockStreamingPayload::new(payload_data));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .detached(true) // Detached payload
        .sign_streaming(&signer, payload)
        .expect("should sign detached streaming");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert!(msg.is_detached());
    assert_eq!(msg.payload(), None);
}

#[test]
fn test_builder_unprotected_headers() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test-key-id");

    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected) // Test unprotected headers
        .sign(&signer, b"payload")
        .expect("should sign with unprotected headers");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"test-key-id".as_slice())
    );
}

#[test]
fn test_builder_empty_protected_headers() {
    // Test with empty protected headers (should use Vec::new() path)
    let protected = CoseHeaderMap::new(); // Empty

    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected) // Empty protected headers
        .sign(&signer, b"payload")
        .expect("should sign with empty protected");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(msg.alg(), None); // No algorithm in empty protected headers
    assert_eq!(msg.payload(), Some(b"payload".as_slice()));
}

#[test]
fn test_builder_all_options_combined() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    protected.set_content_type(ContentType::Int(42));

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"multi-option-key");

    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .external_aad(b"multi_option_aad")
        .detached(false) // Explicit embedded
        .tagged(true) // Explicit tagged
        .max_embed_size(1024 * 1024) // 1MB limit
        .sign(&signer, b"combined_options_payload")
        .expect("should sign with all options");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(
        msg.protected_headers().content_type(),
        Some(ContentType::Int(42))
    );
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"multi-option-key".as_slice())
    );
    assert_eq!(msg.payload(), Some(b"combined_options_payload".as_slice()));
    assert!(!msg.is_detached());
}

#[test]
fn test_builder_method_chaining_order() {
    // Test that method chaining works in different orders
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();

    // Chain methods in different order
    let result1 = CoseSign1Builder::new()
        .tagged(false)
        .detached(true)
        .protected(protected.clone())
        .external_aad(b"aad")
        .sign(&signer, b"payload1")
        .expect("should work in order 1");

    let result2 = CoseSign1Builder::new()
        .external_aad(b"aad")
        .protected(protected.clone())
        .detached(true)
        .tagged(false)
        .sign(&signer, b"payload2")
        .expect("should work in order 2");

    // Both should produce similar structures (detached, untagged)
    let msg1 = CoseSign1Message::parse(&result1).expect("parse 1");
    let msg2 = CoseSign1Message::parse(&result2).expect("parse 2");

    assert!(msg1.is_detached());
    assert!(msg2.is_detached());

    // Both should be untagged (no tag 18 at start)
    let provider = EverParseCborProvider;
    let mut decoder1 = provider.decoder(&result1);
    let mut decoder2 = provider.decoder(&result2);

    // Should start with array, not tag
    assert!(decoder1.decode_array_len().is_ok());
    assert!(decoder2.decode_array_len().is_ok());
}

#[test]
fn test_builder_default_values() {
    // Test that Default trait works if implemented, otherwise test new()
    let builder = CoseSign1Builder::new();

    // Verify default values by testing their effects
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();
    let result = builder
        .protected(protected)
        .sign(&signer, b"default_test")
        .expect("should sign with defaults");

    let msg = CoseSign1Message::parse(&result).expect("should parse");

    // Default should be embedded (not detached)
    assert!(!msg.is_detached());
    assert_eq!(msg.payload(), Some(b"default_test".as_slice()));

    // Default should be tagged - check for tag 18
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&result);
    let tag = decoder.decode_tag().expect("should have tag");
    assert_eq!(tag, 18u64);
}

#[test]
fn test_builder_debug_impl() {
    // Test Debug implementation if it exists
    let builder = CoseSign1Builder::new();
    let debug_str = format!("{:?}", builder);

    // Should contain struct name
    assert!(debug_str.contains("CoseSign1Builder"));
}

#[test]
fn test_builder_clone_impl() {
    // Test Clone implementation
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let builder1 = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .tagged(false);

    let builder2 = builder1.clone();

    let signer = MockSigner::new();

    // Both builders should produce equivalent results
    let result1 = builder1.sign(&signer, b"payload").expect("should sign 1");
    let result2 = builder2.sign(&signer, b"payload").expect("should sign 2");

    let msg1 = CoseSign1Message::parse(&result1).expect("parse 1");
    let msg2 = CoseSign1Message::parse(&result2).expect("parse 2");

    assert_eq!(msg1.is_detached(), msg2.is_detached());
    assert_eq!(msg1.alg(), msg2.alg());
}

#[test]
fn test_builder_no_unprotected_headers() {
    // Test path where unprotected is None (empty map encoding)
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = MockSigner::new();

    let result = CoseSign1Builder::new()
        .protected(protected)
        // Deliberately don't set unprotected headers
        .sign(&signer, b"payload")
        .expect("should sign without unprotected");

    let msg = CoseSign1Message::parse(&result).expect("should parse");
    assert!(msg.unprotected_headers().is_empty()); // Should have empty unprotected map
}

#[test]
fn test_constants() {
    // Test that MAX_EMBED_PAYLOAD_SIZE constant is accessible
    use cose_sign1_primitives::builder::MAX_EMBED_PAYLOAD_SIZE;
    assert_eq!(MAX_EMBED_PAYLOAD_SIZE, 2 * 1024 * 1024 * 1024); // 2GB
}
