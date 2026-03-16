// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for DirectSignatureFactory happy path scenarios.

use std::collections::HashMap;
use std::sync::Arc;

use cose_sign1_factories::{
    FactoryError,
    direct::{DirectSignatureFactory, DirectSignatureOptions},
};
use cose_sign1_primitives::{
    CoseHeaderMap, CoseSign1Message, CryptoSigner, CryptoError, MemoryPayload,
};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
    transparency::{TransparencyProvider, TransparencyError, TransparencyValidationResult},
};

/// Mock key that returns deterministic signatures.
#[derive(Clone)]
struct MockKey;

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"test-key-id")
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Return deterministic "signature"
        let mut sig = data.to_vec();
        sig.extend_from_slice(b"mock-signature");
        Ok(sig)
    }
}

/// Mock signing service for testing
struct MockSigningService {
    should_fail_signer: bool,
    should_fail_verify: bool,
}

impl MockSigningService {
    fn new() -> Self {
        Self {
            should_fail_signer: false,
            should_fail_verify: false,
        }
    }

    fn with_signer_failure() -> Self {
        Self {
            should_fail_signer: true,
            should_fail_verify: false,
        }
    }

    fn with_verify_failure() -> Self {
        Self {
            should_fail_signer: false,
            should_fail_verify: true,
        }
    }
}

impl SigningService for MockSigningService {
    fn get_cose_signer(&self, _context: &SigningContext) -> Result<CoseSigner, SigningError> {
        if self.should_fail_signer {
            return Err(SigningError::SigningFailed(
                "Mock signer creation failed".to_string(),
            ));
        }

        let key = Box::new(MockKey);
        let protected = CoseHeaderMap::new();
        let unprotected = CoseHeaderMap::new();
        Ok(CoseSigner::new(key, protected, unprotected))
    }

    fn is_remote(&self) -> bool {
        false
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        use std::sync::OnceLock;
        static METADATA: OnceLock<SigningServiceMetadata> = OnceLock::new();
        METADATA.get_or_init(|| SigningServiceMetadata {
            service_name: "MockSigningService".to_string(),
            service_description: "Test signing service".to_string(),
            additional_metadata: HashMap::new(),
        })
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        Ok(!self.should_fail_verify)
    }
}

/// Mock transparency provider for testing
struct MockTransparencyProvider {
    name: String,
}

impl MockTransparencyProvider {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl TransparencyProvider for MockTransparencyProvider {
    fn provider_name(&self) -> &str {
        &self.name
    }

    fn add_transparency_proof(&self, message_bytes: &[u8]) -> Result<Vec<u8>, TransparencyError> {
        // Just return the message with a suffix for testing
        let mut result = message_bytes.to_vec();
        result.extend_from_slice(format!("-{}-proof", self.name).as_bytes());
        Ok(result)
    }

    fn verify_transparency_proof(
        &self,
        _message_bytes: &[u8],
    ) -> Result<TransparencyValidationResult, TransparencyError> {
        Ok(TransparencyValidationResult::success(&self.name))
    }
}

fn create_test_signing_service() -> Arc<MockSigningService> {
    Arc::new(MockSigningService::new())
}

#[test]
fn test_direct_factory_new() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service.clone());

    // Verify factory was created
    assert_eq!(factory.transparency_providers().len(), 0);
}

#[test]
fn test_direct_factory_with_transparency_providers() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("provider1")),
        Box::new(MockTransparencyProvider::new("provider2")),
    ];

    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);
    assert_eq!(factory.transparency_providers().len(), 2);
}

#[test]
fn test_direct_factory_transparency_providers_accessor() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("test-provider")),
    ];

    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);
    let transparency_providers = factory.transparency_providers();
    assert_eq!(transparency_providers.len(), 1);
    assert_eq!(transparency_providers[0].provider_name(), "test-provider");
}

#[test]
fn test_direct_factory_create_bytes_none_options() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = b"Test payload";
    let content_type = "text/plain";

    let result = factory.create_bytes(payload, content_type, None);
    assert!(result.is_ok(), "create_bytes should succeed with None options");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_direct_factory_create_bytes_with_embed_payload() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = b"Test payload to embed";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_bytes(payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_bytes should succeed with embed_payload"
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse the message to verify payload was embedded
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    assert!(
        message.payload.is_some(),
        "Payload should be embedded in message"
    );
    assert_eq!(
        message.payload.unwrap(),
        payload,
        "Embedded payload should match original"
    );
}

#[test]
fn test_direct_factory_create() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = b"Test payload for create";
    let content_type = "application/octet-stream";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create(payload, content_type, Some(options));
    assert!(result.is_ok(), "create should succeed");

    let message = result.unwrap();
    assert!(
        message.payload.is_some(),
        "Message should have embedded payload"
    );
    assert_eq!(message.payload.unwrap(), payload);
}

#[test]
fn test_direct_factory_create_streaming_bytes() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let payload_data = b"Streaming test payload data";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "application/octet-stream";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming_bytes(streaming_payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_streaming_bytes should succeed: {:?}",
        result.err()
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse the message to verify
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    assert!(message.payload.is_some(), "Payload should be embedded");
    assert_eq!(message.payload.unwrap(), payload_data);
}

#[test]
fn test_direct_factory_create_streaming() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let payload_data = b"Another streaming test";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming(streaming_payload, content_type, Some(options));
    assert!(result.is_ok(), "create_streaming should succeed");

    let message = result.unwrap();
    assert!(message.payload.is_some(), "Message should have embedded payload");
    assert_eq!(message.payload.unwrap(), payload_data);
}

#[test]
fn test_direct_factory_create_bytes_with_transparency() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("test-provider")),
    ];
    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);

    let payload = b"Test payload with transparency";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_bytes(payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_bytes should succeed with transparency"
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
    
    // The mock transparency provider adds a suffix
    let bytes_str = String::from_utf8_lossy(&bytes);
    assert!(bytes_str.contains("test-provider-proof"));
}

#[test]
fn test_direct_factory_create_bytes_disable_transparency() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("disabled-provider")),
    ];
    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);

    let payload = b"Test payload disable transparency";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_disable_transparency(true);

    let result = factory.create_bytes(payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_bytes should succeed with transparency disabled"
    );

    let bytes_with_disabled = result.unwrap();
    
    // Also create without transparency providers for comparison
    let signing_service2 = create_test_signing_service();
    let factory_no_transparency = DirectSignatureFactory::new(signing_service2);
    let options_no_transparency = DirectSignatureOptions::new().with_embed_payload(true);
    let result_no_transparency = factory_no_transparency.create_bytes(payload, content_type, Some(options_no_transparency));
    let bytes_no_transparency = result_no_transparency.unwrap();
    
    // When transparency is disabled, bytes should be same length as without transparency
    assert_eq!(
        bytes_with_disabled.len(), 
        bytes_no_transparency.len(),
        "Disabled transparency should produce same length as no transparency"
    );
}

#[test]
fn test_direct_factory_streaming_max_embed_size() {
    let signing_service = create_test_signing_service();
    let factory = DirectSignatureFactory::new(signing_service);

    let large_payload = vec![0x42; 1000];
    let streaming_payload = Arc::new(MemoryPayload::from(large_payload));
    let content_type = "application/octet-stream";
    let options = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_max_embed_size(500); // Smaller than payload

    let result = factory.create_streaming_bytes(streaming_payload, content_type, Some(options));
    assert!(result.is_err(), "Should fail when payload exceeds max embed size");

    match result.unwrap_err() {
        FactoryError::PayloadTooLargeForEmbedding(size, max_size) => {
            assert_eq!(size, 1000);
            assert_eq!(max_size, 500);
        }
        _ => panic!("Expected PayloadTooLargeForEmbedding error"),
    }
}

#[test]
fn test_direct_factory_error_from_signing_service() {
    let signing_service = Arc::new(MockSigningService::with_signer_failure());
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = b"Test payload";
    let content_type = "text/plain";

    let result = factory.create_bytes(payload, content_type, None);
    assert!(result.is_err(), "Should fail when signing service fails");

    match result.unwrap_err() {
        FactoryError::SigningFailed(_) => {
            // Expected
        }
        _ => panic!("Expected SigningFailed error"),
    }
}

#[test]
fn test_direct_factory_verification_failure() {
    let signing_service = Arc::new(MockSigningService::with_verify_failure());
    let factory = DirectSignatureFactory::new(signing_service);

    let payload = b"Test payload";
    let content_type = "text/plain";

    let result = factory.create_bytes(payload, content_type, None);
    assert!(result.is_err(), "Should fail when verification fails");

    match result.unwrap_err() {
        FactoryError::VerificationFailed(msg) => {
            assert!(msg.contains("Post-sign verification failed"));
        }
        _ => panic!("Expected VerificationFailed error"),
    }
}

#[test]
fn test_factory_error_display() {
    // Test all FactoryError variants for Display implementation
    let signing_failed = FactoryError::SigningFailed("test signing error".to_string());
    assert_eq!(
        format!("{}", signing_failed),
        "Signing failed: test signing error"
    );

    let verification_failed = FactoryError::VerificationFailed("test verify error".to_string());
    assert_eq!(
        format!("{}", verification_failed),
        "Verification failed: test verify error"
    );

    let invalid_input = FactoryError::InvalidInput("test input error".to_string());
    assert_eq!(
        format!("{}", invalid_input),
        "Invalid input: test input error"
    );

    let cbor_error = FactoryError::CborError("test cbor error".to_string());
    assert_eq!(format!("{}", cbor_error), "CBOR error: test cbor error");

    let transparency_failed = FactoryError::TransparencyFailed("test transparency error".to_string());
    assert_eq!(
        format!("{}", transparency_failed),
        "Transparency failed: test transparency error"
    );

    let payload_too_large = FactoryError::PayloadTooLargeForEmbedding(1000, 500);
    assert_eq!(
        format!("{}", payload_too_large),
        "Payload too large for embedding: 1000 bytes (max 500)"
    );
}
