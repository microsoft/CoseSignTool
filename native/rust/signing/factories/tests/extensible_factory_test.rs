// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for extensible factory registry.

use std::any::Any;
use std::sync::Arc;

use cose_sign1_factories::{
    direct::DirectSignatureOptions, indirect::IndirectSignatureOptions, CoseSign1MessageFactory,
    FactoryError, SignatureFactoryProvider,
};
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Message, CryptoError, CryptoSigner};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
};

/// A mock key that returns deterministic signatures.
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

// Mock signing service for testing
struct MockSigningService;

impl SigningService for MockSigningService {
    fn get_cose_signer(&self, _context: &SigningContext) -> Result<CoseSigner, SigningError> {
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
            additional_metadata: std::collections::HashMap::new(),
        })
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        // Always return true for mock
        Ok(true)
    }
}

// Custom options type for testing extension
#[derive(Debug)]
struct CustomOptions {
    custom_field: String,
}

// Custom factory implementation for testing
struct CustomFactory {
    signing_service: Arc<dyn SigningService>,
}

impl CustomFactory {
    fn new(signing_service: Arc<dyn SigningService>) -> Self {
        Self { signing_service }
    }
}

impl SignatureFactoryProvider for CustomFactory {
    fn create_bytes_dyn(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &dyn Any,
    ) -> Result<Vec<u8>, FactoryError> {
        // Downcast options to CustomOptions
        let custom_opts = options
            .downcast_ref::<CustomOptions>()
            .ok_or_else(|| FactoryError::InvalidInput("Expected CustomOptions".to_string()))?;

        // For testing, just use direct signature with the custom field in AAD
        let mut context = SigningContext::from_bytes(payload.to_vec());
        context.content_type = Some(content_type.to_string());

        let signer = self.signing_service.get_cose_signer(&context)?;

        let builder = cose_sign1_primitives::CoseSign1Builder::new()
            .protected(signer.protected_headers().clone())
            .unprotected(signer.unprotected_headers().clone())
            .detached(false)
            .external_aad(custom_opts.custom_field.as_bytes().to_vec());

        let message_bytes = builder.sign(signer.signer(), payload)?;

        // Verify
        let verification_result = self
            .signing_service
            .verify_signature(&message_bytes, &context)?;

        if !verification_result {
            return Err(FactoryError::VerificationFailed(
                "Post-sign verification failed".to_string(),
            ));
        }

        Ok(message_bytes)
    }

    fn create_dyn(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &dyn Any,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes = self.create_bytes_dyn(payload, content_type, options)?;
        CoseSign1Message::parse(&bytes).map_err(|e| FactoryError::SigningFailed(e.to_string()))
    }
}

// Helper to create test signing service
fn create_test_signing_service() -> Arc<MockSigningService> {
    Arc::new(MockSigningService)
}

#[test]
fn test_backward_compatibility_direct_signature() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);

    let payload = b"Test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Direct signature should succeed");

    let message = result.unwrap();
    assert!(message.payload().is_some(), "Payload should be embedded");
}

#[test]
fn test_backward_compatibility_direct_signature_bytes() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);

    let payload = b"Test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_direct_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "Direct signature bytes should succeed");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Message bytes should not be empty");
}

#[test]
fn test_backward_compatibility_indirect_signature() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);

    let payload = b"Test payload for indirect signature";
    let content_type = "application/octet-stream";
    // Explicitly set embed_payload to true on the base options
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new().with_base_options(base_options);

    let result = factory.create_indirect(payload, content_type, Some(options));
    assert!(result.is_ok(), "Indirect signature should succeed");

    let message = result.unwrap();
    // For indirect signatures with embed_payload=true, the hash payload is embedded
    assert!(
        message.payload().is_some(),
        "Hash payload should be embedded"
    );
}

#[test]
fn test_backward_compatibility_indirect_signature_bytes() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);

    let payload = b"Test payload for indirect signature";
    let content_type = "application/octet-stream";
    let options = IndirectSignatureOptions::new();

    let result = factory.create_indirect_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "Indirect signature bytes should succeed");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Message bytes should not be empty");
}

#[test]
fn test_register_and_use_custom_factory() {
    let signing_service = create_test_signing_service();
    let mut factory = CoseSign1MessageFactory::new(signing_service.clone());

    // Register custom factory
    let custom_factory = CustomFactory::new(signing_service);
    factory.register::<CustomOptions>(Box::new(custom_factory));

    // Use custom factory
    let payload = b"Custom payload";
    let content_type = "application/custom";
    let options = CustomOptions {
        custom_field: "test-value".to_string(),
    };

    let result = factory.create_with(payload, content_type, &options);
    assert!(
        result.is_ok(),
        "Custom factory creation should succeed: {:?}",
        result.err()
    );

    let message = result.unwrap();
    assert!(message.payload().is_some(), "Payload should be present");
}

#[test]
fn test_create_with_unregistered_type_fails() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);

    // Try to use an unregistered type
    let payload = b"Test payload";
    let content_type = "text/plain";
    let options = CustomOptions {
        custom_field: "test".to_string(),
    };

    let result = factory.create_with(payload, content_type, &options);
    assert!(
        result.is_err(),
        "Should fail with unregistered factory type"
    );

    match result.unwrap_err() {
        FactoryError::SigningFailed(msg) => {
            assert!(
                msg.contains("No factory registered"),
                "Error should mention unregistered factory"
            );
        }
        _ => panic!("Expected SigningFailed error"),
    }
}

#[test]
fn test_multiple_custom_factories() {
    let signing_service = create_test_signing_service();
    let mut factory = CoseSign1MessageFactory::new(signing_service.clone());

    // Register first custom factory
    factory.register::<CustomOptions>(Box::new(CustomFactory::new(signing_service.clone())));

    // Define a second custom options type
    #[derive(Debug)]
    struct AnotherCustomOptions {
        #[allow(dead_code)]
        another_field: i32,
    }

    // Register second custom factory (reusing CustomFactory for simplicity)
    factory.register::<AnotherCustomOptions>(Box::new(CustomFactory::new(signing_service)));

    // Both should work independently
    let options1 = CustomOptions {
        custom_field: "first".to_string(),
    };
    let result1 = factory.create_with(b"payload1", "type1", &options1);
    assert!(result1.is_ok(), "First custom factory should work");

    let options2 = AnotherCustomOptions { another_field: 42 };
    let result2 = factory.create_with(b"payload2", "type2", &options2);
    // This will fail because CustomFactory expects CustomOptions, but that's
    // expected behavior - it demonstrates type safety
    assert!(
        result2.is_err(),
        "Second factory with wrong options should fail"
    );
}
