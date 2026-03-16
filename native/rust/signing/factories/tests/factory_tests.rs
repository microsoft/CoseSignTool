// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the main factory router.

use std::any::Any;
use std::sync::Arc;
use std::collections::HashMap;

use cose_sign1_factories::{
    CoseSign1MessageFactory, FactoryError, SignatureFactoryProvider,
    direct::DirectSignatureOptions,
    indirect::IndirectSignatureOptions,
};
use cose_sign1_primitives::{CoseHeaderMap, CoseSign1Message, CryptoSigner, CryptoError};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
    transparency::TransparencyProvider,
};

/// Mock key for testing
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
        // Return deterministic signature for testing
        let mut sig = data.to_vec();
        sig.extend_from_slice(b"mock-signature");
        Ok(sig)
    }
}

/// Mock signing service for testing
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
            additional_metadata: HashMap::new(),
        })
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        Ok(true) // Always pass verification for tests
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

    fn add_transparency_proof(
        &self,
        message_bytes: &[u8],
    ) -> Result<Vec<u8>, cose_sign1_signing::transparency::TransparencyError> {
        // Just return the message with a suffix for testing
        let mut result = message_bytes.to_vec();
        result.extend_from_slice(format!("-{}-proof", self.name).as_bytes());
        Ok(result)
    }

    fn verify_transparency_proof(
        &self,
        _message_bytes: &[u8],
    ) -> Result<cose_sign1_signing::transparency::TransparencyValidationResult, cose_sign1_signing::transparency::TransparencyError> {
        use cose_sign1_signing::transparency::TransparencyValidationResult;
        Ok(TransparencyValidationResult::success(&self.name))
    }
}

fn create_test_signing_service() -> Arc<MockSigningService> {
    Arc::new(MockSigningService)
}

#[test]
fn test_factory_new() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    // Factory should be created successfully
    // We can't directly test internal state but we can verify it works
    let payload = b"test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Factory should work after creation");
}

#[test]
fn test_factory_with_transparency() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("test-provider")),
    ];
    
    let factory = CoseSign1MessageFactory::with_transparency(signing_service, providers);
    
    // Test that transparency factory works
    let payload = b"test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Transparency factory should work");
}

#[test]
fn test_factory_create_direct_with_none_options() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"test payload";
    let content_type = "text/plain";
    
    let result = factory.create_direct(payload, content_type, None);
    assert!(result.is_ok(), "Should work with None options");
    
    let message = result.unwrap();
    // Default should be detached payload
    assert!(message.payload.is_none(), "Default should be detached payload");
}

#[test]
fn test_factory_create_direct_bytes_with_none_options() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"test payload";
    let content_type = "text/plain";
    
    let result = factory.create_direct_bytes(payload, content_type, None);
    assert!(result.is_ok(), "Should work with None options");
    
    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Should return non-empty bytes");
}

#[test]
fn test_factory_create_indirect_with_none_options() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"test payload for hashing";
    let content_type = "application/octet-stream";
    
    let result = factory.create_indirect(payload, content_type, None);
    assert!(result.is_ok(), "Should work with None options");
    
    let message = result.unwrap();
    // Indirect with default options should be detached
    assert!(message.payload.is_none(), "Default indirect should be detached");
}

#[test]
fn test_factory_create_indirect_bytes_with_none_options() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"test payload for hashing";
    let content_type = "application/octet-stream";
    
    let result = factory.create_indirect_bytes(payload, content_type, None);
    assert!(result.is_ok(), "Should work with None options");
    
    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Should return non-empty bytes");
}

#[test]
fn test_factory_create_direct_with_embedded_payload() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"embedded test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Should create embedded payload signature");
    
    let message = result.unwrap();
    assert!(message.payload.is_some(), "Payload should be embedded");
    assert_eq!(message.payload.unwrap(), payload);
}

#[test]
fn test_factory_create_indirect_with_embedded_hash() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"test payload for indirect with embedded hash";
    let content_type = "application/octet-stream";
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new().with_base_options(base_options);
    
    let result = factory.create_indirect(payload, content_type, Some(options));
    assert!(result.is_ok(), "Should create indirect signature with embedded hash");
    
    let message = result.unwrap();
    assert!(message.payload.is_some(), "Hash should be embedded");
}

#[test]
fn test_factory_register_custom_factory() {
    let signing_service = create_test_signing_service();
    let mut factory = CoseSign1MessageFactory::new(signing_service.clone());
    
    // Custom options type for testing
    #[derive(Debug)]
    struct TestOptions {
        #[allow(dead_code)]
        custom_field: String,
    }
    
    // Custom factory that just delegates to direct
    struct TestFactory {
        signing_service: Arc<dyn SigningService>,
    }
    
    impl SignatureFactoryProvider for TestFactory {
        fn create_bytes_dyn(
            &self,
            payload: &[u8],
            _content_type: &str,
            options: &dyn Any,
        ) -> Result<Vec<u8>, FactoryError> {
            let _opts = options
                .downcast_ref::<TestOptions>()
                .ok_or_else(|| FactoryError::InvalidInput("Expected TestOptions".to_string()))?;
            
            let context = SigningContext::from_bytes(payload.to_vec());
            let signer = self.signing_service.get_cose_signer(&context)?;
            
            let builder = cose_sign1_primitives::CoseSign1Builder::new()
                .protected(signer.protected_headers().clone())
                .unprotected(signer.unprotected_headers().clone())
                .detached(false);
            
            let message_bytes = builder.sign(signer.signer(), payload)?;
            
            // Verify signature
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
            CoseSign1Message::parse(&bytes)
                .map_err(|e| FactoryError::SigningFailed(e.to_string()))
        }
    }
    
    // Register the custom factory
    factory.register::<TestOptions>(Box::new(TestFactory {
        signing_service: signing_service.clone(),
    }));
    
    // Test using the custom factory
    let options = TestOptions {
        custom_field: "test-value".to_string(),
    };
    
    let result = factory.create_with(b"test payload", "text/plain", &options);
    assert!(result.is_ok(), "Custom factory should work");
}

#[test]
fn test_factory_create_with_unregistered_type_error_message() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    #[derive(Debug)]
    struct UnregisteredOptions;
    
    let options = UnregisteredOptions;
    let result = factory.create_with(b"test", "text/plain", &options);
    
    assert!(result.is_err());
    match result.unwrap_err() {
        FactoryError::SigningFailed(msg) => {
            assert!(msg.contains("No factory registered"));
            assert!(msg.contains("UnregisteredOptions"));
        }
        _ => panic!("Expected SigningFailed error with type name"),
    }
}

#[test]
fn test_factory_multiple_transparency_providers() {
    let signing_service = create_test_signing_service();
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("provider1")),
        Box::new(MockTransparencyProvider::new("provider2")),
        Box::new(MockTransparencyProvider::new("provider3")),
    ];
    
    let factory = CoseSign1MessageFactory::with_transparency(signing_service, providers);
    
    let payload = b"test payload";
    let content_type = "text/plain";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Should work with multiple transparency providers");
    
    // The transparency providers will be applied in sequence
    let message = result.unwrap();
    assert!(message.payload.is_some());
}

#[test]
fn test_factory_empty_payload() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = b"";
    let content_type = "application/octet-stream";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(payload, content_type, Some(options));
    assert!(result.is_ok(), "Should handle empty payload");
    
    let message = result.unwrap();
    assert!(message.payload.is_some());
    assert_eq!(message.payload.unwrap(), b"");
}

#[test]
fn test_factory_large_payload() {
    let signing_service = create_test_signing_service();
    let factory = CoseSign1MessageFactory::new(signing_service);
    
    let payload = vec![0x42; 10000]; // 10KB payload
    let content_type = "application/octet-stream";
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    
    let result = factory.create_direct(&payload, content_type, Some(options));
    assert!(result.is_ok(), "Should handle large payload");
    
    let message = result.unwrap();
    assert!(message.payload.is_some());
    assert_eq!(message.payload.unwrap(), payload);
}
