// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for IndirectSignatureFactory happy path scenarios.

use std::collections::HashMap;
use std::sync::Arc;

use cose_sign1_factories::{
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{HashAlgorithm, IndirectSignatureFactory, IndirectSignatureOptions},
};
use cose_sign1_primitives::{
    CoseHeaderMap, CoseSign1Message, CryptoSigner, CryptoError, MemoryPayload,
};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
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

fn create_test_signing_service() -> Arc<MockSigningService> {
    Arc::new(MockSigningService)
}

#[test]
fn test_indirect_factory_new() {
    let signing_service = create_test_signing_service();
    let direct_factory = DirectSignatureFactory::new(signing_service);
    let indirect_factory = IndirectSignatureFactory::new(direct_factory);

    // Factory should be created successfully
    // Test by accessing the direct factory
    assert_eq!(
        indirect_factory.direct_factory().transparency_providers().len(),
        0
    );
}

#[test]
fn test_indirect_factory_from_signing_service() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    // Should create internal direct factory
    assert_eq!(
        indirect_factory.direct_factory().transparency_providers().len(),
        0
    );
}

#[test]
fn test_indirect_factory_direct_factory_accessor() {
    let signing_service = create_test_signing_service();
    let direct_factory = DirectSignatureFactory::new(signing_service.clone());
    let indirect_factory = IndirectSignatureFactory::new(direct_factory);

    // Should be able to access the direct factory
    let direct = indirect_factory.direct_factory();
    assert_eq!(direct.transparency_providers().len(), 0);
}

#[test]
fn test_indirect_factory_create_bytes_none_options() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload for hashing";
    let content_type = "application/pdf";

    let result = indirect_factory.create_bytes(payload, content_type, None);
    assert!(
        result.is_ok(),
        "create_bytes should succeed with None options"
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse the message and verify it's detached by default
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    assert!(
        message.payload().is_none(),
        "Default indirect should be detached (no embedded payload)"
    );
}

#[test]
fn test_indirect_factory_create_bytes_sha256() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload for SHA256 hashing";
    let content_type = "text/plain";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha256);

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "create_bytes should succeed with SHA256");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse and verify the message contains hash envelope headers
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    // The payload should be the hash (detached by default), so no payload in parsed message
    assert!(message.payload().is_none(), "Should be detached signature");
}

#[test]
fn test_indirect_factory_create_bytes_sha384() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload for SHA384 hashing";
    let content_type = "application/json";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha384);

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "create_bytes should succeed with SHA384");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_indirect_factory_create_bytes_sha512() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload for SHA512 hashing";
    let content_type = "application/xml";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha512);

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "create_bytes should succeed with SHA512");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_indirect_factory_create_bytes_with_payload_location() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload with location";
    let content_type = "application/octet-stream";
    let options = IndirectSignatureOptions::new()
        .with_payload_location("https://example.com/payload.bin".to_string());

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "create_bytes should succeed with payload location");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_indirect_factory_create_bytes_with_embedded_hash() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload with embedded hash";
    let content_type = "text/plain";
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new().with_base_options(base_options);

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_bytes should succeed with embedded hash"
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse the message and verify hash is embedded
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    assert!(
        message.payload().is_some(),
        "Hash payload should be embedded when embed_payload=true"
    );
    // The payload should be the hash of the original payload, not the original payload
    let hash_payload = message.payload().unwrap();
    assert_ne!(hash_payload, payload, "Embedded payload should be hash, not original");
    // SHA256 hash should be 32 bytes
    assert_eq!(hash_payload.len(), 32, "SHA256 hash should be 32 bytes");
}

#[test]
fn test_indirect_factory_create() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test payload for create method";
    let content_type = "application/octet-stream";
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new().with_base_options(base_options);

    let result = indirect_factory.create(payload, content_type, Some(options));
    assert!(result.is_ok(), "create should succeed");

    let message = result.unwrap();
    assert!(
        message.payload().is_some(),
        "Message should have embedded hash payload"
    );
    // Verify it's a hash, not the original payload
    let hash_payload = message.payload().unwrap();
    assert_ne!(hash_payload, payload);
    assert_eq!(hash_payload.len(), 32); // SHA256
}

#[test]
fn test_indirect_factory_create_streaming_bytes() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload_data = b"Streaming test payload for indirect signature";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "application/octet-stream";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha384);

    let result = indirect_factory.create_streaming_bytes(streaming_payload, content_type, Some(options));
    assert!(
        result.is_ok(),
        "create_streaming_bytes should succeed: {:?}",
        result.err()
    );

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");

    // Parse and verify
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    // Should be detached by default
    assert!(message.payload().is_none(), "Should be detached by default");
}

#[test]
fn test_indirect_factory_create_streaming_bytes_sha256() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload_data = b"Test streaming SHA256";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "text/plain";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha256);

    let result = indirect_factory.create_streaming_bytes(streaming_payload, content_type, Some(options));
    assert!(result.is_ok(), "create_streaming_bytes SHA256 should succeed");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_indirect_factory_create_streaming_bytes_sha512() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload_data = b"Test streaming SHA512";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "application/binary";
    let options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha512);

    let result = indirect_factory.create_streaming_bytes(streaming_payload, content_type, Some(options));
    assert!(result.is_ok(), "create_streaming_bytes SHA512 should succeed");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result bytes should not be empty");
}

#[test]
fn test_indirect_factory_create_streaming() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload_data = b"Another streaming test for create method";
    let streaming_payload = Arc::new(MemoryPayload::from(payload_data.to_vec()));
    let content_type = "text/plain";
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new()
        .with_base_options(base_options)
        .with_hash_algorithm(HashAlgorithm::Sha384);

    let result = indirect_factory.create_streaming(streaming_payload, content_type, Some(options));
    assert!(result.is_ok(), "create_streaming should succeed");

    let message = result.unwrap();
    assert!(
        message.payload().is_some(),
        "Message should have embedded hash payload"
    );
    // Verify it's a SHA384 hash (48 bytes)
    let hash_payload = message.payload().unwrap();
    assert_eq!(hash_payload.len(), 48, "SHA384 hash should be 48 bytes");
}

#[test]
fn test_indirect_factory_with_all_hash_algorithms() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Test all hash algorithms";
    let content_type = "application/test";

    // Test SHA256
    let sha256_options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha256);
    let sha256_result = indirect_factory.create_bytes(payload, content_type, Some(sha256_options));
    assert!(sha256_result.is_ok(), "SHA256 should work");

    // Test SHA384
    let sha384_options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha384);
    let sha384_result = indirect_factory.create_bytes(payload, content_type, Some(sha384_options));
    assert!(sha384_result.is_ok(), "SHA384 should work");

    // Test SHA512
    let sha512_options = IndirectSignatureOptions::new().with_hash_algorithm(HashAlgorithm::Sha512);
    let sha512_result = indirect_factory.create_bytes(payload, content_type, Some(sha512_options));
    assert!(sha512_result.is_ok(), "SHA512 should work");

    // All results should be different (different hash algorithms)
    let sha256_bytes = sha256_result.unwrap();
    let sha384_bytes = sha384_result.unwrap();
    let sha512_bytes = sha512_result.unwrap();

    assert_ne!(sha256_bytes, sha384_bytes);
    assert_ne!(sha256_bytes, sha512_bytes);
    assert_ne!(sha384_bytes, sha512_bytes);
}

#[test]
fn test_indirect_factory_complex_options() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"Complex options test payload";
    let content_type = "application/custom";

    // Create complex options with base DirectSignatureOptions
    let base_options = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_additional_data(b"additional authenticated data".to_vec());

    let options = IndirectSignatureOptions::new()
        .with_base_options(base_options)
        .with_hash_algorithm(HashAlgorithm::Sha512)
        .with_payload_location("https://example.com/complex-payload".to_string());

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "Complex options should work");

    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "Result should not be empty");

    // Parse and verify
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    assert!(message.payload().is_some(), "Hash should be embedded");
    
    // SHA512 hash should be 64 bytes
    let hash_payload = message.payload().unwrap();
    assert_eq!(hash_payload.len(), 64, "SHA512 hash should be 64 bytes");
}

#[test]
fn test_indirect_factory_empty_payload() {
    let signing_service = create_test_signing_service();
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);

    let payload = b"";
    let content_type = "application/octet-stream";
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new().with_base_options(base_options);

    let result = indirect_factory.create_bytes(payload, content_type, Some(options));
    assert!(result.is_ok(), "Should handle empty payload");

    let bytes = result.unwrap();
    let message = CoseSign1Message::parse(&bytes).expect("Should parse successfully");
    
    assert!(message.payload().is_some(), "Hash should be embedded");
    // SHA256 hash of empty bytes
    let hash_payload = message.payload().unwrap();
    assert_eq!(hash_payload.len(), 32, "SHA256 hash should be 32 bytes even for empty payload");
}
