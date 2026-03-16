// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for direct and indirect signature factories.

use std::sync::Arc;
use std::collections::HashMap;

use cose_sign1_factories::{
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{IndirectSignatureFactory, IndirectSignatureOptions, HashAlgorithm},
};
use cose_sign1_primitives::{CoseHeaderMap, CryptoSigner, CryptoError, StreamingPayload};
use cose_sign1_signing::{
    CoseSigner, SigningContext, SigningError, SigningService, SigningServiceMetadata,
    transparency::TransparencyProvider,
};

/// Mock key for testing
#[derive(Clone)]
struct MockKey;

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"test-key")
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Return predictable signature
        let mut sig = b"signature-".to_vec();
        sig.extend_from_slice(&data[..std::cmp::min(data.len(), 10)]);
        Ok(sig)
    }
}

/// Mock signing service
struct MockSigningService {
    verification_result: bool,
}

impl MockSigningService {
    fn new() -> Self {
        Self { verification_result: true }
    }
    
    #[allow(dead_code)]
    fn with_verification_result(verification_result: bool) -> Self {
        Self { verification_result }
    }
}

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
            service_description: "Mock service for testing".to_string(),
            additional_metadata: HashMap::new(),
        })
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        Ok(self.verification_result)
    }
}

/// Mock transparency provider
struct MockTransparencyProvider {
    name: String,
    should_fail: bool,
}

impl MockTransparencyProvider {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            should_fail: false,
        }
    }
    
    #[allow(dead_code)]
    fn new_failing(name: &str) -> Self {
        Self {
            name: name.to_string(),
            should_fail: true,
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
        use cose_sign1_signing::transparency::TransparencyError;
        if self.should_fail {
            Err(TransparencyError::SubmissionFailed(format!("{} transparency failed", self.name)))
        } else {
            let mut result = message_bytes.to_vec();
            result.extend_from_slice(format!("-{}", self.name).as_bytes());
            Ok(result)
        }
    }

    fn verify_transparency_proof(
        &self,
        _message_bytes: &[u8],
    ) -> Result<cose_sign1_signing::transparency::TransparencyValidationResult, cose_sign1_signing::transparency::TransparencyError> {
        use cose_sign1_signing::transparency::TransparencyValidationResult;
        Ok(TransparencyValidationResult::success(&self.name))
    }
}

/// Mock streaming payload
#[allow(dead_code)]
struct MockStreamingPayload {
    data: Vec<u8>,
    should_fail_open: bool,
    should_fail_read: bool,
}

impl MockStreamingPayload {
    #[allow(dead_code)]
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            should_fail_open: false,
            should_fail_read: false,
        }
    }
    
    #[allow(dead_code)]
    fn new_with_open_failure(data: Vec<u8>) -> Self {
        Self {
            data,
            should_fail_open: true,
            should_fail_read: false,
        }
    }
    
    #[allow(dead_code)]
    fn new_with_read_failure(data: Vec<u8>) -> Self {
        Self {
            data,
            should_fail_open: false,
            should_fail_read: true,
        }
    }
}

impl StreamingPayload for MockStreamingPayload {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn open(&self) -> Result<Box<dyn cose_sign1_primitives::SizedRead + Send>, cose_sign1_primitives::PayloadError> {
        use cose_sign1_primitives::PayloadError;
        if self.should_fail_open {
            Err(PayloadError::OpenFailed("Failed to open stream".to_string()))
        } else if self.should_fail_read {
            // Return a reader that will fail on read
            Ok(Box::new(cose_sign1_primitives::SizedReader::new(
                FailingReader,
                self.data.len() as u64
            )))
        } else {
            Ok(Box::new(std::io::Cursor::new(self.data.clone())))
        }
    }
}

#[allow(dead_code)]
struct FailingReader;

impl std::io::Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, "Read failed"))
    }
}

// Direct Factory Tests

#[test]
fn test_direct_factory_new() {
    let signing_service = Arc::new(MockSigningService::new());
    let factory = DirectSignatureFactory::new(signing_service);
    
    // Verify no transparency providers by default
    assert_eq!(factory.transparency_providers().len(), 0);
}

#[test]
fn test_direct_factory_with_transparency_providers() {
    let signing_service = Arc::new(MockSigningService::new());
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("provider1")),
        Box::new(MockTransparencyProvider::new("provider2")),
    ];
    
    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);
    
    // Verify transparency providers are stored
    assert_eq!(factory.transparency_providers().len(), 2);
}

#[test]
fn test_direct_factory_transparency_providers_access() {
    let signing_service = Arc::new(MockSigningService::new());
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparencyProvider::new("test-provider")),
    ];
    
    let factory = DirectSignatureFactory::with_transparency_providers(signing_service, providers);
    let providers = factory.transparency_providers();
    
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0].provider_name(), "test-provider");
}

// Indirect Factory Tests

#[test]
fn test_indirect_factory_new() {
    let signing_service = Arc::new(MockSigningService::new());
    let direct_factory = DirectSignatureFactory::new(signing_service);
    let indirect_factory = IndirectSignatureFactory::new(direct_factory);
    
    // Should be able to access the direct factory
    let _direct_ref = indirect_factory.direct_factory();
}

#[test]
fn test_indirect_factory_from_signing_service() {
    let signing_service = Arc::new(MockSigningService::new());
    let indirect_factory = IndirectSignatureFactory::from_signing_service(signing_service);
    
    // Should work as expected
    let _direct_ref = indirect_factory.direct_factory();
}

#[test]
fn test_indirect_factory_direct_factory_access() {
    let signing_service = Arc::new(MockSigningService::new());
    let direct_factory = DirectSignatureFactory::new(signing_service);
    let indirect_factory = IndirectSignatureFactory::new(direct_factory);
    
    let direct_ref = indirect_factory.direct_factory();
    assert_eq!(direct_ref.transparency_providers().len(), 0);
}

#[test]
fn test_indirect_signature_options_default() {
    let options = IndirectSignatureOptions::default();
    
    // Check default values
    assert_eq!(options.payload_hash_algorithm, HashAlgorithm::Sha256);
    assert_eq!(options.payload_location, None);
    
    // Base options should have reasonable defaults
    assert_eq!(options.base.embed_payload, false);
}

#[test]
fn test_indirect_signature_options_with_sha384() {
    let options = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha384);
    
    assert_eq!(options.payload_hash_algorithm, HashAlgorithm::Sha384);
}

#[test]
fn test_indirect_signature_options_with_sha512() {
    let options = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha512);
    
    assert_eq!(options.payload_hash_algorithm, HashAlgorithm::Sha512);
}

#[test]
fn test_indirect_signature_options_with_payload_location() {
    let location = "https://example.com/payload";
    let options = IndirectSignatureOptions::new()
        .with_payload_location(location.to_string());
    
    assert_eq!(options.payload_location, Some(location.to_string()));
}

#[test]
fn test_indirect_signature_options_with_base_options() {
    let base_options = DirectSignatureOptions::new().with_embed_payload(true);
    let options = IndirectSignatureOptions::new()
        .with_base_options(base_options);
    
    assert_eq!(options.base.embed_payload, true);
}

#[test]
fn test_direct_signature_options_new() {
    let options = DirectSignatureOptions::new();
    
    // Check defaults
    assert_eq!(options.embed_payload, true);
    assert!(options.additional_header_contributors.is_empty());
}

#[test]
fn test_direct_signature_options_with_embed_payload() {
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    assert_eq!(options.embed_payload, true);
    
    let options = DirectSignatureOptions::new().with_embed_payload(false);
    assert_eq!(options.embed_payload, false);
}

#[test]
fn test_hash_algorithm_debug() {
    // Test Debug implementation for HashAlgorithm
    assert_eq!(format!("{:?}", HashAlgorithm::Sha256), "Sha256");
    assert_eq!(format!("{:?}", HashAlgorithm::Sha384), "Sha384");
    assert_eq!(format!("{:?}", HashAlgorithm::Sha512), "Sha512");
}

#[test]
fn test_hash_algorithm_partial_eq() {
    // Test PartialEq implementation
    assert_eq!(HashAlgorithm::Sha256, HashAlgorithm::Sha256);
    assert_ne!(HashAlgorithm::Sha256, HashAlgorithm::Sha384);
    assert_ne!(HashAlgorithm::Sha384, HashAlgorithm::Sha512);
}

#[test]
fn test_hash_algorithm_clone() {
    // Test Clone implementation
    let algo = HashAlgorithm::Sha256;
    let cloned = algo.clone();
    assert_eq!(algo, cloned);
}


#[test]
fn test_indirect_signature_options_debug() {
    let options = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha512);
    
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("Sha512"));
}

#[test]
fn test_direct_signature_options_debug() {
    let options = DirectSignatureOptions::new().with_embed_payload(true);
    let debug_str = format!("{:?}", options);
    assert!(debug_str.contains("embed_payload"));
}
