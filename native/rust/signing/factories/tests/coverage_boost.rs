// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Targeted coverage tests for cose_sign1_factories.
//!
//! Covers uncovered lines:
//! - factory.rs L206-267: CoseSign1MessageFactory streaming router methods
//! - indirect/factory.rs L145,L147: IndirectSignatureFactory::create
//! - indirect/factory.rs L179,L187,L200,L213: streaming Sha384/Sha512 paths
//! - indirect/factory.rs L265,L267: IndirectSignatureFactory::create_streaming
//! - indirect/hash_envelope_contributor.rs L44-46: merge_strategy()
//! - direct/factory.rs L67,L78,L109,L114: create_bytes logging/embed paths

use std::collections::HashMap;
use std::sync::Arc;

use cose_sign1_factories::{
    CoseSign1MessageFactory, FactoryError, SignatureFactoryProvider,
    direct::{DirectSignatureFactory, DirectSignatureOptions},
    indirect::{
        HashAlgorithm, HashEnvelopeHeaderContributor, IndirectSignatureFactory,
        IndirectSignatureOptions,
    },
};
use cose_sign1_primitives::{
    CoseHeaderMap, CoseSign1Message, CryptoError, CryptoSigner, MemoryPayload,
};
use cose_sign1_signing::{
    CoseSigner, HeaderMergeStrategy, HeaderContributor, SigningContext, SigningError,
    SigningService, SigningServiceMetadata,
};

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockKey;

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"coverage-key")
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sig: Vec<u8> = data.to_vec();
        sig.extend_from_slice(b"-sig");
        Ok(sig)
    }
}

struct MockSigningService;

impl SigningService for MockSigningService {
    fn get_cose_signer(&self, _ctx: &SigningContext) -> Result<CoseSigner, SigningError> {
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
        static META: OnceLock<SigningServiceMetadata> = OnceLock::new();
        META.get_or_init(|| SigningServiceMetadata {
            service_name: "CoverageMockService".to_string(),
            service_description: "mock".to_string(),
            additional_metadata: HashMap::new(),
        })
    }
    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &SigningContext,
    ) -> Result<bool, SigningError> {
        Ok(true)
    }
}

fn mock_service() -> Arc<dyn SigningService> {
    Arc::new(MockSigningService)
}

// ---------------------------------------------------------------------------
// CoseSign1MessageFactory streaming router tests (factory.rs L206-L267)
// ---------------------------------------------------------------------------

/// Exercises create_direct_streaming (factory.rs L206-L215).
#[test]
fn router_create_direct_streaming() {
    let factory = CoseSign1MessageFactory::new(mock_service());
    let payload = Arc::new(MemoryPayload::from(b"stream-direct".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result: Result<CoseSign1Message, FactoryError> =
        factory.create_direct_streaming(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "create_direct_streaming failed: {:?}", result.err());
}

/// Exercises create_direct_streaming_bytes (factory.rs L224-L233).
#[test]
fn router_create_direct_streaming_bytes() {
    let factory = CoseSign1MessageFactory::new(mock_service());
    let payload = Arc::new(MemoryPayload::from(b"stream-direct-bytes".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_direct_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "create_direct_streaming_bytes failed: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

/// Exercises create_indirect_streaming (factory.rs L242-L250).
#[test]
fn router_create_indirect_streaming() {
    let factory = CoseSign1MessageFactory::new(mock_service());
    let payload = Arc::new(MemoryPayload::from(b"stream-indirect".to_vec()));
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new().with_base_options(base);

    let result: Result<CoseSign1Message, FactoryError> =
        factory.create_indirect_streaming(payload, "application/octet-stream", Some(opts));
    assert!(result.is_ok(), "create_indirect_streaming failed: {:?}", result.err());
}

/// Exercises create_indirect_streaming_bytes (factory.rs L259-L267).
#[test]
fn router_create_indirect_streaming_bytes() {
    let factory = CoseSign1MessageFactory::new(mock_service());
    let payload = Arc::new(MemoryPayload::from(b"stream-indirect-bytes".to_vec()));
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new().with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_indirect_streaming_bytes(payload, "application/octet-stream", Some(opts));
    assert!(result.is_ok(), "create_indirect_streaming_bytes failed: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// IndirectSignatureFactory::create (indirect/factory.rs L145, L147)
// ---------------------------------------------------------------------------

/// Exercises IndirectSignatureFactory::create which parses bytes to CoseSign1Message.
#[test]
fn indirect_factory_create_returns_message() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new().with_base_options(base);

    let result: Result<CoseSign1Message, FactoryError> =
        factory.create(b"indirect-create-test", "text/plain", Some(opts));
    assert!(result.is_ok(), "indirect create failed: {:?}", result.err());
    assert!(result.unwrap().payload.is_some());
}

// ---------------------------------------------------------------------------
// IndirectSignatureFactory streaming with Sha384/Sha512
// (indirect/factory.rs L179, L187, L195-L206, L208-L220)
// ---------------------------------------------------------------------------

/// Exercises streaming Sha384 hash path (indirect/factory.rs ~L195-L206).
#[test]
fn indirect_streaming_sha384() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let payload = Arc::new(MemoryPayload::from(b"sha384-stream".to_vec()));
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha384)
        .with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "sha384 streaming failed: {:?}", result.err());
}

/// Exercises streaming Sha512 hash path (indirect/factory.rs ~L208-L220).
#[test]
fn indirect_streaming_sha512() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let payload = Arc::new(MemoryPayload::from(b"sha512-stream".to_vec()));
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha512)
        .with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "sha512 streaming failed: {:?}", result.err());
}

/// Exercises IndirectSignatureFactory::create_streaming (indirect/factory.rs L265, L267).
#[test]
fn indirect_create_streaming_returns_message() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let payload = Arc::new(MemoryPayload::from(b"streaming-msg".to_vec()));
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new().with_base_options(base);

    let result: Result<CoseSign1Message, FactoryError> =
        factory.create_streaming(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "create_streaming failed: {:?}", result.err());
}

// ---------------------------------------------------------------------------
// Non-default hash algorithms for the non-streaming indirect path
// (indirect/factory.rs L84-L93)
// ---------------------------------------------------------------------------

/// Exercises Sha384 hash for non-streaming indirect create_bytes.
#[test]
fn indirect_create_bytes_sha384() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha384)
        .with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_bytes(b"sha384-payload", "text/plain", Some(opts));
    assert!(result.is_ok(), "sha384 create_bytes failed: {:?}", result.err());
}

/// Exercises Sha512 hash for non-streaming indirect create_bytes.
#[test]
fn indirect_create_bytes_sha512() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new()
        .with_hash_algorithm(HashAlgorithm::Sha512)
        .with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_bytes(b"sha512-payload", "text/plain", Some(opts));
    assert!(result.is_ok(), "sha512 create_bytes failed: {:?}", result.err());
}

// ---------------------------------------------------------------------------
// HashEnvelopeHeaderContributor::merge_strategy (L44-46)
// ---------------------------------------------------------------------------

/// Exercises the merge_strategy method on HashEnvelopeHeaderContributor.
#[test]
fn hash_envelope_contributor_merge_strategy_is_replace() {
    let contributor = HashEnvelopeHeaderContributor::new(
        HashAlgorithm::Sha256,
        "text/plain",
        None,
    );
    assert_eq!(contributor.merge_strategy(), HeaderMergeStrategy::Replace);
}

/// Exercises hash envelope contributor with payload location.
#[test]
fn hash_envelope_contributor_with_payload_location() {
    let contributor = HashEnvelopeHeaderContributor::new(
        HashAlgorithm::Sha256,
        "application/json",
        Some("https://example.com/payload".to_string()),
    );
    assert_eq!(contributor.merge_strategy(), HeaderMergeStrategy::Replace);
}

// ---------------------------------------------------------------------------
// IndirectSignatureOptions with payload_location
// ---------------------------------------------------------------------------

/// Exercises the payload_location option for indirect signatures.
#[test]
fn indirect_with_payload_location() {
    let svc = mock_service();
    let factory = IndirectSignatureFactory::from_signing_service(svc);
    let base = DirectSignatureOptions::new().with_embed_payload(true);
    let opts = IndirectSignatureOptions::new()
        .with_payload_location("https://example.com/blob")
        .with_base_options(base);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_bytes(b"with-location", "text/plain", Some(opts));
    assert!(result.is_ok(), "payload_location create_bytes failed: {:?}", result.err());
}

// ---------------------------------------------------------------------------
// Direct factory with additional AAD (direct/factory.rs L104-L106)
// ---------------------------------------------------------------------------

/// Exercises the additional_data path in direct factory's create_bytes.
#[test]
fn direct_factory_with_additional_data() {
    let svc = mock_service();
    let factory = DirectSignatureFactory::new(svc);
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_additional_data(b"extra-aad".to_vec());

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_bytes(b"payload-with-aad", "text/plain", Some(opts));
    assert!(result.is_ok(), "aad create_bytes failed: {:?}", result.err());
}

/// Exercises direct factory create_bytes with detached payload (embed_payload = false).
#[test]
fn direct_factory_detached_payload() {
    let svc = mock_service();
    let factory = DirectSignatureFactory::new(svc);
    let opts = DirectSignatureOptions::new().with_embed_payload(false);

    let result: Result<Vec<u8>, FactoryError> =
        factory.create_bytes(b"detached-payload", "text/plain", Some(opts));
    assert!(result.is_ok(), "detached create_bytes failed: {:?}", result.err());
}

/// Exercises direct factory create (not create_bytes) returning CoseSign1Message.
#[test]
fn direct_factory_create_returns_message() {
    let svc = mock_service();
    let factory = DirectSignatureFactory::new(svc);
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result: Result<CoseSign1Message, FactoryError> =
        factory.create(b"direct-msg", "text/plain", Some(opts));
    assert!(result.is_ok(), "direct create failed: {:?}", result.err());
}

// ---------------------------------------------------------------------------
// Router create_with with a custom factory (factory.rs create_with/register)
// Already partially covered in extensible_factory_test.rs, but we test
// the create_bytes_dyn path specifically.
// ---------------------------------------------------------------------------

struct SimpleCustomFactory;

impl SignatureFactoryProvider for SimpleCustomFactory {
    fn create_bytes_dyn(
        &self,
        payload: &[u8],
        _content_type: &str,
        _options: &dyn std::any::Any,
    ) -> Result<Vec<u8>, FactoryError> {
        // Return a trivially "signed" payload for coverage
        Ok(payload.to_vec())
    }

    fn create_dyn(
        &self,
        payload: &[u8],
        content_type: &str,
        options: &dyn std::any::Any,
    ) -> Result<CoseSign1Message, FactoryError> {
        let bytes: Vec<u8> = self.create_bytes_dyn(payload, content_type, options)?;
        // This will fail to parse as valid COSE, which is fine — we test the error path
        CoseSign1Message::parse(&bytes)
            .map_err(|e| FactoryError::SigningFailed(e.to_string()))
    }
}

struct CustomOpts;

/// Exercises create_with path where factory create_dyn delegates correctly.
#[test]
fn router_create_with_custom_factory_invoked() {
    let mut factory = CoseSign1MessageFactory::new(mock_service());
    factory.register::<CustomOpts>(Box::new(SimpleCustomFactory));

    let opts = CustomOpts;
    // create_with invokes create_dyn which will fail parse (our mock returns raw bytes),
    // but the factory dispatch itself succeeds — that's what we're testing
    let result: Result<CoseSign1Message, FactoryError> =
        factory.create_with(b"custom-payload", "text/plain", &opts);
    // The create_dyn from SimpleCustomFactory will try to parse raw bytes as COSE — expect err
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// FactoryError Display coverage
// ---------------------------------------------------------------------------

/// Exercises Display on all FactoryError variants.
#[test]
fn factory_error_display_variants() {
    let e1 = FactoryError::SigningFailed("sign err".to_string());
    assert!(format!("{}", e1).contains("Signing failed"));

    let e2 = FactoryError::VerificationFailed("verify err".to_string());
    assert!(format!("{}", e2).contains("Verification failed"));

    let e3 = FactoryError::InvalidInput("bad input".to_string());
    assert!(format!("{}", e3).contains("Invalid input"));

    let e4 = FactoryError::CborError("cbor err".to_string());
    assert!(format!("{}", e4).contains("CBOR error"));

    let e5 = FactoryError::TransparencyFailed("tp err".to_string());
    assert!(format!("{}", e5).contains("Transparency failed"));

    let e6 = FactoryError::PayloadTooLargeForEmbedding(200, 100);
    assert!(format!("{}", e6).contains("too large"));
}
