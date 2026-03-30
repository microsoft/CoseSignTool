// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for cose_sign1_factories direct/factory.rs.
//!
//! Targets uncovered lines in direct/factory.rs:
//! - create() parsing path (lines 158-160)
//! - create_streaming_bytes with embed payload (lines 201-236)
//! - create_streaming_bytes with additional AAD (lines 231-232)
//! - create_streaming_bytes with custom header contributors (lines 214-217)
//! - create_streaming_bytes with max_embed_size (lines 226-228)
//! - create_streaming_bytes post-sign verification failure (lines 243-246)
//! - create_streaming_bytes with transparency providers (lines 250-262)
//! - create_streaming_bytes with transparency disabled (lines 251-252)
//! - create_streaming with parse (lines 285-287)
//! - create_bytes with additional AAD (lines 104-106)
//! - create_bytes with additional header contributors (lines 92-95)

use std::collections::HashMap;
use std::sync::Arc;

use cose_sign1_factories::direct::{DirectSignatureFactory, DirectSignatureOptions};
use cose_sign1_factories::FactoryError;
use cose_sign1_primitives::{
    CoseHeaderMap, CoseHeaderValue, CoseSign1Message, CryptoError, CryptoSigner, MemoryPayload,
};
use cose_sign1_signing::{
    CoseSigner, HeaderContributor, HeaderContributorContext, HeaderMergeStrategy,
    SigningContext, SigningError, SigningService, SigningServiceMetadata,
    transparency::{TransparencyError, TransparencyProvider, TransparencyValidationResult},
};

// ---------------------------------------------------------------------------
// Mock types
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockKey;

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"deep-test-key")
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sig = data.to_vec();
        sig.extend_from_slice(b"mock-sig");
        Ok(sig)
    }
}

struct TestSigningService {
    fail_signer: bool,
    fail_verify: bool,
}

impl TestSigningService {
    fn ok() -> Self {
        Self {
            fail_signer: false,
            fail_verify: false,
        }
    }
    fn verify_fails() -> Self {
        Self {
            fail_signer: false,
            fail_verify: true,
        }
    }
}

impl SigningService for TestSigningService {
    fn get_cose_signer(&self, _ctx: &SigningContext) -> Result<CoseSigner, SigningError> {
        if self.fail_signer {
            return Err(SigningError::SigningFailed("mock fail".into()));
        }
        Ok(CoseSigner::new(
            Box::new(MockKey),
            CoseHeaderMap::new(),
            CoseHeaderMap::new(),
        ))
    }

    fn is_remote(&self) -> bool {
        false
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        use std::sync::OnceLock;
        static META: OnceLock<SigningServiceMetadata> = OnceLock::new();
        META.get_or_init(|| SigningServiceMetadata {
            service_name: "TestSigningService".into(),
            service_description: "for deep factory tests".into(),
            additional_metadata: HashMap::new(),
        })
    }

    fn verify_signature(&self, _bytes: &[u8], _ctx: &SigningContext) -> Result<bool, SigningError> {
        Ok(!self.fail_verify)
    }
}

/// A header contributor that adds a custom integer header.
struct CustomHeaderContributor {
    label: i64,
    value: i64,
}

impl HeaderContributor for CustomHeaderContributor {
    fn merge_strategy(&self) -> HeaderMergeStrategy {
        HeaderMergeStrategy::Replace
    }
    fn contribute_protected_headers(
        &self,
        headers: &mut CoseHeaderMap,
        _ctx: &HeaderContributorContext,
    ) {
        headers.insert(
            cose_sign1_primitives::CoseHeaderLabel::Int(self.label),
            CoseHeaderValue::Int(self.value),
        );
    }
    fn contribute_unprotected_headers(
        &self,
        _headers: &mut CoseHeaderMap,
        _ctx: &HeaderContributorContext,
    ) {
    }
}

/// Mock transparency provider.
struct MockTransparency {
    name: String,
}

impl MockTransparency {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }
}

impl TransparencyProvider for MockTransparency {
    fn provider_name(&self) -> &str {
        &self.name
    }
    fn add_transparency_proof(&self, message_bytes: &[u8]) -> Result<Vec<u8>, TransparencyError> {
        let mut out = message_bytes.to_vec();
        out.extend_from_slice(format!("-{}-proof", self.name).as_bytes());
        Ok(out)
    }
    fn verify_transparency_proof(
        &self,
        _bytes: &[u8],
    ) -> Result<TransparencyValidationResult, TransparencyError> {
        Ok(TransparencyValidationResult::success(&self.name))
    }
}

fn service() -> Arc<TestSigningService> {
    Arc::new(TestSigningService::ok())
}

// =========================================================================
// create_bytes with additional header contributors (lines 92-95)
// =========================================================================

#[test]
fn create_bytes_with_additional_header_contributor() {
    let factory = DirectSignatureFactory::new(service());
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .add_header_contributor(Box::new(CustomHeaderContributor {
            label: 99,
            value: 42,
        }));

    let result = factory.create_bytes(b"payload", "text/plain", Some(opts));
    assert!(result.is_ok(), "create_bytes with contributor: {:?}", result.err());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).unwrap();

    // Verify our custom header was applied.
    let label = cose_sign1_primitives::CoseHeaderLabel::Int(99);
    let val = msg.protected.headers().get(&label);
    assert!(val.is_some(), "custom header 99 should be present");
}

// =========================================================================
// create_bytes with additional AAD (lines 104-106)
// =========================================================================

#[test]
fn create_bytes_with_additional_aad() {
    let factory = DirectSignatureFactory::new(service());
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_additional_data(b"extra-aad".to_vec());

    let result = factory.create_bytes(b"payload-aad", "text/plain", Some(opts));
    assert!(result.is_ok(), "create_bytes with AAD: {:?}", result.err());
    assert!(!result.unwrap().is_empty());
}

// =========================================================================
// create() parsing path (lines 158-160)
// =========================================================================

#[test]
fn create_returns_parsed_message() {
    let factory = DirectSignatureFactory::new(service());
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let msg = factory.create(b"parse me", "text/plain", Some(opts)).unwrap();
    assert!(msg.payload().is_some());
    assert_eq!(msg.payload().unwrap(), b"parse me");
}

// =========================================================================
// create_streaming_bytes basic path (lines 201-236)
// =========================================================================

#[test]
fn create_streaming_bytes_embedded() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"streaming data".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "streaming embedded: {:?}", result.err());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert_eq!(msg.payload().unwrap(), b"streaming data");
}

#[test]
fn create_streaming_bytes_detached() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"detach me".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(false);

    let result = factory.create_streaming_bytes(payload, "application/octet-stream", Some(opts));
    assert!(result.is_ok(), "streaming detached: {:?}", result.err());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    assert!(msg.payload().is_none(), "detached payload should be None");
}

// =========================================================================
// create_streaming_bytes with additional AAD (lines 231-232)
// =========================================================================

#[test]
fn create_streaming_bytes_with_aad() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"stream-aad".to_vec()));
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_additional_data(b"stream-extra".to_vec());

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "streaming with AAD: {:?}", result.err());
}

// =========================================================================
// create_streaming_bytes with header contributor (lines 214-217)
// =========================================================================

#[test]
fn create_streaming_bytes_with_header_contributor() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"stream-hdr".to_vec()));
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .add_header_contributor(Box::new(CustomHeaderContributor {
            label: 77,
            value: 88,
        }));

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "streaming with contributor: {:?}", result.err());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).unwrap();
    let label = cose_sign1_primitives::CoseHeaderLabel::Int(77);
    assert!(msg.protected.headers().get(&label).is_some());
}

// =========================================================================
// create_streaming_bytes with max_embed_size (lines 226-228)
// =========================================================================

#[test]
fn create_streaming_bytes_with_max_embed_size_fitting() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"small".to_vec()));
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_max_embed_size(1000);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "should fit within max_embed_size");
}

#[test]
fn create_streaming_bytes_payload_too_large() {
    let factory = DirectSignatureFactory::new(service());
    let large = vec![0x42u8; 2000];
    let payload = Arc::new(MemoryPayload::from(large));
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_max_embed_size(1000);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_err());
    match result.unwrap_err() {
        FactoryError::PayloadTooLargeForEmbedding(actual, max) => {
            assert_eq!(actual, 2000);
            assert_eq!(max, 1000);
        }
        other => panic!("expected PayloadTooLargeForEmbedding, got: {other}"),
    }
}

// =========================================================================
// create_streaming_bytes post-sign verification failure (lines 243-246)
// =========================================================================

#[test]
fn create_streaming_bytes_verification_failure() {
    let svc = Arc::new(TestSigningService::verify_fails());
    let factory = DirectSignatureFactory::new(svc);
    let payload = Arc::new(MemoryPayload::from(b"verify fail".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_err());
    match result.unwrap_err() {
        FactoryError::VerificationFailed(msg) => {
            assert!(msg.contains("Post-sign verification failed"));
        }
        other => panic!("expected VerificationFailed, got: {other}"),
    }
}

// =========================================================================
// create_streaming_bytes with transparency providers (lines 250-262)
// =========================================================================

#[test]
fn create_streaming_bytes_with_transparency() {
    let providers: Vec<Box<dyn TransparencyProvider>> =
        vec![Box::new(MockTransparency::new("stream-tp"))];
    let factory = DirectSignatureFactory::with_transparency_providers(service(), providers);
    let payload = Arc::new(MemoryPayload::from(b"stream-transparency".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok(), "streaming with transparency: {:?}", result.err());
    let bytes = result.unwrap();
    let tail = String::from_utf8_lossy(&bytes);
    assert!(tail.contains("stream-tp-proof"), "transparency proof not appended");
}

#[test]
fn create_streaming_bytes_with_multiple_transparency_providers() {
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparency::new("tp1")),
        Box::new(MockTransparency::new("tp2")),
    ];
    let factory = DirectSignatureFactory::with_transparency_providers(service(), providers);
    let payload = Arc::new(MemoryPayload::from(b"multi-tp".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok());
    let bytes = result.unwrap();
    let tail = String::from_utf8_lossy(&bytes);
    assert!(tail.contains("tp1-proof"));
    assert!(tail.contains("tp2-proof"));
}

// =========================================================================
// create_streaming_bytes with transparency disabled (lines 251-252)
// =========================================================================

#[test]
fn create_streaming_bytes_transparency_disabled() {
    let providers: Vec<Box<dyn TransparencyProvider>> =
        vec![Box::new(MockTransparency::new("disabled-tp"))];
    let factory = DirectSignatureFactory::with_transparency_providers(service(), providers);
    let payload = Arc::new(MemoryPayload::from(b"no-tp".to_vec()));
    let opts = DirectSignatureOptions::new()
        .with_embed_payload(true)
        .with_disable_transparency(true);

    let result = factory.create_streaming_bytes(payload, "text/plain", Some(opts));
    assert!(result.is_ok());
    let bytes = result.unwrap();
    let tail = String::from_utf8_lossy(&bytes);
    assert!(
        !tail.contains("disabled-tp-proof"),
        "transparency should be skipped"
    );
}

// =========================================================================
// create_streaming with parse (lines 285-287)
// =========================================================================

#[test]
fn create_streaming_returns_parsed_message() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"parse-stream".to_vec()));
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let msg = factory
        .create_streaming(payload, "text/plain", Some(opts))
        .unwrap();
    assert!(msg.payload().is_some());
    assert_eq!(msg.payload().unwrap(), b"parse-stream");
}

// =========================================================================
// create_bytes with None options (line 68 default)
// =========================================================================

#[test]
fn create_bytes_none_options_uses_defaults() {
    let factory = DirectSignatureFactory::new(service());
    let result = factory.create_bytes(b"default-opts", "text/plain", None);
    assert!(result.is_ok());
}

// =========================================================================
// create_streaming_bytes with None options (line 182 default)
// =========================================================================

#[test]
fn create_streaming_bytes_none_options() {
    let factory = DirectSignatureFactory::new(service());
    let payload = Arc::new(MemoryPayload::from(b"none-opts".to_vec()));
    let result = factory.create_streaming_bytes(payload, "text/plain", None);
    assert!(result.is_ok());
}

// =========================================================================
// create_bytes with transparency + multiple providers (lines 127-134)
// =========================================================================

#[test]
fn create_bytes_with_multiple_transparency_providers() {
    let providers: Vec<Box<dyn TransparencyProvider>> = vec![
        Box::new(MockTransparency::new("p1")),
        Box::new(MockTransparency::new("p2")),
    ];
    let factory = DirectSignatureFactory::with_transparency_providers(service(), providers);
    let opts = DirectSignatureOptions::new().with_embed_payload(true);

    let result = factory.create_bytes(b"multi-tp-bytes", "text/plain", Some(opts));
    assert!(result.is_ok());
    let bytes = result.unwrap();
    let tail = String::from_utf8_lossy(&bytes);
    assert!(tail.contains("p1-proof"));
    assert!(tail.contains("p2-proof"));
}
