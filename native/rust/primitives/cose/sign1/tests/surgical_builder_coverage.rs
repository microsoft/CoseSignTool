// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical tests targeting uncovered lines in builder.rs, sig_structure.rs, and payload.rs.
//!
//! Focuses on:
//! - Streaming sign with a signer that supports_streaming()
//! - PayloadTooLargeForEmbedding error
//! - sign() and sign_streaming() with non-empty protected headers + external AAD
//! - sign_streaming() with unprotected headers
//! - SigStructureHasher init/update/finalize and error paths
//! - Payload Debug for Streaming variant

use std::sync::Arc;

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::headers::CoseHeaderMap;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::{MemoryPayload, Payload};
use cose_sign1_primitives::sig_structure::SigStructureHasher;
use cose_sign1_primitives::{SizedRead, StreamingPayload};
use crypto_primitives::{CryptoError, CryptoSigner, SigningContext};

// ═══════════════════════════════════════════════════════════════════════════
// Mock signers
// ═══════════════════════════════════════════════════════════════════════════

/// A mock signer that does NOT support streaming (the default path).
struct NonStreamingSigner;

impl CryptoSigner for NonStreamingSigner {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"non-stream-key")
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Deterministic: first 3 bytes of input + fixed trailer
        let mut sig = data.iter().take(3).copied().collect::<Vec<_>>();
        sig.extend_from_slice(&[0xDE, 0xAD]);
        Ok(sig)
    }
}

/// A mock signing context for streaming.
struct MockStreamingContext {
    buf: Vec<u8>,
}

impl SigningContext for MockStreamingContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.buf.extend_from_slice(chunk);
        Ok(())
    }
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        // Produce a deterministic signature from accumulated data
        let len = self.buf.len();
        Ok(vec![0xAA_u8.wrapping_add(len as u8), 0xBB, 0xCC])
    }
}

/// A mock signer that DOES support streaming.
struct StreamingSigner;

impl CryptoSigner for StreamingSigner {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"stream-key")
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(vec![0xAA, 0xBB, 0xCC])
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Ok(Box::new(MockStreamingContext { buf: Vec::new() }))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: sign() with protected headers + external AAD
// Targets lines 103, 105, 114-115, 106-107 and build_message paths
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sign_with_protected_headers_and_external_aad() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);
    protected.set_kid(b"my-kid".to_vec());

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"extra-aad")
        .sign(&NonStreamingSigner, b"hello world")
        .expect("sign should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload(), Some(b"hello world".as_slice()));
}

#[test]
fn sign_detached_with_protected_and_aad() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-35);

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"aad-data")
        .detached(true)
        .sign(&NonStreamingSigner, b"detached-payload")
        .expect("sign should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
    assert_eq!(msg.alg(), Some(-35));
}

#[test]
fn sign_untagged_with_unprotected_headers() {
    let _provider = EverParseCborProvider;
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"unprot-kid".to_vec());

    let bytes = CoseSign1Builder::new()
        .unprotected(unprotected)
        .tagged(false)
        .sign(&NonStreamingSigner, b"payload")
        .expect("sign should succeed");

    // Should not start with CBOR tag 18 (0xD2)
    assert_ne!(bytes[0], 0xD2);
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"unprot-kid".as_slice())
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: sign_streaming() with streaming signer (supports_streaming=true)
// Targets lines 136-151 (streaming init, update, finalize path)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sign_streaming_with_streaming_signer() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"streamed payload data".to_vec()));

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&StreamingSigner, payload)
        .expect("streaming sign should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload(), Some(b"streamed payload data".as_slice()));
}

#[test]
fn sign_streaming_with_streaming_signer_and_external_aad() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload: Arc<dyn StreamingPayload> = Arc::new(MemoryPayload::new(b"aad-stream".to_vec()));

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"stream-aad")
        .sign_streaming(&StreamingSigner, payload)
        .expect("streaming sign with AAD should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.payload(), Some(b"aad-stream".as_slice()));
}

#[test]
fn sign_streaming_detached_with_streaming_signer() {
    let _provider = EverParseCborProvider;

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"detach-stream".to_vec()));

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign_streaming(&StreamingSigner, payload)
        .expect("detached streaming sign should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: sign_streaming() with non-streaming signer (fallback path)
// Targets lines 152-160 (fallback: buffer payload, build full sig_structure)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sign_streaming_fallback_with_non_streaming_signer() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"fallback payload".to_vec()));

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"fallback-aad")
        .sign_streaming(&NonStreamingSigner, payload)
        .expect("fallback streaming sign should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.payload(), Some(b"fallback payload".as_slice()));
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: sign_streaming() with unprotected headers
// Targets lines 198-200 (Some(headers) branch in build_message_opt)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sign_streaming_with_unprotected_headers() {
    let _provider = EverParseCborProvider;
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"stream-unprot-kid".to_vec());

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"with-unprotected".to_vec()));

    let bytes = CoseSign1Builder::new()
        .unprotected(unprotected)
        .sign_streaming(&StreamingSigner, payload)
        .expect("streaming sign with unprotected should succeed");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(
        msg.unprotected_headers().kid(),
        Some(b"stream-unprot-kid".as_slice())
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: PayloadTooLargeForEmbedding
// Targets line 130-133
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sign_streaming_payload_too_large_for_embedding() {
    let _provider = EverParseCborProvider;

    // Use a small max_embed_size to trigger the error without huge allocations
    let payload: Arc<dyn StreamingPayload> = Arc::new(MemoryPayload::new(vec![0u8; 100]));

    let result = CoseSign1Builder::new()
        .max_embed_size(50)
        .sign_streaming(&NonStreamingSigner, payload);

    match result {
        Err(cose_sign1_primitives::error::CoseSign1Error::PayloadTooLargeForEmbedding(
            size,
            max,
        )) => {
            assert_eq!(size, 100);
            assert_eq!(max, 50);
        }
        other => panic!("Expected PayloadTooLargeForEmbedding, got: {:?}", other),
    }
}

#[test]
fn sign_streaming_detached_bypasses_embed_size_check() {
    let _provider = EverParseCborProvider;

    let payload: Arc<dyn StreamingPayload> = Arc::new(MemoryPayload::new(vec![0u8; 100]));

    // Detached mode should bypass the embed size check
    let result = CoseSign1Builder::new()
        .max_embed_size(50)
        .detached(true)
        .sign_streaming(&NonStreamingSigner, payload);

    assert!(result.is_ok(), "Detached mode should bypass embed check");
}

// ═══════════════════════════════════════════════════════════════════════════
// builder.rs: sign_streaming() open error path
// Targets the PayloadError path in line 141
// ═══════════════════════════════════════════════════════════════════════════

struct FailOpenPayload;

impl StreamingPayload for FailOpenPayload {
    fn size(&self) -> u64 {
        42
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Err(PayloadError::OpenFailed("injected open failure".into()))
    }
}

#[test]
fn sign_streaming_open_error() {
    let _provider = EverParseCborProvider;

    let payload: Arc<dyn StreamingPayload> = Arc::new(FailOpenPayload);

    let result = CoseSign1Builder::new().sign_streaming(&StreamingSigner, payload);

    assert!(result.is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// sig_structure.rs: SigStructureHasher init, update, finalize, error paths
// Targets lines 222-256, 263-264, 271-272
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn sig_structure_hasher_happy_path() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    hasher.init(b"", None, 5).expect("init should succeed");
    hasher.update(b"hello").expect("update should succeed");
    let inner = hasher.into_inner();
    assert!(!inner.is_empty());
}

#[test]
fn sig_structure_hasher_with_aad() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    hasher
        .init(b"\xa1\x01\x26", Some(b"external-aad"), 10)
        .expect("init should succeed");
    hasher.update(b"0123456789").expect("update should succeed");
    let inner = hasher.into_inner();
    assert!(!inner.is_empty());
}

#[test]
fn sig_structure_hasher_double_init_error() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    hasher.init(b"", None, 0).expect("first init");

    let err = hasher.init(b"", None, 0);
    assert!(err.is_err(), "Double init should fail");
}

#[test]
fn sig_structure_hasher_update_before_init_error() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    let err = hasher.update(b"data");
    assert!(err.is_err(), "Update before init should fail");
}

#[test]
fn sig_structure_hasher_clone_hasher() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    hasher.init(b"", None, 3).expect("init");
    hasher.update(b"abc").expect("update");
    let cloned = hasher.clone_hasher();
    assert!(!cloned.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// payload.rs: Payload Debug for Streaming variant
// Targets lines 146-149
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn payload_debug_streaming_variant() {
    let mem = MemoryPayload::new(b"test".to_vec());
    let payload = Payload::Streaming(Box::new(mem));
    let debug = format!("{:?}", payload);
    assert!(
        debug.contains("Streaming"),
        "Debug should contain 'Streaming', got: {}",
        debug
    );
}

#[test]
fn payload_debug_bytes_variant() {
    let payload = Payload::Bytes(vec![1, 2, 3]);
    let debug = format!("{:?}", payload);
    assert!(
        debug.contains("Bytes"),
        "Debug should contain 'Bytes', got: {}",
        debug
    );
    assert!(
        debug.contains("3 bytes"),
        "Debug should contain '3 bytes', got: {}",
        debug
    );
}
