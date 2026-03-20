// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for CoseSign1Builder to maximize code path coverage.
//!
//! This test file focuses on exercising all branches and error paths in builder.rs,
//! including edge cases in CBOR encoding, streaming payload handling, and builder configurations.

use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::headers::CoseHeaderMap;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::StreamingPayload;
use cose_sign1_primitives::sig_structure::SizedRead;
use crypto_primitives::{CryptoError, CryptoSigner, SigningContext};

// ============================================================================
// Mock Implementations
// ============================================================================

/// Mock signer that simulates streaming capabilities and various error conditions
struct AdvancedMockSigner {
    streaming_enabled: bool,
    fail_init: bool,
    fail_update: bool,
    fail_finalize: bool,
    fail_sign: bool,
    signature: Vec<u8>,
}

impl AdvancedMockSigner {
    fn new() -> Self {
        Self {
            streaming_enabled: false,
            fail_init: false,
            fail_update: false,
            fail_finalize: false,
            fail_sign: false,
            signature: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }
    }

    fn with_streaming(mut self) -> Self {
        self.streaming_enabled = true;
        self
    }

    fn with_sign_failure(mut self) -> Self {
        self.fail_sign = true;
        self
    }

    fn with_init_failure(mut self) -> Self {
        self.fail_init = true;
        self
    }

    fn with_update_failure(mut self) -> Self {
        self.fail_update = true;
        self
    }

    fn with_finalize_failure(mut self) -> Self {
        self.fail_finalize = true;
        self
    }

    fn with_signature(mut self, sig: Vec<u8>) -> Self {
        self.signature = sig;
        self
    }
}

impl Default for AdvancedMockSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoSigner for AdvancedMockSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if self.fail_sign {
            return Err(CryptoError::SigningFailed(
                "Mock signing failure".to_string(),
            ));
        }
        Ok(self.signature.clone())
    }

    fn algorithm(&self) -> i64 {
        -7 // ES256
    }

    fn key_type(&self) -> &str {
        "EC2"
    }

    fn key_id(&self) -> Option<&[u8]> {
        Some(b"test_key_id")
    }

    fn supports_streaming(&self) -> bool {
        self.streaming_enabled
    }

    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        if self.fail_init {
            return Err(CryptoError::SigningFailed("Mock init failure".to_string()));
        }
        Ok(Box::new(AdvancedMockSigningContext {
            data: Vec::new(),
            fail_update: self.fail_update,
            fail_finalize: self.fail_finalize,
            signature: self.signature.clone(),
        }))
    }
}

/// Mock signing context for streaming operations
struct AdvancedMockSigningContext {
    data: Vec<u8>,
    fail_update: bool,
    fail_finalize: bool,
    signature: Vec<u8>,
}

impl SigningContext for AdvancedMockSigningContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        if self.fail_update {
            return Err(CryptoError::SigningFailed(
                "Mock update failure".to_string(),
            ));
        }
        self.data.extend_from_slice(chunk);
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        if self.fail_finalize {
            return Err(CryptoError::SigningFailed(
                "Mock finalize failure".to_string(),
            ));
        }
        Ok(self.signature.clone())
    }
}

/// Mock streaming payload for various test scenarios
struct AdvancedMockStreamingPayload {
    data: Vec<u8>,
    fail_open: bool,
    fail_on_read: bool,
    max_reads_before_fail: usize,
    read_count: Arc<Mutex<usize>>,
}

impl AdvancedMockStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            fail_open: false,
            fail_on_read: false,
            max_reads_before_fail: usize::MAX,
            read_count: Arc::new(Mutex::new(0)),
        }
    }

    fn with_open_failure(mut self) -> Self {
        self.fail_open = true;
        self
    }

    fn with_read_failure(mut self) -> Self {
        self.fail_on_read = true;
        self
    }

    fn with_failure_on_nth_read(mut self, n: usize) -> Self {
        self.max_reads_before_fail = n;
        self
    }
}

impl StreamingPayload for AdvancedMockStreamingPayload {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        if self.fail_open {
            return Err(PayloadError::OpenFailed("Mock open failure".to_string()));
        }

        let read_count = self.read_count.clone();
        let data = self.data.clone();
        let fail_on_read = self.fail_on_read;
        let max_reads = self.max_reads_before_fail;

        Ok(Box::new(FailableReader {
            cursor: Cursor::new(data.clone()),
            len: data.len() as u64,
            read_count,
            fail_on_read,
            max_reads,
        }))
    }
}

/// A reader that can fail on demand
struct FailableReader {
    cursor: Cursor<Vec<u8>>,
    len: u64,
    read_count: Arc<Mutex<usize>>,
    fail_on_read: bool,
    max_reads: usize,
}

impl Read for FailableReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.fail_on_read {
            let mut count = self.read_count.lock().unwrap();
            *count += 1;
            if *count > self.max_reads {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Mock read failure",
                ));
            }
        }
        self.cursor.read(buf)
    }
}

impl SizedRead for FailableReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.len)
    }
}

// ============================================================================
// Comprehensive Tests
// ============================================================================

#[test]
fn test_builder_sign_with_signing_error() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let failing_signer = AdvancedMockSigner::new().with_sign_failure();

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign(&failing_signer, b"test payload");

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("signing") || err.to_string().contains("key error"));
}

#[test]
fn test_builder_streaming_with_streaming_enabled_signer() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let streaming_signer = AdvancedMockSigner::new().with_streaming();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(
        b"streaming test data".to_vec(),
    ));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&streaming_signer, payload);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    assert_eq!(msg.payload(), Some(b"streaming test data".as_slice()));
}

#[test]
fn test_builder_streaming_with_streaming_init_failure() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let failing_signer = AdvancedMockSigner::new()
        .with_streaming()
        .with_init_failure();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(b"test".to_vec()));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&failing_signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_with_streaming_update_failure() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let failing_signer = AdvancedMockSigner::new()
        .with_streaming()
        .with_update_failure();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(
        b"test data for update failure".to_vec(),
    ));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&failing_signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_with_streaming_finalize_failure() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let failing_signer = AdvancedMockSigner::new()
        .with_streaming()
        .with_finalize_failure();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(b"test".to_vec()));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&failing_signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_payload_open_fails() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(b"test".to_vec()).with_open_failure());

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_with_prefix_read_error() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();
    // Payload that fails during the prefix read (first open for non-streaming signer)
    let payload = Arc::new(
        AdvancedMockStreamingPayload::new(b"test data".to_vec())
            .with_read_failure()
            .with_failure_on_nth_read(0),
    );

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_with_embed_read_error() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new().with_streaming();
    // For streaming signer, second open (re-read for embedded payload) should fail
    let payload = Arc::new(
        AdvancedMockStreamingPayload::new(b"test data".to_vec())
            .with_read_failure()
            .with_failure_on_nth_read(1), // Fail on second read attempt
    );

    let result = CoseSign1Builder::new()
        .protected(protected)
        .detached(false) // Not detached, so we need to re-read
        .sign_streaming(&signer, payload);

    assert!(result.is_err());
}

#[test]
fn test_builder_streaming_large_payload_chunks() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new().with_streaming();

    // Create a large payload that will be read in multiple 65536-byte chunks
    let large_data = vec![0xAB; 200_000];
    let payload = Arc::new(AdvancedMockStreamingPayload::new(large_data));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload);

    assert!(result.is_ok());
}

#[test]
fn test_builder_streaming_exact_chunk_size() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new().with_streaming();

    // Create payload that's exactly 65536 bytes (one chunk)
    let data = vec![0x42; 65536];
    let payload = Arc::new(AdvancedMockStreamingPayload::new(data));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload);

    assert!(result.is_ok());
}

#[test]
fn test_builder_streaming_empty_payload() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new().with_streaming();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(vec![]));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&signer, payload);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    assert_eq!(msg.payload(), Some(b"".as_slice()));
}

#[test]
fn test_builder_sign_empty_payload() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();
    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign(&signer, b"");

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("should parse");
    assert_eq!(msg.payload(), Some(b"".as_slice()));
}

#[test]
fn test_builder_multiple_external_aad_variations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Test 1: Empty AAD
    let result1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .external_aad(b"".to_vec())
        .sign(&signer, b"payload");
    assert!(result1.is_ok());

    // Test 2: Large AAD
    let large_aad = vec![0xFF; 10000];
    let result2 = CoseSign1Builder::new()
        .protected(protected.clone())
        .external_aad(large_aad)
        .sign(&signer, b"payload");
    assert!(result2.is_ok());

    // Test 3: AAD as reference (using Into<Vec<u8>>)
    let result3 = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(&b"reference_aad"[..])
        .sign(&signer, b"payload");
    assert!(result3.is_ok());
}

#[test]
fn test_builder_unprotected_headers_variations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Test 1: Unprotected with key ID only
    let mut unprotected1 = CoseHeaderMap::new();
    unprotected1.set_kid(b"key1");
    let result1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .unprotected(unprotected1)
        .sign(&signer, b"test1");
    assert!(result1.is_ok());

    // Test 2: Unprotected with large key ID
    let mut unprotected2 = CoseHeaderMap::new();
    unprotected2.set_kid(vec![0x42; 1000]);
    let result2 = CoseSign1Builder::new()
        .protected(protected.clone())
        .unprotected(unprotected2)
        .sign(&signer, b"test2");
    assert!(result2.is_ok());

    // Test 3: Override protected with unprotected (same field if possible)
    let mut unprotected3 = CoseHeaderMap::new();
    unprotected3.set_kid(b"override_kid");
    let result3 = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected3)
        .sign(&signer, b"test3");
    assert!(result3.is_ok());
}

#[test]
fn test_builder_tagged_untagged_consistency() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Sign with tag
    let tagged = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(true)
        .sign(&signer, b"test payload")
        .unwrap();

    // Sign without tag
    let untagged = CoseSign1Builder::new()
        .protected(protected)
        .tagged(false)
        .sign(&signer, b"test payload")
        .unwrap();

    // Tagged version should be longer (has tag prefix)
    assert!(tagged.len() > untagged.len());

    // Both should parse successfully
    let tagged_msg = CoseSign1Message::parse(&tagged).expect("tagged parse");
    let untagged_msg = CoseSign1Message::parse(&untagged).expect("untagged parse");

    assert_eq!(tagged_msg.payload(), untagged_msg.payload());
    assert_eq!(tagged_msg.signature(), untagged_msg.signature());
}

#[test]
fn test_builder_detached_embedded_consistency() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Sign with embedded payload
    let embedded = CoseSign1Builder::new()
        .protected(protected.clone())
        .detached(false)
        .sign(&signer, b"test payload")
        .unwrap();

    // Sign with detached payload
    let detached = CoseSign1Builder::new()
        .protected(protected)
        .detached(true)
        .sign(&signer, b"test payload")
        .unwrap();

    let embedded_msg = CoseSign1Message::parse(&embedded).expect("embedded parse");
    let detached_msg = CoseSign1Message::parse(&detached).expect("detached parse");

    assert_eq!(embedded_msg.payload(), Some(b"test payload".as_slice()));
    assert_eq!(detached_msg.payload(), None);
    assert!(detached_msg.is_detached());
}

#[test]
fn test_builder_all_builder_options_combinations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Combination 1: tagged + embedded + external_aad + no unprotected
    let r1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(true)
        .detached(false)
        .external_aad(b"aad1")
        .sign(&signer, b"payload1");
    assert!(r1.is_ok());

    // Combination 2: untagged + detached + external_aad + unprotected
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"kid");
    let r2 = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(false)
        .detached(true)
        .external_aad(b"aad2")
        .unprotected(unprotected)
        .sign(&signer, b"payload2");
    assert!(r2.is_ok());

    // Combination 3: tagged + embedded + no external_aad + unprotected + max_embed_size
    let mut unprotected2 = CoseHeaderMap::new();
    unprotected2.set_kid(b"kid2");
    let r3 = CoseSign1Builder::new()
        .protected(protected)
        .tagged(true)
        .detached(false)
        .unprotected(unprotected2)
        .max_embed_size(1024)
        .sign(&signer, b"payload3");
    assert!(r3.is_ok());
}

#[test]
fn test_builder_streaming_with_all_combinations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"streaming_kid");

    let signer = AdvancedMockSigner::new().with_streaming();
    let payload = Arc::new(AdvancedMockStreamingPayload::new(
        b"streaming payload".to_vec(),
    ));

    // Combination 1: tagged + embedded + external_aad
    let r1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(true)
        .detached(false)
        .external_aad(b"stream_aad1")
        .sign_streaming(&signer, payload.clone());
    assert!(r1.is_ok());

    // Combination 2: untagged + detached + unprotected
    let r2 = CoseSign1Builder::new()
        .protected(protected.clone())
        .tagged(false)
        .detached(true)
        .unprotected(unprotected.clone())
        .sign_streaming(&signer, payload.clone());
    assert!(r2.is_ok());

    // Combination 3: tagged + embedded + max_embed_size within limit
    let r3 = CoseSign1Builder::new()
        .protected(protected)
        .max_embed_size(100_000)
        .sign_streaming(&signer, payload);
    assert!(r3.is_ok());
}

#[test]
fn test_builder_empty_protected_with_various_options() {
    let empty_protected = CoseHeaderMap::new();
    let signer = AdvancedMockSigner::new();

    // Empty protected + tagged + embedded
    let r1 = CoseSign1Builder::new()
        .protected(empty_protected.clone())
        .tagged(true)
        .detached(false)
        .sign(&signer, b"test1");
    assert!(r1.is_ok());

    // Empty protected + untagged + detached + external_aad
    let r2 = CoseSign1Builder::new()
        .protected(empty_protected.clone())
        .tagged(false)
        .detached(true)
        .external_aad(b"aad")
        .sign(&signer, b"test2");
    assert!(r2.is_ok());

    // Empty protected + unprotected headers
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"empty_prot_kid");
    let r3 = CoseSign1Builder::new()
        .protected(empty_protected)
        .unprotected(unprotected)
        .sign(&signer, b"test3");
    assert!(r3.is_ok());
}

#[test]
fn test_builder_large_payload_variations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // 1MB payload
    let large1 = vec![0x42; 1_000_000];
    let r1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .sign(&signer, &large1);
    assert!(r1.is_ok());

    // 10MB payload (may take a moment)
    let large2 = vec![0x43; 10_000_000];
    let r2 = CoseSign1Builder::new()
        .protected(protected)
        .sign(&signer, &large2);
    assert!(r2.is_ok());
}

#[test]
fn test_builder_signature_variations() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    // Test 1: Empty signature
    let signer1 = AdvancedMockSigner::new().with_signature(vec![]);
    let r1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .sign(&signer1, b"payload1");
    assert!(r1.is_ok());

    // Test 2: Very large signature
    let large_sig = vec![0xFF; 10_000];
    let signer2 = AdvancedMockSigner::new().with_signature(large_sig);
    let r2 = CoseSign1Builder::new()
        .protected(protected.clone())
        .sign(&signer2, b"payload2");
    assert!(r2.is_ok());

    // Test 3: Various signature bytes
    let varied_sig = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let signer3 = AdvancedMockSigner::new().with_signature(varied_sig);
    let r3 = CoseSign1Builder::new()
        .protected(protected)
        .sign(&signer3, b"payload3");
    assert!(r3.is_ok());
}

#[test]
fn test_builder_cbor_encoding_edge_cases() {
    // This test ensures various CBOR encoding paths are exercised
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let signer = AdvancedMockSigner::new();

    // Test payloads with various byte patterns
    let payloads = vec![
        b"".to_vec(),                       // Empty
        vec![0x00],                         // Single null byte
        vec![0xFF; 256],                    // 256 0xFF bytes
        vec![0x00; 1000],                   // 1000 0x00 bytes
        (0u8..=255u8).collect::<Vec<u8>>(), // All byte values
    ];

    for payload in payloads {
        let result = CoseSign1Builder::new()
            .protected(protected.clone())
            .sign(&signer, &payload);
        assert!(result.is_ok(), "Failed for payload: {:?}", payload);
    }
}

#[test]
fn test_builder_method_order_independence() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"test_kid");

    let signer = AdvancedMockSigner::new();

    // Order 1
    let r1 = CoseSign1Builder::new()
        .protected(protected.clone())
        .unprotected(unprotected.clone())
        .external_aad(b"aad")
        .detached(true)
        .tagged(false)
        .max_embed_size(1024)
        .sign(&signer, b"test")
        .unwrap();

    // Order 2
    let r2 = CoseSign1Builder::new()
        .max_embed_size(1024)
        .tagged(false)
        .detached(true)
        .external_aad(b"aad")
        .unprotected(unprotected)
        .protected(protected)
        .sign(&signer, b"test")
        .unwrap();

    // Parse both and verify they have the same structure
    let msg1 = CoseSign1Message::parse(&r1).unwrap();
    let msg2 = CoseSign1Message::parse(&r2).unwrap();

    assert_eq!(msg1.is_detached(), msg2.is_detached());
    assert_eq!(msg1.payload(), msg2.payload());
    assert_eq!(msg1.signature(), msg2.signature());
}

#[test]
fn test_builder_clone_independence() {
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let base = CoseSign1Builder::new().protected(protected).tagged(false);

    let signer = AdvancedMockSigner::new();

    // Clone and modify each
    let r1 = base.clone().detached(true).sign(&signer, b"test1").unwrap();
    let r2 = base
        .clone()
        .detached(false)
        .sign(&signer, b"test2")
        .unwrap();
    let r3 = base.detached(false).sign(&signer, b"test3").unwrap();

    let msg1 = CoseSign1Message::parse(&r1).unwrap();
    let msg2 = CoseSign1Message::parse(&r2).unwrap();
    let msg3 = CoseSign1Message::parse(&r3).unwrap();

    assert!(msg1.is_detached());
    assert!(!msg2.is_detached());
    assert!(!msg3.is_detached());
}
