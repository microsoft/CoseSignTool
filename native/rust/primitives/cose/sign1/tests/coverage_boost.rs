// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for cose_sign1_primitives.
//!
//! Covers uncovered lines in:
//! - builder.rs: L103, L105, L114, L124, L136, L149, etc. (sign, sign_streaming, build methods)
//! - message.rs: L90, L124, L130, L135, L202, L222, etc. (parse, verify, encode)
//! - sig_structure.rs: streaming hasher, build_sig_structure_prefix, stream_sig_structure

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::headers::CoseHeaderMap;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::MemoryPayload;
use cose_sign1_primitives::sig_structure::{
    build_sig_structure, build_sig_structure_prefix, hash_sig_structure_streaming,
    hash_sig_structure_streaming_chunked, stream_sig_structure, stream_sig_structure_chunked,
    SigStructureHasher, SizedRead, SizedReader,
};
use cose_sign1_primitives::{CoseSign1Error, StreamingPayload};
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier, SigningContext};
use std::sync::Arc;

// ============================================================================
// Mock crypto implementations
// ============================================================================

/// Mock signer that produces deterministic signatures.
struct MockSigner;

impl CryptoSigner for MockSigner {
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"mock-key-id")
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Produce a "signature" that includes the data length
        let mut sig = vec![0xAA, 0xBB];
        sig.extend_from_slice(&(data.len() as u32).to_be_bytes());
        Ok(sig)
    }
}

/// Mock verifier that checks our mock signature format.
struct MockVerifier;

impl CryptoVerifier for MockVerifier {
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if signature.len() < 6 {
            return Ok(false);
        }
        if signature[0] != 0xAA || signature[1] != 0xBB {
            return Ok(false);
        }
        let expected_len = u32::from_be_bytes([signature[2], signature[3], signature[4], signature[5]]);
        Ok(expected_len == data.len() as u32)
    }
}

/// Mock signer that supports streaming.
struct StreamingMockSigner;

impl CryptoSigner for StreamingMockSigner {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sig = vec![0xCC, 0xDD];
        sig.extend_from_slice(&(data.len() as u32).to_be_bytes());
        Ok(sig)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn sign_init(&self) -> Result<Box<dyn SigningContext>, CryptoError> {
        Ok(Box::new(MockSigningContext { data: Vec::new() }))
    }
}

struct MockSigningContext {
    data: Vec<u8>,
}

impl SigningContext for MockSigningContext {
    fn update(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        self.data.extend_from_slice(data);
        Ok(())
    }
    fn finalize(self: Box<Self>) -> Result<Vec<u8>, CryptoError> {
        let mut sig = vec![0xCC, 0xDD];
        sig.extend_from_slice(&(self.data.len() as u32).to_be_bytes());
        Ok(sig)
    }
}

/// A simple Write sink for collecting streamed data.
struct WriteCollector {
    buf: Vec<u8>,
}

impl WriteCollector {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
}

impl std::io::Write for WriteCollector {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Clone for WriteCollector {
    fn clone(&self) -> Self {
        Self {
            buf: self.buf.clone(),
        }
    }
}

// ============================================================================
// builder.rs coverage
// ============================================================================

/// Covers L103-108 (sign: protected_bytes, build_sig_structure, build_message)
#[test]
fn test_builder_sign_with_protected_headers() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"test payload");

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse should succeed");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload, Some(b"test payload".to_vec()));
}

/// Covers L110-116 (protected_bytes with empty vs non-empty headers)
#[test]
fn test_builder_sign_empty_protected() {
    let _provider = EverParseCborProvider;
    let result = CoseSign1Builder::new().sign(&MockSigner, b"empty headers payload");
    assert!(result.is_ok());

    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.alg().is_none());
}

/// Covers L124-174 (sign_streaming with non-streaming signer fallback)
#[test]
fn test_builder_sign_streaming_non_streaming_signer() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload = MemoryPayload::new(b"streaming test".to_vec());
    let payload_arc: Arc<dyn StreamingPayload> = Arc::new(payload);

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&MockSigner, payload_arc);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.payload, Some(b"streaming test".to_vec()));
}

/// Covers L138-151 (sign_streaming with streaming signer)
#[test]
fn test_builder_sign_streaming_with_streaming_signer() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload = MemoryPayload::new(b"streaming signer test".to_vec());
    let payload_arc: Arc<dyn StreamingPayload> = Arc::new(payload);

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&StreamingMockSigner, payload_arc);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.payload, Some(b"streaming signer test".to_vec()));
}

/// Covers L129-134 (sign_streaming embed size limit)
#[test]
fn test_builder_sign_streaming_embed_size_limit() {
    let _provider = EverParseCborProvider;

    let payload = MemoryPayload::new(vec![0u8; 100]);
    let payload_arc: Arc<dyn StreamingPayload> = Arc::new(payload);

    let result = CoseSign1Builder::new()
        .max_embed_size(10)
        .sign_streaming(&MockSigner, payload_arc);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, CoseSign1Error::PayloadTooLargeForEmbedding(_, _)),
        "should be payload too large error"
    );
}

/// Covers L163-174 (sign_streaming detached: no embed payload)
#[test]
fn test_builder_sign_streaming_detached() {
    let _provider = EverParseCborProvider;

    let payload = MemoryPayload::new(b"detached streaming".to_vec());
    let payload_arc: Arc<dyn StreamingPayload> = Arc::new(payload);

    let result = CoseSign1Builder::new()
        .detached(true)
        .sign_streaming(&MockSigner, payload_arc);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
    assert!(msg.payload.is_none());
}

/// Covers builder with unprotected headers and tagged/untagged
#[test]
fn test_builder_with_unprotected_headers() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let mut unprotected = CoseHeaderMap::new();
    unprotected.insert(
        cose_sign1_primitives::CoseHeaderLabel::Int(4),
        cose_sign1_primitives::CoseHeaderValue::Bytes(b"kid-value".to_vec()),
    );

    let result = CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .tagged(false)
        .sign(&MockSigner, b"unprotected test");

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(!msg.unprotected.is_empty());
}

/// Covers builder with external AAD
#[test]
fn test_builder_with_external_aad() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let result = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"extra-context")
        .sign(&MockSigner, b"aad test");

    assert!(result.is_ok());
}

// ============================================================================
// message.rs coverage
// ============================================================================

/// Covers L90-96 (parse: wrong COSE tag error)
#[test]
fn test_message_parse_wrong_tag() {
    let _provider = EverParseCborProvider;

    // Build a CBOR tag(99) + array(4) + valid contents — wrong tag
    let mut encoder = cbor_primitives_everparse::EverParseCborProvider.encoder();
    use cbor_primitives::{CborEncoder, CborProvider};
    encoder.encode_tag(99).unwrap();
    encoder.encode_array(4).unwrap();
    encoder.encode_bstr(&[]).unwrap();
    // empty map for unprotected
    let mut map_enc = cbor_primitives_everparse::EverParseCborProvider.encoder();
    map_enc.encode_map(0).unwrap();
    encoder.encode_raw(&map_enc.into_bytes()).unwrap();
    encoder.encode_bstr(b"payload").unwrap();
    encoder.encode_bstr(b"sig").unwrap();
    let bytes = encoder.into_bytes();

    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("unexpected COSE tag"));
}

/// Covers L104-117 (parse: wrong array length)
#[test]
fn test_message_parse_wrong_array_length() {
    let _provider = EverParseCborProvider;
    use cbor_primitives::{CborEncoder, CborProvider};

    let mut encoder = cbor_primitives_everparse::EverParseCborProvider.encoder();
    encoder.encode_tag(18).unwrap();
    encoder.encode_array(3).unwrap(); // wrong: should be 4
    encoder.encode_bstr(&[]).unwrap();
    let mut map_enc = cbor_primitives_everparse::EverParseCborProvider.encoder();
    map_enc.encode_map(0).unwrap();
    encoder.encode_raw(&map_enc.into_bytes()).unwrap();
    encoder.encode_bstr(b"payload").unwrap();
    let bytes = encoder.into_bytes();

    let result = CoseSign1Message::parse(&bytes);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("4 elements"));
}

/// Covers L124 (ProtectedHeader::decode), L130 (decode_payload)
/// Covers L135 (signature decode)
#[test]
fn test_message_parse_and_verify_roundtrip() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockSigner, b"verify me")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload.as_deref(), Some(b"verify me".as_slice()));
    assert!(!msg.signature.is_empty());

    // Verify
    let valid = msg.verify(&MockVerifier, None).expect("verify should not error");
    assert!(valid, "signature should verify successfully");
}

/// Covers L198-207 (verify: embedded payload, sig_structure construction)
#[test]
fn test_message_verify_with_external_aad() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let bytes = CoseSign1Builder::new()
        .protected(protected)
        .external_aad(b"context")
        .sign(&MockSigner, b"aad verify")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    // Verify with same external AAD
    let valid = msg
        .verify(&MockVerifier, Some(b"context"))
        .expect("verify");
    assert!(valid);

    // Verify with different external AAD should fail
    let invalid = msg
        .verify(&MockVerifier, Some(b"wrong-context"))
        .expect("verify");
    assert!(!invalid, "wrong AAD should not verify");
}

/// Covers L200-201 (verify: PayloadMissing on detached)
#[test]
fn test_message_verify_detached_requires_payload() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, b"detached")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());

    let result = msg.verify(&MockVerifier, None);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CoseSign1Error::PayloadMissing));
}

/// Covers L216-227 (verify_detached)
#[test]
fn test_message_verify_detached() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, b"detached payload")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    let valid = msg
        .verify_detached(&MockVerifier, b"detached payload", None)
        .expect("verify_detached");
    assert!(valid);
}

/// Covers L248-262 (verify_detached_streaming)
#[test]
fn test_message_verify_detached_streaming() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, b"stream payload")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    let payload_data = b"stream payload";
    let mut sized = SizedReader::new(&payload_data[..], payload_data.len() as u64);
    let valid = msg
        .verify_detached_streaming(&MockVerifier, &mut sized, None)
        .expect("verify_detached_streaming");
    assert!(valid);
}

/// Covers L285-295 (verify_detached_read)
#[test]
fn test_message_verify_detached_read() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, b"read payload")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    let mut cursor = std::io::Cursor::new(b"read payload".to_vec());
    let valid = msg
        .verify_detached_read(&MockVerifier, &mut cursor, None)
        .expect("verify_detached_read");
    assert!(valid);
}

/// Covers L304-314 (verify_streaming)
#[test]
fn test_message_verify_streaming() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockSigner, b"streaming verify")
        .expect("sign");

    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    let payload = MemoryPayload::new(b"streaming verify".to_vec());
    let payload_arc: Arc<dyn StreamingPayload> = Arc::new(payload);
    let valid = msg
        .verify_streaming(&MockVerifier, payload_arc, None)
        .expect("verify_streaming");
    assert!(valid);
}

/// Covers L370-413 (encode method)
#[test]
fn test_message_encode_tagged_and_untagged() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .sign(&MockSigner, b"encode test")
        .expect("sign");
    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    // Encode tagged
    let tagged_bytes = msg.encode(true).expect("encode tagged");
    let reparsed = CoseSign1Message::parse(&tagged_bytes).expect("reparse tagged");
    assert_eq!(reparsed.payload, msg.payload);

    // Encode untagged
    let untagged_bytes = msg.encode(false).expect("encode untagged");
    let reparsed2 = CoseSign1Message::parse(&untagged_bytes).expect("reparse untagged");
    assert_eq!(reparsed2.payload, msg.payload);
}

/// Covers sig_structure_bytes method
#[test]
fn test_message_sig_structure_bytes() {
    let _provider = EverParseCborProvider;

    let bytes = CoseSign1Builder::new()
        .sign(&MockSigner, b"sig structure test")
        .expect("sign");
    let msg = CoseSign1Message::parse(&bytes).expect("parse");

    let sig_bytes = msg
        .sig_structure_bytes(b"sig structure test", None)
        .expect("sig_structure_bytes");
    assert!(!sig_bytes.is_empty());
}

// ============================================================================
// sig_structure.rs coverage
// ============================================================================

/// Covers build_sig_structure with various inputs
#[test]
fn test_build_sig_structure_with_external_aad() {
    let _provider = EverParseCborProvider;

    let result = build_sig_structure(b"protected", Some(b"external"), b"payload");
    assert!(result.is_ok());
    let bytes = result.unwrap();
    assert!(!bytes.is_empty());
}

/// Covers build_sig_structure_prefix
#[test]
fn test_build_sig_structure_prefix_various_sizes() {
    let _provider = EverParseCborProvider;

    // Small payload
    let prefix_small = build_sig_structure_prefix(b"hdr", None, 10).expect("small prefix");
    assert!(!prefix_small.is_empty());

    // Large payload
    let prefix_large = build_sig_structure_prefix(b"hdr", None, 1_000_000).expect("large prefix");
    assert!(!prefix_large.is_empty());

    // With external AAD
    let prefix_aad =
        build_sig_structure_prefix(b"hdr", Some(b"ext-aad"), 50).expect("prefix with aad");
    assert!(!prefix_aad.is_empty());
}

/// Covers SigStructureHasher init/update/into_inner
#[test]
fn test_sig_structure_hasher() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(WriteCollector::new());

    hasher
        .init(b"protected-bytes", None, 5)
        .expect("init");

    hasher.update(b"hello").expect("update");

    let collector = hasher.into_inner();
    assert!(!collector.buf.is_empty());
}

/// Covers SigStructureHasher double-init error
#[test]
fn test_sig_structure_hasher_double_init() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(WriteCollector::new());
    hasher.init(b"hdr", None, 0).expect("first init");

    let result = hasher.init(b"hdr", None, 0);
    assert!(result.is_err());
}

/// Covers SigStructureHasher update without init
#[test]
fn test_sig_structure_hasher_update_without_init() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(WriteCollector::new());
    let result = hasher.update(b"data");
    assert!(result.is_err());
}

/// Covers SigStructureHasher clone_hasher
#[test]
fn test_sig_structure_hasher_clone() {
    let _provider = EverParseCborProvider;

    let mut hasher = SigStructureHasher::new(WriteCollector::new());
    hasher.init(b"hdr", None, 3).expect("init");
    hasher.update(b"abc").expect("update");

    let cloned = hasher.clone_hasher();
    assert!(!cloned.buf.is_empty());
}

/// Covers hash_sig_structure_streaming
#[test]
fn test_hash_sig_structure_streaming() {
    let _provider = EverParseCborProvider;

    let payload = b"streaming hash payload";
    let sized = SizedReader::new(&payload[..], payload.len() as u64);

    let result = hash_sig_structure_streaming(
        WriteCollector::new(),
        b"protected",
        None,
        sized,
    );

    assert!(result.is_ok());
    let collector = result.unwrap();
    assert!(!collector.buf.is_empty());
}

/// Covers hash_sig_structure_streaming_chunked
#[test]
fn test_hash_sig_structure_streaming_chunked() {
    let _provider = EverParseCborProvider;

    let payload = b"chunked hash payload data that is longer for multiple chunks";
    let mut sized = SizedReader::new(&payload[..], payload.len() as u64);

    let mut collector = WriteCollector::new();
    let result = hash_sig_structure_streaming_chunked(
        &mut collector,
        b"protected",
        Some(b"aad"),
        &mut sized,
        8, // small chunk size to exercise loop
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), payload.len() as u64);
}

/// Covers stream_sig_structure
#[test]
fn test_stream_sig_structure() {
    let _provider = EverParseCborProvider;

    let payload = b"stream sig structure test";
    let sized = SizedReader::new(&payload[..], payload.len() as u64);

    let mut output = Vec::new();
    let result = stream_sig_structure(
        &mut output,
        b"protected",
        None,
        sized,
    );

    assert!(result.is_ok());
    assert!(!output.is_empty());
}

/// Covers stream_sig_structure_chunked
#[test]
fn test_stream_sig_structure_chunked() {
    let _provider = EverParseCborProvider;

    let payload = b"chunked stream sig structure";
    let mut sized = SizedReader::new(&payload[..], payload.len() as u64);

    let mut output = Vec::new();
    let result = stream_sig_structure_chunked(
        &mut output,
        b"protected",
        Some(b"aad"),
        &mut sized,
        4, // very small chunks
    );

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), payload.len() as u64);
}

/// Covers SizedReader::new and SizedRead::is_empty
#[test]
fn test_sized_reader_basics() {
    let data = b"hello world";
    let sized = SizedReader::new(&data[..], data.len() as u64);
    assert_eq!(sized.len().unwrap(), 11);
    assert!(!sized.is_empty().unwrap());

    let empty = SizedReader::new(&[][..], 0u64);
    assert_eq!(empty.len().unwrap(), 0);
    assert!(empty.is_empty().unwrap());
}

/// Covers SizedRead for byte slices
#[test]
fn test_sized_read_for_slices() {
    let data: &[u8] = b"slice data";
    assert_eq!(SizedRead::len(&data).unwrap(), 10);
    assert!(!SizedRead::is_empty(&data).unwrap());
}

/// Covers SizedRead for Cursor
#[test]
fn test_sized_read_for_cursor() {
    let cursor = std::io::Cursor::new(vec![1, 2, 3, 4, 5]);
    assert_eq!(SizedRead::len(&cursor).unwrap(), 5);
}

/// Covers IntoSizedRead for Vec
#[test]
fn test_into_sized_read_vec() {
    use cose_sign1_primitives::IntoSizedRead;

    let data = vec![1u8, 2, 3];
    let cursor = data.into_sized().unwrap();
    assert_eq!(SizedRead::len(&cursor).unwrap(), 3);
}

/// Covers IntoSizedRead for Box<[u8]>
#[test]
fn test_into_sized_read_box() {
    use cose_sign1_primitives::IntoSizedRead;

    let data: Box<[u8]> = vec![1u8, 2, 3, 4].into_boxed_slice();
    let cursor = data.into_sized().unwrap();
    assert_eq!(SizedRead::len(&cursor).unwrap(), 4);
}

/// Covers sized_from_bytes
#[test]
fn test_sized_from_bytes() {
    use cose_sign1_primitives::sized_from_bytes;

    let cursor = sized_from_bytes(vec![10, 20, 30]);
    assert_eq!(SizedRead::len(&cursor).unwrap(), 3);
}

/// Covers sized_from_reader
#[test]
fn test_sized_from_reader() {
    use cose_sign1_primitives::sized_from_reader;

    let data = b"reader data";
    let sized = sized_from_reader(&data[..], data.len() as u64);
    assert_eq!(sized.len().unwrap(), 11);
}

/// Covers sized_from_read_buffered
#[test]
fn test_sized_from_read_buffered() {
    use cose_sign1_primitives::sized_from_read_buffered;

    let data = b"buffered data";
    let cursor = sized_from_read_buffered(&data[..]).unwrap();
    assert_eq!(SizedRead::len(&cursor).unwrap(), 13);
}

/// Covers SizedSeekReader
#[test]
fn test_sized_seek_reader() {
    use cose_sign1_primitives::SizedSeekReader;

    let cursor = std::io::Cursor::new(b"seekable data".to_vec());
    let sized = SizedSeekReader::new(cursor).expect("new SizedSeekReader");
    assert_eq!(sized.len().unwrap(), 13);

    let inner = sized.into_inner();
    assert_eq!(inner.into_inner(), b"seekable data");
}

/// Covers sized_from_seekable
#[test]
fn test_sized_from_seekable() {
    use cose_sign1_primitives::sized_from_seekable;

    let cursor = std::io::Cursor::new(b"seekable".to_vec());
    let sized = sized_from_seekable(cursor).expect("sized_from_seekable");
    assert_eq!(sized.len().unwrap(), 8);
}
