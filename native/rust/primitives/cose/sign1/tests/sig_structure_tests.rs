// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for Sig_structure construction and SigStructureHasher streaming.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    build_sig_structure, build_sig_structure_prefix, SigStructureHasher, SIG_STRUCTURE_CONTEXT,
};
use std::io::Write;

/// Simple Write impl that collects bytes for testing.
#[derive(Clone)]
struct ByteCollector(Vec<u8>);

impl Write for ByteCollector {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_sig_structure_context_constant() {
    assert_eq!(SIG_STRUCTURE_CONTEXT, "Signature1");
}

#[test]
fn test_build_sig_structure_basic() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26"; // {1: -7} (alg: ES256)
    let payload = b"test payload";
    let external_aad = None;

    let result = build_sig_structure(protected, external_aad, payload);
    assert!(result.is_ok());

    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
    // The structure should be a CBOR array with 4 elements
    assert_eq!(sig_structure[0], 0x84); // array of 4
}

#[test]
fn test_build_sig_structure_with_external_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"test payload";
    let external_aad = Some(b"some aad".as_slice());

    let result = build_sig_structure(protected, external_aad, payload);
    assert!(result.is_ok());

    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
}

#[test]
fn test_build_sig_structure_empty_payload() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"";
    let external_aad = None;

    let result = build_sig_structure(protected, external_aad, payload);
    assert!(result.is_ok());

    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
}

#[test]
fn test_build_sig_structure_prefix() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload_len = 100u64;
    let external_aad = None;

    let result = build_sig_structure_prefix(protected, external_aad, payload_len);
    assert!(result.is_ok());

    let prefix = result.unwrap();
    assert!(!prefix.is_empty());
    // The prefix should end with the bstr header for the payload
    // but not include the actual payload bytes
}

#[test]
fn test_build_sig_structure_prefix_with_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload_len = 100u64;
    let external_aad = Some(b"external data".as_slice());

    let result = build_sig_structure_prefix(protected, external_aad, payload_len);
    assert!(result.is_ok());
}

#[test]
fn test_sig_structure_hasher_basic() {
    let provider = EverParseCborProvider::default();
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);

    let protected = b"\xa1\x01\x26"; // {1: -7}
    let payload = b"test payload";

    hasher.init(protected, None, payload.len() as u64).unwrap();
    hasher.update(payload).unwrap();

    let result = hasher.into_inner();
    // Verify the collected bytes form a valid Sig_structure header
    assert!(!result.0.is_empty());
    assert_eq!(result.0[0], 0x84); // array of 4
}

#[test]
fn test_sig_structure_hasher_matches_full_build() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26"; // {1: -7} (alg: ES256)
    let payload = b"test payload data for hashing verification";
    let external_aad: Option<&[u8]> = None;

    // Method 1: Full build
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, payload).unwrap();

    // Method 2: Streaming hasher
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher
        .init(protected_bytes, external_aad, payload.len() as u64)
        .unwrap();
    hasher.update(payload).unwrap();
    let streaming_result = hasher.into_inner();

    assert_eq!(
        full_sig_structure, streaming_result.0,
        "streaming hasher should produce same bytes as full build"
    );
}

#[test]
fn test_sig_structure_hasher_with_external_aad() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26";
    let payload = b"test payload";
    let external_aad = Some(b"external aad data".as_slice());

    // Full build reference
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, payload).unwrap();

    // Streaming hasher
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher
        .init(protected_bytes, external_aad, payload.len() as u64)
        .unwrap();
    hasher.update(payload).unwrap();
    let streaming_result = hasher.into_inner();

    assert_eq!(full_sig_structure, streaming_result.0);
}

#[test]
fn test_sig_structure_hasher_chunked() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26";
    let payload = b"this is a longer payload that will be processed in multiple chunks";
    let external_aad = Some(b"some external aad".as_slice());

    // Full build reference
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, payload).unwrap();

    // Streaming with small chunks
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher
        .init(protected_bytes, external_aad, payload.len() as u64)
        .unwrap();

    // Process in 10-byte chunks
    for chunk in payload.chunks(10) {
        hasher.update(chunk).unwrap();
    }

    let streaming_result = hasher.into_inner();
    assert_eq!(full_sig_structure, streaming_result.0);
}

#[test]
fn test_sig_structure_hasher_empty_payload() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26";
    let payload = b"";
    let external_aad = None;

    // Full build reference
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, payload).unwrap();

    // Streaming hasher
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher.init(protected_bytes, external_aad, 0).unwrap();
    // No update calls for empty payload

    let streaming_result = hasher.into_inner();
    assert_eq!(full_sig_structure, streaming_result.0);
}

#[test]
fn test_sig_structure_hasher_double_init_error() {
    let provider = EverParseCborProvider::default();
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);

    let protected_bytes = b"\xa1\x01\x26";

    hasher.init(protected_bytes, None, 10).unwrap();

    let result = hasher.init(protected_bytes, None, 10);
    assert!(result.is_err(), "double init should fail");
}

#[test]
fn test_sig_structure_hasher_update_before_init_error() {
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);

    let result = hasher.update(b"some data");
    assert!(result.is_err(), "update before init should fail");
}

#[test]
fn test_sig_structure_hasher_single_byte_chunks() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26";
    let payload = b"single byte chunks";
    let external_aad = None;

    // Full build reference
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, payload).unwrap();

    // Streaming with single byte chunks
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher
        .init(protected_bytes, external_aad, payload.len() as u64)
        .unwrap();

    for &byte in payload {
        hasher.update(&[byte]).unwrap();
    }

    let streaming_result = hasher.into_inner();
    assert_eq!(full_sig_structure, streaming_result.0);
}

#[test]
fn test_sig_structure_hasher_clone_hasher() {
    let provider = EverParseCborProvider::default();
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);

    let protected_bytes = b"\xa1\x01\x26";
    hasher.init(protected_bytes, None, 5).unwrap();
    hasher.update(b"hello").unwrap();

    // Clone the inner hasher
    let cloned = hasher.clone_hasher();
    assert!(!cloned.0.is_empty());

    // Original hasher should still be usable
    let original = hasher.into_inner();
    assert_eq!(original.0, cloned.0);
}

#[test]
fn test_sig_structure_different_protected_headers() {
    let provider = EverParseCborProvider::default();
    let payload = b"same payload";
    let external_aad = None;

    // Different protected headers should produce different Sig_structures
    let protected1 = b"\xa1\x01\x26"; // {1: -7} (ES256)
    let protected2 = b"\xa1\x01\x27"; // {1: -8} (EdDSA)

    let sig1 = build_sig_structure(protected1, external_aad, payload).unwrap();
    let sig2 = build_sig_structure(protected2, external_aad, payload).unwrap();

    assert_ne!(
        sig1, sig2,
        "different protected headers should produce different Sig_structures"
    );
}

#[test]
fn test_sig_structure_different_external_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"same payload";

    // Different external AAD should produce different Sig_structures
    let aad1 = Some(b"aad1".as_slice());
    let aad2 = Some(b"aad2".as_slice());

    let sig1 = build_sig_structure(protected, aad1, payload).unwrap();
    let sig2 = build_sig_structure(protected, aad2, payload).unwrap();

    assert_ne!(
        sig1, sig2,
        "different external AAD should produce different Sig_structures"
    );
}

#[test]
fn test_sig_structure_different_payloads() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let external_aad = None;

    // Different payloads should produce different Sig_structures
    let payload1 = b"payload one";
    let payload2 = b"payload two";

    let sig1 = build_sig_structure(protected, external_aad, payload1).unwrap();
    let sig2 = build_sig_structure(protected, external_aad, payload2).unwrap();

    assert_ne!(
        sig1, sig2,
        "different payloads should produce different Sig_structures"
    );
}

#[test]
fn test_sig_structure_hasher_large_payload() {
    let provider = EverParseCborProvider::default();

    let protected_bytes = b"\xa1\x01\x26";
    let payload = vec![0xCD; 100000]; // 100KB payload
    let external_aad = None;

    // Full build reference
    let full_sig_structure =
        build_sig_structure(protected_bytes, external_aad, &payload).unwrap();

    // Streaming with 8KB chunks
    let collector = ByteCollector(Vec::new());
    let mut hasher = SigStructureHasher::new(collector);
    hasher
        .init(protected_bytes, external_aad, payload.len() as u64)
        .unwrap();

    for chunk in payload.chunks(8192) {
        hasher.update(chunk).unwrap();
    }

    let streaming_result = hasher.into_inner();
    assert_eq!(full_sig_structure, streaming_result.0);
}
