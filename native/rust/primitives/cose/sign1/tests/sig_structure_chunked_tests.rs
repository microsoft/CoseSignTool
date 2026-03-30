// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for chunked streaming sig_structure helpers, length-mismatch error paths,
//! and `open_sized_file`.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    build_sig_structure, hash_sig_structure_streaming, hash_sig_structure_streaming_chunked,
    open_sized_file, sized_from_reader, stream_sig_structure, stream_sig_structure_chunked,
    CoseSign1Error, PayloadError, SizedRead,
};
use std::io::{Read, Write};

// ─── Helpers ────────────────────────────────────────────────────────────────

/// A `Write` sink that collects all bytes, used as a stand-in for a hasher.
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

/// A `SizedRead` that lies about its length, reporting a larger size than
/// the actual data. This triggers the length-mismatch error path.
struct TruncatedReader {
    data: Vec<u8>,
    pos: usize,
    claimed_len: u64,
}

impl TruncatedReader {
    fn new(data: Vec<u8>, claimed_len: u64) -> Self {
        Self {
            data,
            pos: 0,
            claimed_len,
        }
    }
}

impl SizedRead for TruncatedReader {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.claimed_len)
    }

    fn is_empty(&self) -> std::io::Result<bool> {
        Ok(self.data.is_empty())
    }
}

impl Read for TruncatedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = &self.data[self.pos..];
        let n = std::cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

// ─── open_sized_file ────────────────────────────────────────────────────────

#[test]
fn open_sized_file_returns_sized_read() {
    let dir = std::env::temp_dir();
    let path = dir.join("cose_chunked_test_open_sized.bin");
    let content = b"open_sized_file test content";
    std::fs::write(&path, content).unwrap();

    let file = open_sized_file(&path).unwrap();
    assert_eq!(file.len().unwrap(), content.len() as u64);

    std::fs::remove_file(&path).ok();
}

#[test]
fn open_sized_file_can_be_read() {
    let dir = std::env::temp_dir();
    let path = dir.join("cose_chunked_test_open_read.bin");
    let content = b"readable content";
    std::fs::write(&path, content).unwrap();

    let mut file = open_sized_file(&path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, content);

    std::fs::remove_file(&path).ok();
}

#[test]
fn open_sized_file_nonexistent_returns_error() {
    let result = open_sized_file("nonexistent_file_that_does_not_exist.bin");
    assert!(result.is_err());
}

// ─── hash_sig_structure_streaming ───────────────────────────────────────────

#[test]
fn hash_sig_structure_streaming_matches_build() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"streaming hash test payload";

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let hasher =
        hash_sig_structure_streaming(ByteCollector(Vec::new()), protected, None, payload_reader)
            .unwrap();

    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

#[test]
fn hash_sig_structure_streaming_with_external_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"payload with aad";
    let aad = Some(b"my external aad".as_slice());

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let hasher =
        hash_sig_structure_streaming(ByteCollector(Vec::new()), protected, aad, payload_reader)
            .unwrap();

    let expected = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

#[test]
fn hash_sig_structure_streaming_empty_payload() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload: &[u8] = b"";

    let payload_reader = sized_from_reader(payload, 0);
    let hasher =
        hash_sig_structure_streaming(ByteCollector(Vec::new()), protected, None, payload_reader)
            .unwrap();

    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

// ─── hash_sig_structure_streaming_chunked with various chunk sizes ──────────

#[test]
fn hash_sig_structure_streaming_chunked_chunk_size_1() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"one byte at a time";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let total =
        hash_sig_structure_streaming_chunked(&mut hasher, protected, None, &mut payload_reader, 1)
            .unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

#[test]
fn hash_sig_structure_streaming_chunked_chunk_size_4() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"four byte chunks here";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let total =
        hash_sig_structure_streaming_chunked(&mut hasher, protected, None, &mut payload_reader, 4)
            .unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

#[test]
fn hash_sig_structure_streaming_chunked_chunk_size_1024() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"large chunk size for small payload";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let total = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload_reader,
        1024,
    )
    .unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

#[test]
fn hash_sig_structure_streaming_chunked_with_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"chunked with aad test";
    let aad = Some(b"extra data".as_slice());

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let total =
        hash_sig_structure_streaming_chunked(&mut hasher, protected, aad, &mut payload_reader, 7)
            .unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(hasher.0, expected);
}

// ─── hash_sig_structure_streaming_chunked length mismatch ───────────────────

#[test]
fn hash_sig_structure_streaming_chunked_length_mismatch() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";

    // Actual data is 5 bytes but we claim 100 bytes
    let mut reader = TruncatedReader::new(vec![1, 2, 3, 4, 5], 100);
    let mut hasher = ByteCollector(Vec::new());

    let result = hash_sig_structure_streaming_chunked(&mut hasher, protected, None, &mut reader, 4);

    match result {
        Err(CoseSign1Error::PayloadError(PayloadError::LengthMismatch { expected, actual })) => {
            assert_eq!(expected, 100);
            assert_eq!(actual, 5);
        }
        other => panic!("expected LengthMismatch error, got {:?}", other),
    }
}

#[test]
fn hash_sig_structure_streaming_chunked_length_mismatch_chunk_size_1() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";

    // 3 bytes of data but claim 10
    let mut reader = TruncatedReader::new(vec![10, 20, 30], 10);
    let mut hasher = ByteCollector(Vec::new());

    let result = hash_sig_structure_streaming_chunked(&mut hasher, protected, None, &mut reader, 1);

    assert!(matches!(
        result,
        Err(CoseSign1Error::PayloadError(
            PayloadError::LengthMismatch { .. }
        ))
    ));
}

// ─── stream_sig_structure ───────────────────────────────────────────────────

#[test]
fn stream_sig_structure_matches_build() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"stream output test";

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output, protected, None, payload_reader).unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn stream_sig_structure_with_aad_matches_build() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"stream with aad";
    let aad = Some(b"stream aad".as_slice());

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output, protected, aad, payload_reader).unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn stream_sig_structure_empty_payload() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload: &[u8] = b"";

    let payload_reader = sized_from_reader(payload, 0);
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output, protected, None, payload_reader).unwrap();

    assert_eq!(total, 0);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, expected);
}

// ─── stream_sig_structure_chunked with various chunk sizes ──────────────────

#[test]
fn stream_sig_structure_chunked_chunk_size_1() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"byte by byte streaming";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total =
        stream_sig_structure_chunked(&mut output, protected, None, &mut payload_reader, 1).unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn stream_sig_structure_chunked_chunk_size_4() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"four-byte-chunk streaming";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total =
        stream_sig_structure_chunked(&mut output, protected, None, &mut payload_reader, 4).unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn stream_sig_structure_chunked_chunk_size_1024() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"large chunk for small data";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total =
        stream_sig_structure_chunked(&mut output, protected, None, &mut payload_reader, 1024)
            .unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, expected);
}

#[test]
fn stream_sig_structure_chunked_with_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"chunked stream with aad";
    let aad = Some(b"aad value".as_slice());

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total =
        stream_sig_structure_chunked(&mut output, protected, aad, &mut payload_reader, 5).unwrap();

    assert_eq!(total, payload.len() as u64);
    let expected = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(output, expected);
}

// ─── stream_sig_structure_chunked length mismatch ───────────────────────────

#[test]
fn stream_sig_structure_chunked_length_mismatch() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";

    // Actual data is 4 bytes but we claim 50 bytes
    let mut reader = TruncatedReader::new(vec![0xAA, 0xBB, 0xCC, 0xDD], 50);
    let mut output = Vec::new();

    let result = stream_sig_structure_chunked(&mut output, protected, None, &mut reader, 8);

    match result {
        Err(CoseSign1Error::PayloadError(PayloadError::LengthMismatch { expected, actual })) => {
            assert_eq!(expected, 50);
            assert_eq!(actual, 4);
        }
        other => panic!("expected LengthMismatch error, got {:?}", other),
    }
}

#[test]
fn stream_sig_structure_chunked_length_mismatch_chunk_size_1() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";

    // 2 bytes of data but claim 20
    let mut reader = TruncatedReader::new(vec![0x01, 0x02], 20);
    let mut output = Vec::new();

    let result = stream_sig_structure_chunked(&mut output, protected, None, &mut reader, 1);

    assert!(matches!(
        result,
        Err(CoseSign1Error::PayloadError(
            PayloadError::LengthMismatch { .. }
        ))
    ));
}

// ─── open_sized_file used in streaming pipeline ─────────────────────────────

#[test]
fn open_sized_file_used_with_hash_sig_structure_streaming() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let content = b"file-based payload for hashing";

    let dir = std::env::temp_dir();
    let path = dir.join("cose_chunked_test_hash_file.bin");
    std::fs::write(&path, content).unwrap();

    let file = open_sized_file(&path).unwrap();
    let hasher =
        hash_sig_structure_streaming(ByteCollector(Vec::new()), protected, None, file).unwrap();

    let expected = build_sig_structure(protected, None, content).unwrap();
    assert_eq!(hasher.0, expected);

    std::fs::remove_file(&path).ok();
}

#[test]
fn open_sized_file_used_with_stream_sig_structure() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let content = b"file-based payload for streaming";

    let dir = std::env::temp_dir();
    let path = dir.join("cose_chunked_test_stream_file.bin");
    std::fs::write(&path, content).unwrap();

    let file = open_sized_file(&path).unwrap();
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output, protected, None, file).unwrap();

    assert_eq!(total, content.len() as u64);
    let expected = build_sig_structure(protected, None, content).unwrap();
    assert_eq!(output, expected);

    std::fs::remove_file(&path).ok();
}
