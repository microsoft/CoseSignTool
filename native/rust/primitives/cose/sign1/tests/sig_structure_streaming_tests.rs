// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for SizedRead types, streaming sig_structure helpers, and IntoSizedRead.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    build_sig_structure,
    hash_sig_structure_streaming, hash_sig_structure_streaming_chunked,
    stream_sig_structure, stream_sig_structure_chunked,
    sized_from_bytes, sized_from_read_buffered, sized_from_reader, sized_from_seekable,
    IntoSizedRead, SizedRead, SizedReader, SizedSeekReader,
    DEFAULT_CHUNK_SIZE, SIG_STRUCTURE_CONTEXT,
};
use std::io::{Cursor, Read, Write};

// ─── SizedRead for &[u8] ───────────────────────────────────────────────────

#[test]
fn sized_read_slice_len() {
    let data: &[u8] = b"hello world";
    assert_eq!(SizedRead::len(&data).unwrap(), 11);
}

#[test]
fn sized_read_slice_is_empty_false() {
    let data: &[u8] = b"hello";
    assert!(!SizedRead::is_empty(&data).unwrap());
}

#[test]
fn sized_read_slice_is_empty_true() {
    let data: &[u8] = b"";
    assert!(SizedRead::is_empty(&data).unwrap());
}

// ─── SizedRead for Cursor ───────────────────────────────────────────────────

#[test]
fn sized_read_cursor_len() {
    let cursor = Cursor::new(vec![1u8, 2, 3, 4, 5]);
    assert_eq!(cursor.len().unwrap(), 5);
}

#[test]
fn sized_read_cursor_is_empty() {
    let cursor: Cursor<Vec<u8>> = Cursor::new(vec![]);
    assert!(cursor.is_empty().unwrap());
}

// ─── SizedReader ────────────────────────────────────────────────────────────

#[test]
fn sized_reader_len() {
    let data = b"hello world";
    let reader = SizedReader::new(&data[..], 11);
    assert_eq!(reader.len().unwrap(), 11);
}

#[test]
fn sized_reader_read() {
    let data = b"hello";
    let mut reader = SizedReader::new(&data[..], 5);
    let mut buf = [0u8; 10];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf[..n], b"hello");
}

#[test]
fn sized_reader_into_inner() {
    let cursor = Cursor::new(vec![1, 2, 3]);
    let reader = SizedReader::new(cursor, 3);
    let inner = reader.into_inner();
    assert_eq!(inner.get_ref(), &vec![1, 2, 3]);
}

// ─── SizedSeekReader ────────────────────────────────────────────────────────

#[test]
fn sized_seek_reader_from_cursor() {
    let cursor = Cursor::new(vec![1u8, 2, 3, 4, 5]);
    let reader = SizedSeekReader::new(cursor).unwrap();
    assert_eq!(reader.len().unwrap(), 5);
}

#[test]
fn sized_seek_reader_read() {
    let cursor = Cursor::new(vec![10u8, 20, 30]);
    let mut reader = SizedSeekReader::new(cursor).unwrap();
    let mut buf = [0u8; 10];
    let n = reader.read(&mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(&buf[..n], &[10, 20, 30]);
}

#[test]
fn sized_seek_reader_into_inner() {
    let cursor = Cursor::new(vec![1, 2, 3]);
    let reader = SizedSeekReader::new(cursor).unwrap();
    let inner = reader.into_inner();
    assert_eq!(inner.get_ref(), &vec![1, 2, 3]);
}

#[test]
fn sized_seek_reader_partial_position() {
    use std::io::{Seek, SeekFrom};

    // Start from offset 2 in the cursor
    let mut cursor = Cursor::new(vec![0u8, 1, 2, 3, 4]);
    cursor.seek(SeekFrom::Start(2)).unwrap();
    let reader = SizedSeekReader::new(cursor).unwrap();
    // Length should be from current position to end: 3 bytes
    assert_eq!(reader.len().unwrap(), 3);
}

// ─── Convenience functions ──────────────────────────────────────────────────

#[test]
fn sized_from_bytes_creates_cursor() {
    let cursor = sized_from_bytes(b"hello world");
    assert_eq!(cursor.get_ref().as_ref(), b"hello world");
}

#[test]
fn sized_from_bytes_vec() {
    let cursor = sized_from_bytes(vec![1u8, 2, 3]);
    assert_eq!(cursor.get_ref(), &vec![1, 2, 3]);
}

#[test]
fn sized_from_read_buffered_works() {
    let data = b"buffer me" as &[u8];
    let cursor = sized_from_read_buffered(data).unwrap();
    assert_eq!(cursor.get_ref(), b"buffer me");
    assert_eq!(cursor.len().unwrap(), 9);
}

#[test]
fn sized_from_reader_creates_wrapper() {
    let data = b"hello" as &[u8];
    let reader = sized_from_reader(data, 5);
    assert_eq!(reader.len().unwrap(), 5);
}

#[test]
fn sized_from_seekable_works() {
    let cursor = Cursor::new(vec![1u8, 2, 3, 4]);
    let reader = sized_from_seekable(cursor).unwrap();
    assert_eq!(reader.len().unwrap(), 4);
}

// ─── IntoSizedRead ──────────────────────────────────────────────────────────

#[test]
fn into_sized_read_cursor() {
    let cursor = Cursor::new(vec![1u8, 2, 3]);
    let sized = cursor.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 3);
}

#[test]
fn into_sized_read_vec() {
    let data = vec![1u8, 2, 3, 4, 5];
    let sized = data.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 5);
}

#[test]
fn into_sized_read_boxed_slice() {
    let data: Box<[u8]> = vec![1u8, 2, 3].into_boxed_slice();
    let sized = data.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 3);
}

// ─── DEFAULT_CHUNK_SIZE ─────────────────────────────────────────────────────

#[test]
fn default_chunk_size() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 64 * 1024);
}

// ─── hash_sig_structure_streaming ───────────────────────────────────────────

/// Simple Write that collects bytes, for testing hasher output.
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
fn hash_sig_structure_streaming_basic() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"test payload";

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);

    let hasher = hash_sig_structure_streaming(ByteCollector(Vec::new()),
        protected,
        None,
        payload_reader,
    )
    .unwrap();

    // The output should be a complete Sig_structure
    let full = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, full);
}

#[test]
fn hash_sig_structure_streaming_with_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"test payload";
    let aad = Some(b"external aad".as_slice());

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);

    let hasher = hash_sig_structure_streaming(ByteCollector(Vec::new()),
        protected,
        aad,
        payload_reader,
    )
    .unwrap();

    let full = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(hasher.0, full);
}

#[test]
fn hash_sig_structure_streaming_chunked_small() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"chunked streaming test data";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut hasher = ByteCollector(Vec::new());

    let total = hash_sig_structure_streaming_chunked(&mut hasher,
        protected,
        None,
        &mut payload_reader,
        4, // very small chunks
    )
    .unwrap();

    assert_eq!(total, payload.len() as u64);

    let full = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(hasher.0, full);
}

// ─── stream_sig_structure ───────────────────────────────────────────────────

#[test]
fn stream_sig_structure_basic() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"stream test";

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output,
        protected,
        None,
        payload_reader,
    )
    .unwrap();

    assert_eq!(total, payload.len() as u64);

    let full = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, full);
}

#[test]
fn stream_sig_structure_with_aad() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"stream test with aad";
    let aad = Some(b"some aad".as_slice());

    let payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    stream_sig_structure(&mut output,
        protected,
        aad,
        payload_reader,
    )
    .unwrap();

    let full = build_sig_structure(protected, aad, payload).unwrap();
    assert_eq!(output, full);
}

#[test]
fn stream_sig_structure_chunked_small() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload = b"chunked stream test data";

    let mut payload_reader = sized_from_reader(&payload[..], payload.len() as u64);
    let mut output = Vec::new();

    let total = stream_sig_structure_chunked(&mut output,
        protected,
        None,
        &mut payload_reader,
        3, // very small chunks
    )
    .unwrap();

    assert_eq!(total, payload.len() as u64);

    let full = build_sig_structure(protected, None, payload).unwrap();
    assert_eq!(output, full);
}

#[test]
fn stream_sig_structure_empty_payload() {
    let provider = EverParseCborProvider::default();
    let protected = b"\xa1\x01\x26";
    let payload: &[u8] = b"";

    let payload_reader = sized_from_reader(payload, 0);
    let mut output = Vec::new();

    let total = stream_sig_structure(&mut output,
        protected,
        None,
        payload_reader,
    )
    .unwrap();

    assert_eq!(total, 0);
}

// ─── SIG_STRUCTURE_CONTEXT ──────────────────────────────────────────────────

#[test]
fn sig_structure_context_value() {
    assert_eq!(SIG_STRUCTURE_CONTEXT, "Signature1");
}

// ─── SizedRead for File (via tempfile) ──────────────────────────────────────

#[test]
fn sized_read_file() {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let path = dir.join("cose_test_sized_read.bin");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"file content").unwrap();
    }
    let f = std::fs::File::open(&path).unwrap();
    assert_eq!(f.len().unwrap(), 12);
    std::fs::remove_file(&path).ok();
}

#[test]
fn into_sized_read_file() {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let path = dir.join("cose_test_into_sized.bin");
    {
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"test data").unwrap();
    }
    let f = std::fs::File::open(&path).unwrap();
    let sized = f.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 9);
    std::fs::remove_file(&path).ok();
}
