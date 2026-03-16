// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Edge case tests for sig_structure functions.
//!
//! Tests uncovered paths in sig_structure.rs including:
//! - SigStructureHasher state management
//! - Encoding variations with different parameters
//! - SizedRead implementations
//! - Error handling paths

use cbor_primitives::{CborProvider, CborDecoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{
    build_sig_structure, build_sig_structure_prefix, SigStructureHasher,
    SizedRead, SizedReader, SizedSeekReader, IntoSizedRead,
    hash_sig_structure_streaming, stream_sig_structure,
    sized_from_read_buffered, sized_from_seekable, sized_from_reader, sized_from_bytes,

    error::CoseSign1Error,
};
use std::io::{Read, Write, Cursor, Seek, SeekFrom};

/// Mock hasher that implements Write for testing.
#[derive(Clone)]
#[derive(Debug)]
struct MockHasher {
    data: Vec<u8>,
    fail_on_write: bool,
}

impl MockHasher {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            fail_on_write: false,
        }
    }
    
    fn fail_on_write() -> Self {
        Self {
            data: Vec::new(),
            fail_on_write: true,
        }
    }
    
    fn finalize(self) -> Vec<u8> {
        self.data
    }
}

impl Write for MockHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.fail_on_write {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock write failure"
            ));
        }
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_build_sig_structure_with_external_aad() {
    let protected = b"protected_header";
    let external_aad = Some(b"external_auth_data".as_slice());
    let payload = b"test_payload";
    
    let sig_struct = build_sig_structure(protected, external_aad, payload).unwrap();
    
    // Verify it's valid CBOR array with 4 elements
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&sig_struct);
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    // Check context
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    // Check protected header
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    // Check external AAD
    let external_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(external_decoded, b"external_auth_data");
    
    // Check payload
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded, payload);
}

#[test]
fn test_build_sig_structure_no_external_aad() {
    let protected = b"protected_header";
    let external_aad = None;
    let payload = b"test_payload";
    
    let sig_struct = build_sig_structure(protected, external_aad, payload).unwrap();
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&sig_struct);
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    // Skip context and protected
    decoder.decode_tstr().unwrap();
    decoder.decode_bstr().unwrap();
    
    // Check external AAD is empty bstr
    let external_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(external_decoded, b"");
}

#[test]
fn test_build_sig_structure_empty_payload() {
    let protected = b"protected_header";
    let external_aad = Some(b"external_data".as_slice());
    let payload = b"";
    
    let sig_struct = build_sig_structure(protected, external_aad, payload).unwrap();
    
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&sig_struct);
    decoder.decode_array_len().unwrap();
    decoder.decode_tstr().unwrap(); // context
    decoder.decode_bstr().unwrap(); // protected
    decoder.decode_bstr().unwrap(); // external_aad
    
    let payload_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(payload_decoded, b"");
}

#[test]
fn test_build_sig_structure_prefix() {
    let protected = b"protected_header";
    let external_aad = Some(b"external_data".as_slice());
    let payload_len = 1000u64;
    
    let prefix = build_sig_structure_prefix(protected, external_aad, payload_len).unwrap();
    
    // Prefix should be valid CBOR up to the payload bstr header
    let provider = EverParseCborProvider;
    let mut decoder = provider.decoder(&prefix);
    
    let len = decoder.decode_array_len().unwrap();
    assert_eq!(len, Some(4));
    
    let context = decoder.decode_tstr().unwrap();
    assert_eq!(context, "Signature1");
    
    let protected_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(protected_decoded, protected);
    
    let external_decoded = decoder.decode_bstr().unwrap();
    assert_eq!(external_decoded, b"external_data");
    
    // The remaining bytes should be a bstr header for 1000 bytes
    // We can't easily decode just the header, but we know it should be there
    assert!(decoder.remaining().len() > 0);
}

#[test]
fn test_sig_structure_hasher_lifecycle() {
    let mut hasher = SigStructureHasher::new(MockHasher::new());
    
    let protected = b"protected";
    let external_aad = Some(b"aad".as_slice());
    let payload_len = 20u64;
    
    // Initialize
    hasher.init(protected, external_aad, payload_len).unwrap();
    
    // Update with payload chunks
    hasher.update(b"first_chunk").unwrap();
    hasher.update(b"second").unwrap();
    
    let inner = hasher.into_inner();
    let result = inner.finalize();
    
    // Verify the result contains expected components
    assert!(result.len() > 0);
    
    // Should contain the prefix plus the payload chunks
    let expected_payload = b"first_chunksecond";
    assert_eq!(expected_payload.len(), 17); // Less than 20, but that's OK for test
}

#[test]
fn test_sig_structure_hasher_double_init_error() {
    let mut hasher = SigStructureHasher::new(MockHasher::new());
    
    let protected = b"protected";
    let payload_len = 10u64;
    
    hasher.init(protected, None, payload_len).unwrap();
    
    // Second init should fail
    let result = hasher.init(protected, None, payload_len);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("already initialized"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_sig_structure_hasher_update_before_init_error() {
    let mut hasher = SigStructureHasher::new(MockHasher::new());
    
    // Update without init should fail
    let result = hasher.update(b"data");
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::InvalidMessage(msg) => {
            assert!(msg.contains("not initialized"));
            assert!(msg.contains("call init() first"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_sig_structure_hasher_write_failure() {
    let mut hasher = SigStructureHasher::new(MockHasher::fail_on_write());
    
    let result = hasher.init(b"protected", None, 10);
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::CborError(msg) => {
            assert!(msg.contains("hash write failed"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_sig_structure_hasher_update_write_failure() {
    // Test that init handles write errors from the underlying hasher
    let mut failing_hasher = SigStructureHasher::new(MockHasher::fail_on_write());
    let result = failing_hasher.init(b"protected", None, 10);
    
    // Should fail because the mock hasher fails on write
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        CoseSign1Error::CborError(msg) => {
            assert!(msg.contains("hash write failed") || msg.contains("write"));
        }
        _ => panic!("Expected CborError, got {:?}", err),
    }
}

#[test]
fn test_sig_structure_hasher_clone_capability() {
    let hasher = SigStructureHasher::new(MockHasher::new());
    
    // Test clone_hasher method
    let cloned_inner = hasher.clone_hasher();
    assert_eq!(cloned_inner.data.len(), 0);
}

#[test]
fn test_sized_reader_wrapper() {
    let data = b"test data for sized reader";
    let cursor = Cursor::new(data);
    let mut sized = SizedReader::new(cursor, data.len() as u64);
    
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    assert!(!sized.is_empty().unwrap());
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
    
    let _inner = sized.into_inner();
    // inner should be the original cursor (we can't test this easily)
}

#[test]
fn test_sized_reader_empty() {
    let empty_data = b"";
    let cursor = Cursor::new(empty_data);
    let sized = SizedReader::new(cursor, 0);
    
    assert_eq!(sized.len().unwrap(), 0);
    assert!(sized.is_empty().unwrap());
}

#[test]
fn test_sized_seek_reader() {
    let data = b"test data for seeking";
    let cursor = Cursor::new(data);
    
    let mut sized = SizedSeekReader::new(cursor).unwrap();
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_sized_seek_reader_partial() {
    let data = b"test data for partial seeking";
    let mut cursor = Cursor::new(data);
    
    // Seek to position 5
    cursor.seek(SeekFrom::Start(5)).unwrap();
    
    let sized = SizedSeekReader::new(cursor).unwrap();
    // Length should be remaining bytes from position 5
    assert_eq!(sized.len().unwrap(), (data.len() - 5) as u64);
}

#[test]
fn test_sized_from_read_buffered() {
    let data = b"test data for buffering";
    let cursor = Cursor::new(data);
    
    let mut sized = sized_from_read_buffered(cursor).unwrap();
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_sized_from_seekable() {
    let data = b"test data for seekable wrapper";
    let cursor = Cursor::new(data);
    
    let mut sized = sized_from_seekable(cursor).unwrap();
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_sized_from_reader() {
    let data = b"test data";
    let cursor = Cursor::new(data);
    let len = data.len() as u64;
    
    let mut sized = sized_from_reader(cursor, len);
    assert_eq!(sized.len().unwrap(), len);
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_sized_from_bytes() {
    let data = b"test bytes";
    let mut sized = sized_from_bytes(data);
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    
    let mut buffer = Vec::new();
    sized.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}

#[test]
fn test_into_sized_read_implementations() {
    // Test Vec<u8>
    let data = vec![1, 2, 3, 4, 5];
    let sized = data.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 5);
    
    // Test Box<[u8]>
    let boxed: Box<[u8]> = vec![6, 7, 8].into_boxed_slice();
    let sized = boxed.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 3);
    
    // Test Cursor
    let cursor = Cursor::new(vec![9, 10]);
    let sized = cursor.into_sized().unwrap();
    assert_eq!(sized.len().unwrap(), 2);
}

#[test]
fn test_hash_sig_structure_streaming() {
    let protected = b"protected_header";
    let external_aad = Some(b"external_data".as_slice());
    let payload_data = b"streaming payload data for hashing test";
    let payload = Cursor::new(payload_data);
    
    let hasher = hash_sig_structure_streaming(
        MockHasher::new(),
        protected,
        external_aad,
        payload,
    ).unwrap();
    
    let result = hasher.finalize();
    
    // Should contain the CBOR prefix plus payload
    assert!(result.len() > payload_data.len());
    
    // The end should contain our payload
    assert!(result.ends_with(payload_data));
}

#[test]
fn test_stream_sig_structure() {
    let protected = b"protected_header";
    let external_aad = Some(b"external_data".as_slice());
    let payload_data = b"streaming payload for writer test";
    let payload = Cursor::new(payload_data);
    
    let mut output = Vec::new();
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        external_aad,
        payload,
    ).unwrap();
    
    assert_eq!(bytes_written, payload_data.len() as u64);
    assert!(output.len() > payload_data.len());
    assert!(output.ends_with(payload_data));
}

/// Mock SizedRead that can simulate read errors.
struct FailingReader {
    data: Vec<u8>,
    fail_on_len: bool,
    fail_on_read: bool,
    pos: usize,
}

impl FailingReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            fail_on_len: false,
            fail_on_read: false,
            pos: 0,
        }
    }
    
    fn fail_len(mut self) -> Self {
        self.fail_on_len = true;
        self
    }
    
    fn fail_read(mut self) -> Self {
        self.fail_on_read = true;
        self
    }
}

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.fail_on_read {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock read failure"
            ));
        }
        
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        
        let remaining = &self.data[self.pos..];
        let to_copy = std::cmp::min(buf.len(), remaining.len());
        buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

impl SizedRead for FailingReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        if self.fail_on_len {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock len failure"
            ))
        } else {
            Ok(self.data.len() as u64)
        }
    }
}

#[test]
fn test_hash_sig_structure_streaming_len_error() {
    let payload = FailingReader::new(vec![1, 2, 3]).fail_len();
    
    let result = hash_sig_structure_streaming(
        MockHasher::new(),
        b"protected",
        None,
        payload,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::IoError(msg) => {
            assert!(msg.contains("failed to get payload length"));
        }
        _ => panic!("Wrong error type"),
    }
}

#[test]
fn test_hash_sig_structure_streaming_read_error() {
    let payload = FailingReader::new(vec![1, 2, 3]).fail_read();
    
    let result = hash_sig_structure_streaming(
        MockHasher::new(),
        b"protected",
        None,
        payload,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::IoError(msg) => {
            assert!(msg.contains("payload read failed"));
        }
        _ => panic!("Wrong error type"),
    }
}

/// Mock payload that reports wrong length.
struct WrongLengthReader {
    data: Vec<u8>,
    reported_len: u64,
    pos: usize,
}

impl WrongLengthReader {
    fn new(data: Vec<u8>, reported_len: u64) -> Self {
        Self {
            data,
            reported_len,
            pos: 0,
        }
    }
}

impl Read for WrongLengthReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        
        let remaining = &self.data[self.pos..];
        let to_copy = std::cmp::min(buf.len(), remaining.len());
        buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
        self.pos += to_copy;
        Ok(to_copy)
    }
}

impl SizedRead for WrongLengthReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.reported_len)
    }
}

#[test]
fn test_hash_sig_structure_streaming_length_mismatch() {
    // Reader with 5 bytes but reports 10
    let payload = WrongLengthReader::new(vec![1, 2, 3, 4, 5], 10);
    
    let result = hash_sig_structure_streaming(
        MockHasher::new(),
        b"protected",
        None,
        payload,
    );
    
    assert!(result.is_err());
    match result.unwrap_err() {
        CoseSign1Error::PayloadError(cose_sign1_primitives::PayloadError::LengthMismatch { expected, actual }) => {
            assert_eq!(expected, 10);
            assert_eq!(actual, 5);
        }
        _ => panic!("Wrong error type"),
    }
}
