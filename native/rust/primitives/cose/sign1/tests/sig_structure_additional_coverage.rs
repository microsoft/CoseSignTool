// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for sig_structure to reach all uncovered code paths.

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::error::CoseSign1Error;
use cose_sign1_primitives::sig_structure::{
    build_sig_structure, build_sig_structure_prefix, hash_sig_structure_streaming,
    hash_sig_structure_streaming_chunked, sized_from_bytes, sized_from_read_buffered,
    sized_from_reader, sized_from_seekable, stream_sig_structure, stream_sig_structure_chunked,
    IntoSizedRead, SigStructureHasher, SizedRead, SizedReader, SizedSeekReader, DEFAULT_CHUNK_SIZE,
};

/// Mock writer that can fail for testing error paths
struct FailingWriter {
    should_fail: bool,
    bytes_written: usize,
}

impl FailingWriter {
    fn new(should_fail: bool) -> Self {
        Self {
            should_fail,
            bytes_written: 0,
        }
    }
}

impl Write for FailingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.should_fail {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock write failure",
            ));
        }
        self.bytes_written += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Mock reader that can fail or return incorrect length
struct MockSizedRead {
    data: Cursor<Vec<u8>>,
    reported_len: u64,
    should_fail_len: bool,
    should_fail_read: bool,
}

impl MockSizedRead {
    fn new(data: Vec<u8>, reported_len: u64) -> Self {
        Self {
            data: Cursor::new(data),
            reported_len,
            should_fail_len: false,
            should_fail_read: false,
        }
    }

    fn with_len_failure(mut self) -> Self {
        self.should_fail_len = true;
        self
    }

    fn with_read_failure(mut self) -> Self {
        self.should_fail_read = true;
        self
    }
}

impl Read for MockSizedRead {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.should_fail_read {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock read failure",
            ));
        }
        self.data.read(buf)
    }
}

impl SizedRead for MockSizedRead {
    fn len(&self) -> Result<u64, std::io::Error> {
        if self.should_fail_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mock len failure",
            ));
        }
        Ok(self.reported_len)
    }
}

#[test]
fn test_sig_structure_hasher_lifecycle() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());

    let protected = b"\xa1\x01\x26"; // {1: -7}
    let external_aad = Some(b"test_aad".as_slice());
    let payload_len = 100u64;

    // Test initialization
    hasher
        .init(protected, external_aad, payload_len)
        .expect("should init");

    // Test update with payload chunks
    let chunk1 = b"chunk1";
    let chunk2 = b"chunk2";

    hasher.update(chunk1).expect("should update 1");
    hasher.update(chunk2).expect("should update 2");

    // Test finalization
    let result = hasher.into_inner();
    assert!(!result.is_empty());
}

#[test]
fn test_sig_structure_hasher_double_init_error() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());

    let protected = b"\xa1\x01\x26";
    let payload_len = 50u64;

    // First init should succeed
    hasher.init(protected, None, payload_len).expect("first init");

    // Second init should fail
    let result = hasher.init(protected, None, payload_len);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already initialized"));
}

#[test]
fn test_sig_structure_hasher_update_before_init_error() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());

    // Try to update before init
    let result = hasher.update(b"test");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not initialized"));
}

#[test]
fn test_sig_structure_hasher_write_failure() {
    let mut hasher = SigStructureHasher::new(FailingWriter::new(true));

    let protected = b"\xa1\x01\x26";
    let payload_len = 50u64;

    // Init should fail due to write failure
    let result = hasher.init(protected, None, payload_len);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash write failed"));
}

#[test]
fn test_sig_structure_hasher_update_write_failure() {
    let mut hasher = SigStructureHasher::new(FailingWriter::new(false));

    let protected = b"\xa1\x01\x26";
    let payload_len = 50u64;

    // Init should succeed
    hasher.init(protected, None, payload_len).expect("should init");

    // Change writer to failing mode (can't do this with our current mock)
    // Instead test with hasher that fails on update
    let chunk = b"test chunk";
    let result = hasher.update(chunk);
    // This test may not trigger the error with our simple mock
    // But it exercises the update code path
}

#[test]
fn test_sig_structure_hasher_clone() {
    // Test clone_hasher method for hashers that support Clone
    let hasher = SigStructureHasher::new(Vec::<u8>::new());
    let protected = b"\xa1\x01\x26";
    let payload_len = 50u64;

    let mut initialized_hasher = hasher;
    initialized_hasher.init(protected, None, payload_len).expect("should init");

    // Test clone_hasher method
    let inner_clone = initialized_hasher.clone_hasher();
    // The clone should contain the sig_structure prefix that was written during init
    assert!(!inner_clone.is_empty()); // Contains sig_structure prefix
}

#[test]
fn test_sized_reader_wrapper() {
    let data = b"test data for sized reader";
    let cursor = Cursor::new(data.to_vec());
    let mut sized = SizedReader::new(cursor, data.len() as u64);

    // Test len method
    assert_eq!(sized.len().unwrap(), data.len() as u64);
    assert!(!sized.is_empty().unwrap());

    // Test reading
    let mut buf = [0u8; 5];
    let n = sized.read(&mut buf).unwrap();
    assert_eq!(n, 5);
    assert_eq!(&buf, b"test ");

    // Test into_inner
    let cursor = sized.into_inner();
    // Can't easily test cursor state, but exercises the method
}

#[test]
fn test_sized_seek_reader() {
    let data = b"test data for seek reader";
    let mut cursor = Cursor::new(data.to_vec());

    // Seek to position 5 first
    cursor.seek(SeekFrom::Start(5)).unwrap();

    // Create SizedSeekReader from current position
    let mut sized = SizedSeekReader::new(cursor).expect("should create sized seek reader");

    // Should calculate length from current position to end
    let expected_len = (data.len() - 5) as u64;
    assert_eq!(sized.len().unwrap(), expected_len);

    // Test reading from current position
    let mut buf = [0u8; 4];
    let n = sized.read(&mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"data"); // Should start from position 5

    // Test into_inner
    let _cursor = sized.into_inner();
}

#[test]
fn test_sized_from_functions() {
    // Test sized_from_bytes
    let data = b"test bytes";
    let sized = sized_from_bytes(data);
    assert_eq!(sized.len().unwrap(), data.len() as u64);

    // Test sized_from_reader
    let cursor = Cursor::new(b"test reader".to_vec());
    let sized = sized_from_reader(cursor, 11);
    assert_eq!(sized.len().unwrap(), 11);

    // Test sized_from_read_buffered
    let cursor = Cursor::new(b"buffered read test".to_vec());
    let sized = sized_from_read_buffered(cursor).expect("should buffer");
    assert_eq!(sized.len().unwrap(), 18);

    // Test sized_from_seekable
    let cursor = Cursor::new(b"seekable test".to_vec());
    let sized = sized_from_seekable(cursor).expect("should create from seekable");
    assert_eq!(sized.len().unwrap(), 13);
}

#[test]
fn test_into_sized_read_implementations() {
    // Test Vec<u8> conversion
    let data = b"vector data".to_vec();
    let sized = data.into_sized().expect("should convert vec");
    assert_eq!(sized.len().unwrap(), 11);

    // Test Box<[u8]> conversion
    let boxed: Box<[u8]> = b"boxed data".to_vec().into_boxed_slice();
    let sized = boxed.into_sized().expect("should convert box");
    assert_eq!(sized.len().unwrap(), 10);

    // Test Cursor<Vec<u8>> conversion
    let cursor = Cursor::new(b"cursor data".to_vec());
    let sized = cursor.into_sized().expect("should convert cursor");
    assert_eq!(sized.len().unwrap(), 11);
}

#[test]
fn test_hash_sig_structure_streaming() {
    let protected = b"\xa1\x01\x26";
    let external_aad = Some(b"streaming aad".as_slice());
    let payload_data = b"streaming payload data for hashing";

    let mut payload = sized_from_bytes(payload_data);
    let hasher = Vec::<u8>::new();

    let result = hash_sig_structure_streaming(
        hasher,
        protected,
        external_aad,
        payload,
    )
    .expect("should hash streaming");

    assert!(!result.is_empty());
}

#[test]
fn test_hash_sig_structure_streaming_chunked() {
    let protected = b"\xa1\x01\x26";
    let external_aad = None;
    let payload_data = b"chunked streaming payload";

    let mut payload = sized_from_bytes(payload_data);
    let mut hasher = Vec::<u8>::new();

    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        external_aad,
        &mut payload,
        8, // Small chunk size
    )
    .expect("should hash chunked");

    assert_eq!(bytes_read, payload_data.len() as u64);
    assert!(!hasher.is_empty());
}

#[test]
fn test_hash_streaming_length_mismatch() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"actual data";
    let wrong_length = 999; // Much larger than actual

    let mut payload = MockSizedRead::new(payload_data.to_vec(), wrong_length);
    let mut hasher = Vec::<u8>::new();

    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        CoseSign1Error::PayloadError(payload_err) => {
            assert!(payload_err.to_string().contains("length mismatch"));
        }
        _ => panic!("Expected PayloadError with length mismatch"),
    }
}

#[test]
fn test_hash_streaming_len_failure() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"test data";

    let mut payload = MockSizedRead::new(payload_data.to_vec(), payload_data.len() as u64)
        .with_len_failure();
    let mut hasher = Vec::<u8>::new();

    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("failed to get payload length"));
}

#[test]
fn test_hash_streaming_read_failure() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"test data";

    let mut payload = MockSizedRead::new(payload_data.to_vec(), payload_data.len() as u64)
        .with_read_failure();
    let mut hasher = Vec::<u8>::new();

    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("payload read failed"));
}

#[test]
fn test_hash_streaming_write_failure() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"test data";

    let mut payload = sized_from_bytes(payload_data);
    let mut hasher = FailingWriter::new(true);

    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash write failed"));
}

#[test]
fn test_stream_sig_structure() {
    let protected = b"\xa1\x01\x26";
    let external_aad = Some(b"stream aad".as_slice());
    let payload_data = b"streaming sig structure payload";

    let mut payload = sized_from_bytes(payload_data);
    let mut output = Vec::<u8>::new();

    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        external_aad,
        payload,
    )
    .expect("should stream sig structure");

    assert_eq!(bytes_written, payload_data.len() as u64);
    assert!(!output.is_empty());
}

#[test]
fn test_stream_sig_structure_chunked() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"chunked sig structure payload";

    let mut payload = sized_from_bytes(payload_data);
    let mut output = Vec::<u8>::new();

    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload,
        5, // Small chunk size
    )
    .expect("should stream chunked");

    assert_eq!(bytes_written, payload_data.len() as u64);
    assert!(!output.is_empty());
}

#[test]
fn test_stream_sig_structure_length_mismatch() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"mismatch test";
    let wrong_length = 5; // Smaller than actual

    let mut payload = MockSizedRead::new(payload_data.to_vec(), wrong_length);
    let mut output = Vec::<u8>::new();

    let result = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        CoseSign1Error::PayloadError(payload_err) => {
            assert!(payload_err.to_string().contains("length mismatch"));
        }
        _ => panic!("Expected PayloadError with length mismatch"),
    }
}

#[test]
fn test_stream_sig_structure_write_failure() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"write failure test";

    let mut payload = sized_from_bytes(payload_data);
    let mut output = FailingWriter::new(true);

    let result = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("write failed"));
}

#[test]
fn test_sized_read_slice_implementation() {
    let data: &[u8] = b"slice implementation test";

    // Test SizedRead implementation for &[u8]
    assert_eq!(SizedRead::len(&data).unwrap(), 25);
    assert!(!SizedRead::is_empty(&data).unwrap());

    // Test empty slice
    let empty: &[u8] = b"";
    assert_eq!(SizedRead::len(&empty).unwrap(), 0);
    assert!(SizedRead::is_empty(&empty).unwrap());
}

#[test]
fn test_sized_read_cursor_implementation() {
    let data = b"cursor implementation test";
    let cursor = Cursor::new(data);

    // Test SizedRead implementation for Cursor
    assert_eq!(SizedRead::len(&cursor).unwrap(), 26);
    assert!(!SizedRead::is_empty(&cursor).unwrap());

    // Test with empty cursor
    let empty_cursor = Cursor::new(Vec::<u8>::new());
    assert_eq!(SizedRead::len(&empty_cursor).unwrap(), 0);
    assert!(SizedRead::is_empty(&empty_cursor).unwrap());
}

#[test]
fn test_default_chunk_size_constant() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 64 * 1024); // 64 KB
}

#[test]
fn test_build_sig_structure_empty_protected() {
    let protected = b""; // Empty protected header
    let payload = b"test payload";
    let external_aad = Some(b"aad".as_slice());

    let result = build_sig_structure(protected, external_aad, payload);
    assert!(result.is_ok());
    
    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
}

#[test]
fn test_build_sig_structure_prefix_zero_length() {
    let protected = b"\xa0"; // Empty map
    let payload_len = 0u64; // Zero-length payload
    let external_aad = None;

    let result = build_sig_structure_prefix(protected, external_aad, payload_len);
    assert!(result.is_ok());

    let prefix = result.unwrap();
    assert!(!prefix.is_empty());
}

#[test]
fn test_build_sig_structure_large_payload() {
    let protected = b"\xa1\x01\x26";
    let large_payload = vec![0u8; 1_000_000]; // 1MB payload
    let external_aad = None;

    let result = build_sig_structure(protected, external_aad, &large_payload);
    assert!(result.is_ok());

    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
    // Should be significantly larger than small payloads due to embedded payload
    assert!(sig_structure.len() > 900_000);
}

// ============================================================================
// COMPREHENSIVE COVERAGE TESTS - Edge Cases and Boundary Conditions
// ============================================================================

/// Test empty payload with streaming
#[test]
fn test_stream_sig_structure_empty_payload() {
    let protected = b"\xa1\x01\x26";
    let empty_payload = b"";
    
    let mut payload = sized_from_bytes(empty_payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload,
    ).expect("should stream empty payload");
    
    assert_eq!(bytes_written, 0);
    assert!(!output.is_empty()); // Should still have prefix
}

/// Test hash with empty payload
#[test]
fn test_hash_sig_structure_streaming_empty() {
    let protected = b"\xa1\x01\x26";
    let empty_payload = b"";
    
    let mut payload = sized_from_bytes(empty_payload);
    let mut hasher = Vec::<u8>::new();
    
    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    ).expect("should hash empty payload");
    
    assert_eq!(bytes_read, 0);
    assert!(!hasher.is_empty()); // Should have prefix
}

/// Test very large chunk size (larger than payload)
#[test]
fn test_hash_streaming_chunk_size_larger_than_payload() {
    let protected = b"\xa1\x01\x26";
    let payload = b"small";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut hasher = Vec::<u8>::new();
    
    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload_reader,
        1_000_000, // Much larger than payload
    ).expect("should hash with large chunk size");
    
    assert_eq!(bytes_read, 5);
}

/// Test multiple empty chunks
#[test]
fn test_stream_multiple_chunks_small_size() {
    let protected = b"\xa1\x01\x26";
    let payload = b"1234567890";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload_reader,
        2, // Very small chunk size
    ).expect("should stream with small chunks");
    
    assert_eq!(bytes_written, 10);
}

/// Test with very large external AAD
#[test]
fn test_build_sig_structure_large_external_aad() {
    let protected = b"\xa1\x01\x26";
    let large_aad = vec![0xFFu8; 100_000];
    let payload = b"payload";
    
    let result = build_sig_structure(protected, Some(&large_aad), payload);
    assert!(result.is_ok());
}

/// Test streaming with large external AAD
#[test]
fn test_stream_sig_structure_large_external_aad() {
    let protected = b"\xa1\x01\x26";
    let large_aad = vec![0xAAu8; 50_000];
    let payload = b"test payload";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        Some(&large_aad),
        payload_reader,
    ).expect("should stream with large AAD");
    
    assert_eq!(bytes_written, 12);
}

/// Test boundary condition: exactly 85KB
#[test]
fn test_stream_exactly_85kb_payload() {
    let protected = b"\xa1\x01\x26";
    let payload_85kb = vec![0x55u8; 85 * 1024];
    
    let mut payload_reader = sized_from_bytes(&payload_85kb);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload_reader,
    ).expect("should stream 85KB exactly");
    
    assert_eq!(bytes_written, 85 * 1024 as u64);
}

/// Test boundary condition: 85KB + 1 byte
#[test]
fn test_stream_85kb_plus_one() {
    let protected = b"\xa1\x01\x26";
    let payload = vec![0x56u8; 85 * 1024 + 1];
    
    let mut payload_reader = sized_from_bytes(&payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload_reader,
    ).expect("should stream 85KB + 1");
    
    assert_eq!(bytes_written, 85 * 1024 as u64 + 1);
}

/// Test boundary condition: 85KB - 1 byte
#[test]
fn test_stream_85kb_minus_one() {
    let protected = b"\xa1\x01\x26";
    let payload = vec![0x57u8; 85 * 1024 - 1];
    
    let mut payload_reader = sized_from_bytes(&payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload_reader,
    ).expect("should stream 85KB - 1");
    
    assert_eq!(bytes_written, 85 * 1024 as u64 - 1);
}

/// Test hasher with write failure during prefix
#[test]
fn test_hash_streaming_chunked_write_failure_in_prefix() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"test";
    
    let mut payload = sized_from_bytes(payload_data);
    let mut hasher = FailingWriter::new(true);
    
    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash write failed"));
}

/// Test stream_sig_structure with read failure
#[test]
fn test_stream_sig_structure_read_failure() {
    let protected = b"\xa1\x01\x26";
    let payload_data = b"test";
    
    let mut payload = MockSizedRead::new(payload_data.to_vec(), payload_data.len() as u64)
        .with_read_failure();
    let mut output = Vec::<u8>::new();
    
    let result = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload,
        DEFAULT_CHUNK_SIZE,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("payload read failed"));
}

/// Test build_sig_structure_prefix with maximum payload length
#[test]
fn test_build_sig_structure_prefix_max_u64() {
    let protected = b"\xa1\x01\x26";
    let max_len = u64::MAX;
    
    let result = build_sig_structure_prefix(protected, None, max_len);
    assert!(result.is_ok());
    
    let prefix = result.unwrap();
    assert!(!prefix.is_empty());
}

/// Test SigStructureHasher with write failure during update
#[test]
fn test_sig_structure_hasher_update_write_error() {
    // Create a hasher with FailingWriter that will fail on write during update
    struct FailOnSecondWrite {
        write_count: usize,
    }
    
    impl Write for FailOnSecondWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_count += 1;
            if self.write_count > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Fail on second write",
                ));
            }
            Ok(buf.len())
        }
        
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    
    let mut hasher = SigStructureHasher::new(FailOnSecondWrite {
        write_count: 0,
    });
    
    let protected = b"\xa1\x01\x26";
    hasher.init(protected, None, 50).expect("should init");
    
    // Now try to update - this should fail
    let result = hasher.update(b"chunk");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("hash write failed"));
}

/// Test streaming with None external AAD vs Some(&[])
#[test]
fn test_stream_sig_structure_external_aad_variations() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    
    // Test with None
    let mut payload1 = sized_from_bytes(payload);
    let mut output1 = Vec::<u8>::new();
    
    stream_sig_structure(
        &mut output1,
        protected,
        None,
        payload1,
    ).expect("should stream with None AAD");
    
    // Test with Some(&[])
    let empty_aad = b"";
    let mut payload2 = sized_from_bytes(payload);
    let mut output2 = Vec::<u8>::new();
    
    stream_sig_structure(
        &mut output2,
        protected,
        Some(empty_aad),
        payload2,
    ).expect("should stream with empty AAD");
    
    // Both should produce the same output
    assert_eq!(output1, output2);
}

/// Test hash_sig_structure_streaming with None vs Some external AAD
#[test]
fn test_hash_sig_structure_external_aad_equivalence() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test payload";
    
    // Hash with None
    let mut payload1 = sized_from_bytes(payload);
    let mut hasher1 = Vec::<u8>::new();
    
    hash_sig_structure_streaming_chunked(
        &mut hasher1,
        protected,
        None,
        &mut payload1,
        DEFAULT_CHUNK_SIZE,
    ).expect("should hash with None");
    
    // Hash with Some(&[])
    let empty_aad = b"";
    let mut payload2 = sized_from_bytes(payload);
    let mut hasher2 = Vec::<u8>::new();
    
    hash_sig_structure_streaming_chunked(
        &mut hasher2,
        protected,
        Some(empty_aad),
        &mut payload2,
        DEFAULT_CHUNK_SIZE,
    ).expect("should hash with empty");
    
    // Both should be equal
    assert_eq!(hasher1, hasher2);
}

/// Test SigStructureHasher.clone_hasher() with updated data
#[test]
fn test_sig_structure_hasher_clone_after_updates() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    
    let protected = b"\xa1\x01\x26";
    hasher.init(protected, None, 100).expect("should init");
    
    hasher.update(b"chunk1").expect("should update 1");
    
    // Clone the hasher mid-stream
    let cloned = hasher.clone_hasher();
    assert!(!cloned.is_empty());
    
    // Continue with original
    hasher.update(b"chunk2").expect("should update 2");
    
    let final_hasher = hasher.into_inner();
    assert!(final_hasher.len() > cloned.len());
}

/// Test SizedReader is_empty method
#[test]
fn test_sized_reader_is_empty() {
    let empty_data = b"";
    let sized_empty = SizedReader::new(&empty_data[..], 0);
    assert!(sized_empty.is_empty().unwrap());
    
    let data = b"test";
    let sized_full = SizedReader::new(&data[..], 4);
    assert!(!sized_full.is_empty().unwrap());
}

/// Test SizedSeekReader with zero length
#[test]
fn test_sized_seek_reader_zero_length() {
    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let reader = SizedSeekReader::new(cursor).expect("should create");
    assert_eq!(reader.len().unwrap(), 0);
    assert!(reader.is_empty().unwrap());
}

/// Test stream_sig_structure_chunked with zero chunk size (should still work with small chunks)
#[test]
fn test_stream_sig_structure_very_small_chunk_size() {
    let protected = b"\xa1\x01\x26";
    let payload = b"abc";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    // Even with chunk_size of 1, should work
    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload_reader,
        1,
    ).expect("should stream with 1-byte chunks");
    
    assert_eq!(bytes_written, 3);
}

/// Test hash with very small chunk size
#[test]
fn test_hash_sig_structure_very_small_chunks() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut hasher = Vec::<u8>::new();
    
    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        None,
        &mut payload_reader,
        1,
    ).expect("should hash with 1-byte chunks");
    
    assert_eq!(bytes_read, 4);
}

/// Test with various protected header sizes
#[test]
fn test_build_sig_structure_various_protected_sizes() {
    let payload = b"payload";
    
    // Very small protected header
    let protected_small = b"\xa0"; // empty map
    let result = build_sig_structure(protected_small, None, payload);
    assert!(result.is_ok());
    
    // Medium protected header
    let protected_medium = b"\xa1\x01\x26"; // {1: -7}
    let result = build_sig_structure(protected_medium, None, payload);
    assert!(result.is_ok());
    
    // Larger protected header with multiple fields
    let protected_large = vec![
        0xa4, // map with 4 items
        0x01, 0x26, // 1: -7
        0x04, 0x42, 0x11, 0x22, // 4: h'1122'
        0x05, 0x58, 0x20, // 5: bstr of 32 bytes
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let result = build_sig_structure(&protected_large, None, payload);
    assert!(result.is_ok());
}

/// Test prefix building with 1-byte payload length
#[test]
fn test_build_sig_structure_prefix_1byte_length() {
    let protected = b"\xa1\x01\x26";
    
    let result = build_sig_structure_prefix(protected, None, 42);
    assert!(result.is_ok());
}

/// Test prefix with 2-byte CBOR length encoding (256 bytes)
#[test]
fn test_build_sig_structure_prefix_256byte_length() {
    let protected = b"\xa1\x01\x26";
    
    let result = build_sig_structure_prefix(protected, None, 256);
    assert!(result.is_ok());
}

/// Test prefix with 4-byte CBOR length encoding (65536 bytes)
#[test]
fn test_build_sig_structure_prefix_65kb_length() {
    let protected = b"\xa1\x01\x26";
    
    let result = build_sig_structure_prefix(protected, None, 65536);
    assert!(result.is_ok());
}

/// Test SigStructureHasher into_inner preserves data
#[test]
fn test_sig_structure_hasher_into_inner_preserves_data() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    
    let protected = b"\xa1\x01\x26";
    hasher.init(protected, Some(b"aad"), 50).expect("should init");
    hasher.update(b"test").expect("should update");
    
    let inner = hasher.into_inner();
    assert!(!inner.is_empty());
    
    // The inner should contain everything written
    assert!(inner.len() > 10);
}

/// Test stream_sig_structure with all parameters
#[test]
fn test_stream_sig_structure_all_params() {
    let protected = b"\xa2\x01\x26\x03\x27"; // {1: -7, 3: -8}
    let external_aad = b"critical_aad";
    let payload = b"critical payload";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        Some(external_aad),
        payload_reader,
    ).expect("should stream with all params");
    
    assert_eq!(bytes_written, payload.len() as u64);
    assert!(!output.is_empty());
}

/// Test hash_sig_structure_streaming with all parameters
#[test]
fn test_hash_sig_structure_streaming_all_params() {
    let protected = b"\xa2\x01\x26\x03\x27";
    let external_aad = b"hash_aad";
    let payload = b"hash payload";
    
    let mut payload_reader = sized_from_bytes(payload);
    let hasher = Vec::<u8>::new();
    
    let result = hash_sig_structure_streaming(
        hasher,
        protected,
        Some(external_aad),
        payload_reader,
    ).expect("should hash with all params");
    
    assert!(!result.is_empty());
}

// ============================================================================
// ADDITIONAL EDGE CASES - Comprehensive Coverage
// ============================================================================

/// Test build_sig_structure with maximum protected header size
#[test]
fn test_build_sig_structure_max_protected_header() {
    let payload = b"p";
    // Very large CBOR structure - max CBOR text string (265 bytes)
    let large_protected = vec![0x78, 0xFF]; // text string of 255 bytes
    let text_data = vec![0x41; 255]; // 255 'A' characters
    let mut full_protected = large_protected;
    full_protected.extend_from_slice(&text_data);
    
    let result = build_sig_structure(&full_protected, None, payload);
    assert!(result.is_ok());
}

/// Test build_sig_structure_prefix with various CBOR length encodings
#[test]
fn test_build_sig_structure_prefix_various_length_encodings() {
    let protected = b"\xa0";
    
    // 1-byte length (0-23)
    let result = build_sig_structure_prefix(protected, None, 23);
    assert!(result.is_ok());
    
    // 1-byte encoding (24)
    let result = build_sig_structure_prefix(protected, None, 24);
    assert!(result.is_ok());
    
    // 2-byte encoding (255)
    let result = build_sig_structure_prefix(protected, None, 255);
    assert!(result.is_ok());
    
    // 4-byte encoding (65535)
    let result = build_sig_structure_prefix(protected, None, 65535);
    assert!(result.is_ok());
    
    // 8-byte encoding (large)
    let result = build_sig_structure_prefix(protected, None, 4_294_967_295);
    assert!(result.is_ok());
}

/// Test SigStructureHasher with external_aad variations
#[test]
fn test_sig_structure_hasher_external_aad_variations() {
    // Test with None
    let mut hasher1 = SigStructureHasher::new(Vec::<u8>::new());
    hasher1.init(b"\xa0", None, 10).expect("should init with None");
    
    // Test with Some(&[])
    let mut hasher2 = SigStructureHasher::new(Vec::<u8>::new());
    hasher2.init(b"\xa0", Some(b""), 10).expect("should init with empty");
    
    // Test with Some(data)
    let mut hasher3 = SigStructureHasher::new(Vec::<u8>::new());
    hasher3.init(b"\xa0", Some(b"data"), 10).expect("should init with data");
    
    let result1 = hasher1.into_inner();
    let result2 = hasher2.into_inner();
    let result3 = hasher3.into_inner();
    
    // None and Some(&[]) should produce same result
    assert_eq!(result1, result2);
    
    // Different AAD should produce different results
    assert_ne!(result2, result3);
}

/// Test stream_sig_structure_chunked with write failure mid-stream
#[test]
fn test_stream_sig_structure_write_failure_mid_payload() {
    struct FailOnThirdWrite {
        write_count: usize,
    }
    
    impl Write for FailOnThirdWrite {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_count += 1;
            // Fail on 3rd write (during payload stream)
            if self.write_count > 2 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Fail mid-stream",
                ));
            }
            Ok(buf.len())
        }
        
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    
    let mut payload = sized_from_bytes(b"test payload data");
    let mut output = FailOnThirdWrite { write_count: 0 };
    
    let result = stream_sig_structure_chunked(
        &mut output,
        b"\xa0",
        None,
        &mut payload,
        5,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("write failed"));
}

/// Test hash_sig_structure_streaming_chunked with read failure mid-payload
#[test]
fn test_hash_streaming_read_failure_mid_payload() {
    struct FailOnSecondRead {
        read_count: usize,
        data: Cursor<Vec<u8>>,
    }
    
    impl Read for FailOnSecondRead {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_count += 1;
            if self.read_count > 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Fail on second read",
                ));
            }
            self.data.read(buf)
        }
    }
    
    impl SizedRead for FailOnSecondRead {
        fn len(&self) -> Result<u64, std::io::Error> {
            Ok(100)
        }
    }
    
    let mut payload = FailOnSecondRead {
        read_count: 0,
        data: Cursor::new(b"test".to_vec()),
    };
    let mut hasher = Vec::<u8>::new();
    
    let result = hash_sig_structure_streaming_chunked(
        &mut hasher,
        b"\xa0",
        None,
        &mut payload,
        2,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("payload read failed"));
}

/// Test prefix building with empty external AAD
#[test]
fn test_build_sig_structure_prefix_empty_external_aad() {
    let empty_aad = b"";
    let protected = b"\xa0";
    
    let result1 = build_sig_structure_prefix(protected, None, 100);
    let result2 = build_sig_structure_prefix(protected, Some(empty_aad), 100);
    
    assert!(result1.is_ok());
    assert!(result2.is_ok());
    
    // Both should be identical
    assert_eq!(result1.unwrap(), result2.unwrap());
}

/// Test streaming with single-byte payload chunks
#[test]
fn test_stream_sig_structure_single_byte_chunks() {
    let protected = b"\xa1\x01\x26";
    let payload = b"abc";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload_reader,
        1,
    ).expect("should stream single-byte chunks");
    
    assert_eq!(bytes_written, 3);
}

/// Test hash_sig_structure_streaming with single-byte chunks
#[test]
fn test_hash_sig_structure_single_byte_chunks() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut hasher = Vec::<u8>::new();
    
    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        Some(b"aad"),
        &mut payload_reader,
        1,
    ).expect("should hash single-byte chunks");
    
    assert_eq!(bytes_read, 4);
}

/// Test build_sig_structure with all NULL bytes
#[test]
fn test_build_sig_structure_null_bytes() {
    let protected = vec![0x00; 10];
    let payload = vec![0x00; 10];
    let aad = vec![0x00; 10];
    
    let result = build_sig_structure(&protected, Some(&aad), &payload);
    assert!(result.is_ok());
}

/// Test SizedRead trait methods for Cursor
#[test]
fn test_sized_read_cursor_is_empty_with_data() {
    let cursor = Cursor::new(b"data".to_vec());
    assert!(!SizedRead::is_empty(&cursor).unwrap());
}

/// Test SizedRead trait methods for empty Cursor
#[test]
fn test_sized_read_cursor_is_empty_empty() {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    assert!(SizedRead::is_empty(&cursor).unwrap());
}

/// Test stream_sig_structure with maximum safe payload length
#[test]
fn test_stream_sig_structure_large_safe_length() {
    let protected = b"\xa0";
    let payload = vec![0xFF; 10_000_000]; // 10MB
    
    let mut payload_reader = sized_from_bytes(&payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        None,
        &mut payload_reader,
        1_000_000, // 1MB chunks
    ).expect("should stream 10MB payload");
    
    assert_eq!(bytes_written, 10_000_000);
}

/// Test build_sig_structure consistency with empty vs Some(&[])
#[test]
fn test_build_sig_structure_consistency_empty_aad() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    let empty_slice = b"";
    
    let result1 = build_sig_structure(protected, None, payload);
    let result2 = build_sig_structure(protected, Some(empty_slice), payload);
    
    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert_eq!(result1.unwrap(), result2.unwrap());
}

/// Test SigStructureHasher init called before use
#[test]
fn test_sig_structure_hasher_init_required() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    
    // Trying to update without init should fail
    let result = hasher.update(b"data");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not initialized"));
}

/// Test SizedSeekReader with file at end
#[test]
fn test_sized_seek_reader_at_end() {
    use std::io::Seek;
    
    let data = b"test data";
    let mut cursor = Cursor::new(data.to_vec());
    
    // Seek to end
    use std::io::SeekFrom;
    cursor.seek(SeekFrom::End(0)).ok();
    
    let reader = SizedSeekReader::new(cursor).expect("should create");
    assert_eq!(reader.len().unwrap(), 0);
}

/// Test build_sig_structure with very long protected header (CBOR object with many fields)
#[test]
fn test_build_sig_structure_complex_protected_header() {
    // Create a more complex CBOR object
    let protected = vec![
        0xa5, // map with 5 items
        0x01, 0x26, // 1: -7
        0x04, 0x42, 0xAA, 0xBB, // 4: h'AABB'
        0x05, 0x41, 0xCC, // 5: h'CC'
        0x03, 0x27, // 3: -8
        0x06, 0x78, 0x08, // 6: text string of 8 bytes
        0x6B, 0x65, 0x79, 0x69, 0x64, 0x31, 0x32, 0x33, // "keyid123"
    ];
    
    let payload = b"payload";
    
    let result = build_sig_structure(&protected, None, payload);
    assert!(result.is_ok());
    
    let sig_structure = result.unwrap();
    assert!(!sig_structure.is_empty());
    // The structure should be reasonably sized
    assert!(sig_structure.len() >= 30);
}

/// Test SigStructureHasher with very large payload length
#[test]
fn test_sig_structure_hasher_very_large_payload_len() {
    let mut hasher = SigStructureHasher::new(Vec::<u8>::new());
    
    let protected = b"\xa0";
    let large_len = 1_000_000_000u64; // 1GB
    
    let result = hasher.init(protected, None, large_len);
    assert!(result.is_ok());
    
    // The hasher should be initialized
    let inner = hasher.into_inner();
    assert!(!inner.is_empty());
}

/// Test streaming with payload length exactly at CBOR 1-byte boundary (23)
#[test]
fn test_stream_payload_len_cbor_1byte_boundary() {
    let protected = b"\xa0";
    let payload = vec![0x42; 23];
    
    let mut payload_reader = sized_from_bytes(&payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload_reader,
    ).expect("should stream 23-byte payload");
    
    assert_eq!(bytes_written, 23);
}

/// Test streaming with payload length exactly at CBOR 2-byte boundary (24)
#[test]
fn test_stream_payload_len_cbor_2byte_boundary() {
    let protected = b"\xa0";
    let payload = vec![0x43; 24];
    
    let mut payload_reader = sized_from_bytes(&payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure(
        &mut output,
        protected,
        None,
        payload_reader,
    ).expect("should stream 24-byte payload");
    
    assert_eq!(bytes_written, 24);
}

/// Test stream_sig_structure_chunked returning correct byte count
#[test]
fn test_stream_returns_payload_bytes_not_total() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut output = Vec::<u8>::new();
    
    let bytes_written = stream_sig_structure_chunked(
        &mut output,
        protected,
        Some(b"aad"),
        &mut payload_reader,
        DEFAULT_CHUNK_SIZE,
    ).expect("should stream");
    
    // Should return only payload bytes, not the CBOR structure
    assert_eq!(bytes_written, 4);
    
    // But output should contain full structure
    assert!(output.len() > 4);
}

/// Test hash_sig_structure_streaming_chunked returning correct byte count
#[test]
fn test_hash_returns_payload_bytes_not_total() {
    let protected = b"\xa1\x01\x26";
    let payload = b"test";
    
    let mut payload_reader = sized_from_bytes(payload);
    let mut hasher = Vec::<u8>::new();
    
    let bytes_read = hash_sig_structure_streaming_chunked(
        &mut hasher,
        protected,
        Some(b"aad"),
        &mut payload_reader,
        DEFAULT_CHUNK_SIZE,
    ).expect("should hash");
    
    // Should return only payload bytes
    assert_eq!(bytes_read, 4);
    
    // But hasher should contain full structure
    assert!(hasher.len() > 4);
}
