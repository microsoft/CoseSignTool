// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for payload types and operations.

use cose_sign1_primitives::payload::{FilePayload, MemoryPayload, Payload, StreamingPayload};
use cose_sign1_primitives::SizedRead;
use std::io::{Cursor, Read};

#[test]
fn test_memory_payload_new() {
    let data = vec![1, 2, 3, 4, 5];
    let payload = MemoryPayload::new(data.clone());

    assert_eq!(payload.data(), &data[..]);
}

#[test]
fn test_memory_payload_data() {
    let data = b"hello world";
    let payload = MemoryPayload::new(data.to_vec());

    assert_eq!(payload.data(), data);
}

#[test]
fn test_memory_payload_into_data() {
    let data = vec![1, 2, 3, 4, 5];
    let payload = MemoryPayload::new(data.clone());

    let extracted = payload.into_data();
    assert_eq!(extracted, data);
}

#[test]
fn test_memory_payload_from_vec() {
    let data = vec![1, 2, 3, 4];
    let payload: MemoryPayload = data.clone().into();

    assert_eq!(payload.data(), &data[..]);
}

#[test]
fn test_memory_payload_from_slice() {
    let data = b"test data";
    let payload: MemoryPayload = data.as_slice().into();

    assert_eq!(payload.data(), data);
}

#[test]
fn test_memory_payload_size() {
    let data = vec![1, 2, 3, 4, 5];
    let payload = MemoryPayload::new(data.clone());

    assert_eq!(payload.size(), data.len() as u64);
}

#[test]
fn test_memory_payload_open() {
    let data = b"hello world";
    let payload = MemoryPayload::new(data.to_vec());

    let mut reader = payload.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");

    assert_eq!(buffer, data);
}

#[test]
fn test_memory_payload_open_multiple_times() {
    let data = b"test data";
    let payload = MemoryPayload::new(data.to_vec());

    // First read
    let mut reader1 = payload.open().expect("open failed");
    let mut buffer1 = Vec::new();
    reader1.read_to_end(&mut buffer1).expect("read failed");
    assert_eq!(buffer1, data);

    // Second read
    let mut reader2 = payload.open().expect("open failed");
    let mut buffer2 = Vec::new();
    reader2.read_to_end(&mut buffer2).expect("read failed");
    assert_eq!(buffer2, data);
}

#[test]
fn test_memory_payload_clone() {
    let data = vec![1, 2, 3, 4];
    let payload = MemoryPayload::new(data.clone());
    let cloned = payload.clone();

    assert_eq!(cloned.data(), &data[..]);
}

#[test]
fn test_file_payload_new_nonexistent() {
    let result = FilePayload::new("nonexistent_file_xyz123.bin");
    assert!(result.is_err());
}

#[test]
fn test_file_payload_new_valid() {
    // Create a temporary file
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_file.bin");

    let data = b"test file content";
    std::fs::write(&file_path, data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");

    assert_eq!(payload.path(), file_path.as_path());
    assert_eq!(payload.size(), data.len() as u64);

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_file_payload_open() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_open.bin");

    let data = b"hello from file";
    std::fs::write(&file_path, data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");

    let mut reader = payload.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");

    assert_eq!(buffer, data);

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_file_payload_open_multiple_times() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_multiple.bin");

    let data = b"test data for multiple reads";
    std::fs::write(&file_path, data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");

    // First read
    let mut reader1 = payload.open().expect("open failed");
    let mut buffer1 = Vec::new();
    reader1.read_to_end(&mut buffer1).expect("read failed");
    assert_eq!(buffer1, data);

    // Second read
    let mut reader2 = payload.open().expect("open failed");
    let mut buffer2 = Vec::new();
    reader2.read_to_end(&mut buffer2).expect("read failed");
    assert_eq!(buffer2, data);

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_file_payload_clone() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_clone.bin");

    let data = b"clone test";
    std::fs::write(&file_path, data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");
    let cloned = payload.clone();

    assert_eq!(cloned.path(), payload.path());
    assert_eq!(cloned.size(), payload.size());

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_file_payload_large_file() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_large.bin");

    // Create a 1 MB file
    let size = 1024 * 1024;
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    std::fs::write(&file_path, &data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");
    assert_eq!(payload.size(), size as u64);

    let mut reader = payload.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");

    assert_eq!(buffer.len(), size);
    assert_eq!(buffer[0], 0);
    assert_eq!(buffer[255], 255);
    assert_eq!(buffer[256], 0);

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_payload_from_vec() {
    let data = vec![1, 2, 3, 4];
    let payload: Payload = data.clone().into();

    assert_eq!(payload.size(), data.len() as u64);
    assert_eq!(payload.as_bytes(), Some(data.as_slice()));
    assert!(!payload.is_streaming());
}

#[test]
fn test_payload_from_slice() {
    let data = b"test bytes";
    let payload: Payload = data.as_slice().into();

    assert_eq!(payload.size(), data.len() as u64);
    assert_eq!(payload.as_bytes(), Some(data.as_slice()));
    assert!(!payload.is_streaming());
}

#[test]
fn test_payload_bytes_variant() {
    let data = vec![5, 6, 7, 8];
    let payload = Payload::Bytes(data.clone());

    assert_eq!(payload.size(), data.len() as u64);
    assert_eq!(payload.as_bytes(), Some(data.as_slice()));
    assert!(!payload.is_streaming());
}

#[test]
fn test_payload_streaming_variant() {
    let memory_payload = MemoryPayload::new(vec![1, 2, 3, 4, 5]);
    let size = memory_payload.size();
    let payload = Payload::Streaming(Box::new(memory_payload));

    assert_eq!(payload.size(), size);
    assert!(payload.is_streaming());
    assert_eq!(payload.as_bytes(), None);
}

#[test]
fn test_payload_size_bytes() {
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let payload = Payload::Bytes(data.clone());

    assert_eq!(payload.size(), 10);
}

#[test]
fn test_payload_size_streaming() {
    let memory_payload = MemoryPayload::new(vec![1; 1000]);
    let payload = Payload::Streaming(Box::new(memory_payload));

    assert_eq!(payload.size(), 1000);
}

#[test]
fn test_payload_is_streaming_bytes() {
    let payload = Payload::Bytes(vec![1, 2, 3]);
    assert!(!payload.is_streaming());
}

#[test]
fn test_payload_is_streaming_streaming() {
    let memory_payload = MemoryPayload::new(vec![1, 2, 3]);
    let payload = Payload::Streaming(Box::new(memory_payload));
    assert!(payload.is_streaming());
}

#[test]
fn test_payload_as_bytes_returns_some_for_bytes() {
    let data = vec![1, 2, 3, 4];
    let payload = Payload::Bytes(data.clone());

    let bytes = payload.as_bytes();
    assert!(bytes.is_some());
    assert_eq!(bytes.unwrap(), data.as_slice());
}

#[test]
fn test_payload_as_bytes_returns_none_for_streaming() {
    let memory_payload = MemoryPayload::new(vec![1, 2, 3]);
    let payload = Payload::Streaming(Box::new(memory_payload));

    assert_eq!(payload.as_bytes(), None);
}

// Mock StreamingPayload implementation for testing
struct MockStreamingPayload {
    data: Vec<u8>,
    size: u64,
}

impl MockStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        let size = data.len() as u64;
        Self { data, size }
    }
}

impl StreamingPayload for MockStreamingPayload {
    fn size(&self) -> u64 {
        self.size
    }

    fn open(
        &self,
    ) -> Result<Box<dyn SizedRead + Send>, cose_sign1_primitives::error::PayloadError> {
        Ok(Box::new(Cursor::new(self.data.clone())))
    }
}

#[test]
fn test_mock_streaming_payload_size() {
    let data = vec![1, 2, 3, 4, 5];
    let mock = MockStreamingPayload::new(data.clone());

    assert_eq!(mock.size(), data.len() as u64);
}

#[test]
fn test_mock_streaming_payload_open() {
    let data = b"mock payload data";
    let mock = MockStreamingPayload::new(data.to_vec());

    let mut reader = mock.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");

    assert_eq!(buffer, data);
}

#[test]
fn test_mock_streaming_payload_multiple_opens() {
    let data = b"test data";
    let mock = MockStreamingPayload::new(data.to_vec());

    // First read
    let mut reader1 = mock.open().expect("open failed");
    let mut buffer1 = Vec::new();
    reader1.read_to_end(&mut buffer1).expect("read failed");
    assert_eq!(buffer1, data);

    // Second read
    let mut reader2 = mock.open().expect("open failed");
    let mut buffer2 = Vec::new();
    reader2.read_to_end(&mut buffer2).expect("read failed");
    assert_eq!(buffer2, data);
}

#[test]
fn test_payload_with_mock_streaming() {
    let data = vec![10, 20, 30, 40];
    let mock = MockStreamingPayload::new(data.clone());
    let payload = Payload::Streaming(Box::new(mock));

    assert_eq!(payload.size(), data.len() as u64);
    assert!(payload.is_streaming());
    assert_eq!(payload.as_bytes(), None);
}

#[test]
fn test_memory_payload_empty() {
    let payload = MemoryPayload::new(Vec::new());

    assert_eq!(payload.size(), 0);
    assert_eq!(payload.data(), &[]);
}

#[test]
fn test_payload_bytes_empty() {
    let payload = Payload::Bytes(Vec::new());

    assert_eq!(payload.size(), 0);
    assert_eq!(payload.as_bytes(), Some(&[][..]));
    assert!(!payload.is_streaming());
}

#[test]
fn test_file_payload_empty_file() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_empty.bin");

    // Create an empty file
    std::fs::write(&file_path, b"").expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");
    assert_eq!(payload.size(), 0);

    let mut reader = payload.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");
    assert_eq!(buffer.len(), 0);

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_memory_payload_large() {
    let size = 10_000;
    let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
    let payload = MemoryPayload::new(data.clone());

    assert_eq!(payload.size(), size as u64);
    assert_eq!(payload.data().len(), size);

    let mut reader = payload.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");
    assert_eq!(buffer, data);
}

#[test]
fn test_memory_payload_partial_read() {
    let data = b"hello world from memory";
    let payload = MemoryPayload::new(data.to_vec());

    let mut reader = payload.open().expect("open failed");
    let mut buffer = [0u8; 5];
    reader.read_exact(&mut buffer).expect("read failed");

    assert_eq!(&buffer, b"hello");
}

#[test]
fn test_file_payload_partial_read() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_partial.bin");

    let data = b"hello world from file";
    std::fs::write(&file_path, data).expect("write failed");

    let payload = FilePayload::new(&file_path).expect("FilePayload::new failed");

    let mut reader = payload.open().expect("open failed");
    let mut buffer = [0u8; 5];
    reader.read_exact(&mut buffer).expect("read failed");

    assert_eq!(&buffer, b"hello");

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}

#[test]
fn test_mock_streaming_payload_empty() {
    let mock = MockStreamingPayload::new(Vec::new());

    assert_eq!(mock.size(), 0);

    let mut reader = mock.open().expect("open failed");
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).expect("read failed");
    assert_eq!(buffer.len(), 0);
}

#[test]
fn test_payload_streaming_with_file_payload() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join("test_payload_streaming_file.bin");

    let data = b"streaming file test";
    std::fs::write(&file_path, data).expect("write failed");

    let file_payload = FilePayload::new(&file_path).expect("FilePayload::new failed");
    let payload = Payload::Streaming(Box::new(file_payload));

    assert_eq!(payload.size(), data.len() as u64);
    assert!(payload.is_streaming());

    // Cleanup
    std::fs::remove_file(&file_path).ok();
}
