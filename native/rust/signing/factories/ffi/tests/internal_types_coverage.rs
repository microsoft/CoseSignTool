// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for internal types in the signing/factories/ffi crate.

use std::sync::Arc;
use crypto_primitives::CryptoSigner;
use cose_sign1_signing::{SigningService, SigningContext};
use cose_sign1_primitives::{StreamingPayload, sig_structure::SizedRead};
use std::io::Read;

// Import the internal types we want to test
use cose_sign1_factories_ffi::{CallbackStreamingPayload, CallbackReader, SimpleSigningService, SimpleKeyWrapper};

// Mock data for testing callback functions
struct MockData {
    bytes: Vec<u8>,
    position: usize,
}

// Mock crypto signer for testing
struct MockCryptoSigner {
    algorithm: i64,
    key_type: String,
}

impl MockCryptoSigner {
    fn new(algorithm: i64, key_type: String) -> Self {
        Self { algorithm, key_type }
    }
}

impl CryptoSigner for MockCryptoSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        // Return fake signature based on data length
        Ok(format!("signature-for-{}-bytes", data.len()).into_bytes())
    }
    
    fn algorithm(&self) -> i64 {
        self.algorithm
    }
    
    fn key_type(&self) -> &str {
        &self.key_type
    }
    
    fn key_id(&self) -> Option<&[u8]> {
        Some(b"test-key-id")
    }
    
    fn supports_streaming(&self) -> bool {
        false
    }
}

// Mock callback function that reads from Vec<u8>
unsafe extern "C" fn mock_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let mock_data = &mut *(user_data as *mut MockData);
    
    let available = mock_data.bytes.len() - mock_data.position;
    let to_copy = buffer_len.min(available);
    
    if to_copy == 0 {
        return 0; // EOF
    }
    
    // Copy data to buffer
    std::ptr::copy_nonoverlapping(
        mock_data.bytes.as_ptr().add(mock_data.position),
        buffer,
        to_copy,
    );
    
    mock_data.position += to_copy;
    to_copy as i64
}

// Mock callback that always returns an error
unsafe extern "C" fn error_read_callback(
    _buffer: *mut u8,
    _buffer_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    -1 // Simulate error
}

// Tests for CallbackStreamingPayload
#[test]
fn test_callback_streaming_payload_open_read_close() {
    let test_data = b"Hello, World!".to_vec();
    let mut mock_data = MockData {
        bytes: test_data.clone(),
        position: 0,
    };
    
    let payload = CallbackStreamingPayload {
        callback: mock_read_callback,
        user_data: &mut mock_data as *mut _ as *mut libc::c_void,
        total_len: test_data.len() as u64,
    };
    
    assert_eq!(payload.size(), test_data.len() as u64);
    
    let mut reader = payload.open().expect("Should open successfully");
    assert_eq!(reader.len().expect("Should get size"), test_data.len() as u64);
    
    let mut buffer = vec![0u8; test_data.len()];
    let bytes_read = reader.read(&mut buffer).expect("Should read successfully");
    assert_eq!(bytes_read, test_data.len());
    assert_eq!(buffer, test_data);
}

#[test]
fn test_callback_reader_returns_bytes() {
    let test_data = b"Test data".to_vec();
    let mut mock_data = MockData {
        bytes: test_data.clone(),
        position: 0,
    };
    
    let mut reader = CallbackReader {
        callback: mock_read_callback,
        user_data: &mut mock_data as *mut _ as *mut libc::c_void,
        total_len: test_data.len() as u64,
        bytes_read: 0,
    };
    
    let mut buffer = vec![0u8; 5];
    let bytes_read = reader.read(&mut buffer).expect("Should read successfully");
    assert_eq!(bytes_read, 5);
    assert_eq!(&buffer, b"Test ");
    
    // Read the rest
    let mut buffer2 = vec![0u8; 10];
    let bytes_read2 = reader.read(&mut buffer2).expect("Should read successfully");
    assert_eq!(bytes_read2, 4);
    assert_eq!(&buffer2[..4], b"data");
}

#[test]
fn test_callback_reader_eof_returns_zero() {
    let test_data = b"Short".to_vec();
    let mut mock_data = MockData {
        bytes: test_data.clone(),
        position: 0,
    };
    
    let mut reader = CallbackReader {
        callback: mock_read_callback,
        user_data: &mut mock_data as *mut _ as *mut libc::c_void,
        total_len: test_data.len() as u64,
        bytes_read: 0,
    };
    
    // Read all data
    let mut buffer = vec![0u8; test_data.len()];
    let bytes_read = reader.read(&mut buffer).expect("Should read successfully");
    assert_eq!(bytes_read, test_data.len());
    
    // Try to read more - should return 0 (EOF)
    let mut buffer2 = vec![0u8; 10];
    let bytes_read2 = reader.read(&mut buffer2).expect("Should read successfully");
    assert_eq!(bytes_read2, 0);
}

#[test]
fn test_callback_reader_error_on_negative() {
    let mut mock_data = MockData {
        bytes: vec![],
        position: 0,
    };
    
    let mut reader = CallbackReader {
        callback: error_read_callback,
        user_data: &mut mock_data as *mut _ as *mut libc::c_void,
        total_len: 10,
        bytes_read: 0,
    };
    
    let mut buffer = vec![0u8; 5];
    let result = reader.read(&mut buffer);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("callback read error: -1"));
}

#[test]
fn test_callback_reader_sized_read_len() {
    let test_data = b"Test".to_vec();
    let mut mock_data = MockData {
        bytes: test_data.clone(),
        position: 0,
    };
    
    let reader = CallbackReader {
        callback: mock_read_callback,
        user_data: &mut mock_data as *mut _ as *mut libc::c_void,
        total_len: test_data.len() as u64,
        bytes_read: 0,
    };
    
    assert_eq!(reader.len().expect("Should get length"), test_data.len() as u64);
}

// Tests for SimpleSigningService 
#[test]
fn test_simple_signing_service_get_cose_signer() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let service = SimpleSigningService::new(mock_signer);
    
    let context = SigningContext::from_bytes(b"test payload".to_vec());
    let cose_signer = service.get_cose_signer(&context).expect("Should create signer");
    
    assert_eq!(cose_signer.signer().algorithm(), -7);
    assert_eq!(cose_signer.signer().key_type(), "ECDSA");
}

#[test]
fn test_simple_signing_service_is_remote() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let service = SimpleSigningService::new(mock_signer);
    
    assert!(!service.is_remote());
}

#[test]
fn test_simple_signing_service_metadata() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let service = SimpleSigningService::new(mock_signer);
    
    let metadata = service.service_metadata();
    assert_eq!(metadata.service_name, "Simple Signing Service");
    assert_eq!(metadata.service_description, "FFI-based signing service wrapping a CryptoSigner");
}

#[test]
fn test_simple_signing_service_verify_signature() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let service = SimpleSigningService::new(mock_signer);
    
    let context = SigningContext::from_bytes(b"test payload".to_vec());
    let message = b"test message";
    let result = service.verify_signature(message, &context).expect("Should verify");
    
    // Simple service always returns true
    assert!(result);
}

// Tests for SimpleKeyWrapper
#[test]
fn test_simple_key_wrapper_sign() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let wrapper = SimpleKeyWrapper {
        key: mock_signer,
    };
    
    let data = b"test data";
    let signature = wrapper.sign(data).expect("Should sign successfully");
    assert_eq!(signature, b"signature-for-9-bytes".to_vec());
}

#[test]
fn test_simple_key_wrapper_algorithm() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-35, "RSA".to_string()));
    let wrapper = SimpleKeyWrapper {
        key: mock_signer,
    };
    
    assert_eq!(wrapper.algorithm(), -35);
}

#[test]
fn test_simple_key_wrapper_key_type() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let wrapper = SimpleKeyWrapper {
        key: mock_signer,
    };
    
    assert_eq!(wrapper.key_type(), "ECDSA");
}

#[test]
fn test_simple_key_wrapper_key_id() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let wrapper = SimpleKeyWrapper {
        key: mock_signer,
    };
    
    assert_eq!(wrapper.key_id(), Some(b"test-key-id".as_slice()));
}

#[test]
fn test_simple_key_wrapper_supports_streaming() {
    let mock_signer = Arc::new(MockCryptoSigner::new(-7, "ECDSA".to_string()));
    let wrapper = SimpleKeyWrapper {
        key: mock_signer,
    };
    
    assert!(!wrapper.supports_streaming());
}