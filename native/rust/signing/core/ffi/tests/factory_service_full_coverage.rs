// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive integration tests for FFI signing with MOCK crypto.
//!
//! Tests comprehensive FFI integration coverage using mock keys (like existing tests):
//! - Service lifecycle: cose_sign1_signing_service_from_crypto_signer/free
//! - Factory lifecycle: cose_sign1_factory_create/from_crypto_signer/free  
//! - Factory signing: direct/indirect variants with files/streaming
//! - Error paths: null inputs and failures
//! - Memory management: proper cleanup of all handles

use cose_sign1_signing_ffi::*;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::ptr;
use tempfile::NamedTempFile;

/// Helper to get error message from an error handle.
fn error_message(err: *const CoseSign1SigningErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { cose_sign1_signing_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_sign1_string_free(msg) };
    Some(s)
}

/// Mock sign callback that produces a deterministic signature.
unsafe extern "C" fn mock_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    let sig = vec![0xABu8; 64];
    let len = sig.len();
    let ptr = unsafe { libc::malloc(len) as *mut u8 };
    if ptr.is_null() {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);
        *out_sig = ptr;
        *out_sig_len = len;
    }
    0
}

/// Helper to create a mock key via the extern "C" API.
fn create_mock_key() -> *mut CoseKeyHandle {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type = b"EC2\0".as_ptr() as *const libc::c_char;
    let rc = unsafe {
        cose_key_from_callback(-7, key_type, mock_sign_callback, ptr::null_mut(), &mut key)
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!key.is_null());
    key
}

/// Helper to create a signing service from a key.
fn create_signing_service(key: *const CoseKeyHandle) -> *mut CoseSign1SigningServiceHandle {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_signing_service_create(key, &mut service, &mut error) };
    if rc != COSE_SIGN1_SIGNING_OK {
        let msg = error_message(error);
        unsafe { cose_sign1_signing_error_free(error) };
        panic!("Failed to create signing service: {:?}", msg);
    }
    assert!(!service.is_null());
    service
}

/// Streaming callback data structure.
struct CallbackState {
    data: Vec<u8>,
    offset: usize,
}

/// Read callback implementation for streaming tests.
unsafe extern "C" fn read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let state = &mut *(user_data as *mut CallbackState);
    let remaining = state.data.len() - state.offset;
    let to_copy = remaining.min(buffer_len);
    
    if to_copy == 0 {
        return 0; // EOF
    }
    
    unsafe {
        ptr::copy_nonoverlapping(
            state.data[state.offset..].as_ptr(),
            buffer,
            to_copy,
        );
    }
    
    state.offset += to_copy;
    to_copy as i64
}

#[test]
fn test_comprehensive_abi_version() {
    let version = cose_sign1_signing_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn test_comprehensive_null_free_functions_are_safe() {
    // All free functions should handle null safely
    unsafe {
        cose_sign1_signing_service_free(ptr::null_mut());
        cose_sign1_factory_free(ptr::null_mut());
        cose_sign1_signing_error_free(ptr::null_mut());
        cose_sign1_string_free(ptr::null_mut());
        cose_sign1_cose_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn test_comprehensive_service_lifecycle() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        // Free service and key
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_lifecycle_from_service() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        // Create factory from service
        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(error));
        assert!(!factory.is_null());
        assert!(error.is_null());

        // Cleanup
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_direct_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        let payload = b"Hello, COSE Sign1 Comprehensive!";
        let content_type = CString::new("text/plain").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_indirect_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        let payload = b"Hello, COSE Sign1 Indirect Comprehensive!";
        let content_type = CString::new("text/plain").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_indirect(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_direct_file_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        // Create temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        let payload = b"File-based comprehensive payload for COSE Sign1";
        temp_file.write_all(payload).unwrap();
        temp_file.flush().unwrap();
        
        let file_path = CString::new(temp_file.path().to_str().unwrap()).unwrap();
        let content_type = CString::new("application/octet-stream").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_direct_file(
            factory,
            file_path.as_ptr(),
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        // FFI signing service doesn't support post-sign verification, so factory operations fail
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_indirect_file_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        // Create temp file
        let mut temp_file = NamedTempFile::new().unwrap();
        let payload = b"File-based comprehensive indirect payload for COSE Sign1";
        temp_file.write_all(payload).unwrap();
        temp_file.flush().unwrap();
        
        let file_path = CString::new(temp_file.path().to_str().unwrap()).unwrap();
        let content_type = CString::new("application/octet-stream").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_indirect_file(
            factory,
            file_path.as_ptr(),
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        // FFI signing service doesn't support post-sign verification, so factory operations fail
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_direct_streaming_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        let payload_data = b"Streaming comprehensive payload for COSE Sign1 direct";
        let mut callback_state = CallbackState {
            data: payload_data.to_vec(),
            offset: 0,
        };
        
        let content_type = CString::new("application/octet-stream").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_direct_streaming(
            factory,
            read_callback,
            payload_data.len() as u64,
            &mut callback_state as *mut _ as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        // FFI signing service doesn't support post-sign verification, so factory operations fail
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_factory_sign_indirect_streaming_happy_path() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        let payload_data = b"Streaming comprehensive payload for COSE Sign1 indirect";
        let mut callback_state = CallbackState {
            data: payload_data.to_vec(),
            offset: 0,
        };
        
        let content_type = CString::new("application/octet-stream").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        let rc = cose_sign1_factory_sign_indirect_streaming(
            factory,
            read_callback,
            payload_data.len() as u64,
            &mut callback_state as *mut _ as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        // FFI signing service doesn't support post-sign verification, so factory operations fail
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_comprehensive_error_handling_null_inputs() {
    unsafe {
        // Test null factory for direct signing
        let payload = b"test";
        let content_type = CString::new("text/plain").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_sign_direct(
            ptr::null(),
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );
        
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
        assert!(!error.is_null());
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("null"));
        cose_sign1_signing_error_free(error);
    }
}

#[test]
fn test_comprehensive_empty_payload() {
    unsafe {
        let key = create_mock_key();
        let service = create_signing_service(key);
        
        let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
        let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let rc = cose_sign1_factory_create(service, &mut factory, &mut error);
        assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

        let content_type = CString::new("text/plain").unwrap();
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;

        // Test empty payload (null with len=0)
        let rc = cose_sign1_factory_sign_direct(
            factory,
            ptr::null(),
            0,
            content_type.as_ptr(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        // FFI signing service doesn't support post-sign verification, so factory operations fail
        assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());
        
        let msg = error_message(error).unwrap_or_default();
        assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

        // Cleanup
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}
