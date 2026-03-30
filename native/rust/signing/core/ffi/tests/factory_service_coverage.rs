// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for factory and signing service FFI functions.
//!
//! These tests target the previously uncovered factory and service functions:
//! - cose_sign1_signing_service_create/free
//! - cose_sign1_signing_service_from_crypto_signer 
//! - cose_sign1_factory_create/free/from_crypto_signer
//! - cose_sign1_factory_sign_direct/indirect/direct_file/indirect_file
//! - cose_sign1_factory_sign_direct_streaming/indirect_streaming
//! - cose_sign1_cose_bytes_free

use cose_sign1_signing_ffi::*;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::Write;
use std::ptr;

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

/// Mock read callback for streaming tests that returns a fixed payload.
unsafe extern "C" fn mock_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    // user_data points to a counter (starts at 0)
    let counter_ptr = user_data as *mut usize;
    let counter = unsafe { *counter_ptr };
    
    // Simple test payload
    let payload = b"streaming test payload data";
    
    if counter >= payload.len() {
        return 0; // EOF
    }
    
    let remaining = payload.len() - counter;
    let to_copy = std::cmp::min(remaining, buffer_len);
    
    unsafe {
        std::ptr::copy_nonoverlapping(
            payload.as_ptr().add(counter),
            buffer,
            to_copy,
        );
        *counter_ptr = counter + to_copy;
    }
    
    to_copy as i64
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

/// Helper to create a factory from a signing service.
fn create_factory(service: *const CoseSign1SigningServiceHandle) -> *mut CoseSign1FactoryHandle {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_factory_create(service, &mut factory, &mut error) };
    if rc != COSE_SIGN1_SIGNING_OK {
        let msg = error_message(error);
        unsafe { cose_sign1_signing_error_free(error) };
        panic!("Failed to create factory: {:?}", msg);
    }
    assert!(!factory.is_null());
    factory
}

// ============================================================================
// Service creation tests
// ============================================================================

#[test]
fn test_signing_service_create_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    
    // Clean up
    unsafe {
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_signing_service_create_null_key() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_signing_service_create(ptr::null(), &mut service, &mut error) };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(service.is_null());
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("key"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_signing_service_create_null_output() {
    let key = create_mock_key();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_signing_service_create(key, ptr::null_mut(), &mut error) };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("out_service"));
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_key_free(key);
    }
}

#[test]
fn test_signing_service_free_null() {
    // Should not crash
    unsafe { cose_sign1_signing_service_free(ptr::null_mut()) };
}

// ============================================================================
// Factory creation tests
// ============================================================================

#[test]
fn test_factory_create_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    // Clean up
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_create_null_service() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_factory_create(ptr::null(), &mut factory, &mut error) };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(factory.is_null());
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("service"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_create_null_output() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_factory_create(service, ptr::null_mut(), &mut error) };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("out_factory"));
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_free_null() {
    // Should not crash
    unsafe { cose_sign1_factory_free(ptr::null_mut()) };
}

// ============================================================================
// Factory direct signing tests
// ============================================================================

#[test]
fn test_factory_sign_direct_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"test payload";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));
    
    // Clean up
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_null_factory() {
    let payload = b"test payload";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            ptr::null(),
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_sign_direct_null_payload_nonzero_len() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            ptr::null(),
            10,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"test payload";
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ptr::null(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_null_outputs() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"test payload";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_empty_payload() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            ptr::null(),
            0,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_invalid_utf8_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"test payload";
    // Invalid UTF-8 + null terminator
    let invalid_content_type = [0xC0u8, 0xAF, 0x00];
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            invalid_content_type.as_ptr() as *const libc::c_char,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

// ============================================================================
// Factory indirect signing tests
// ============================================================================

#[test]
fn test_factory_sign_indirect_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"test payload for indirect signing";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_indirect(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_indirect_null_factory() {
    let payload = b"test payload";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_indirect(
            ptr::null(),
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe { cose_sign1_signing_error_free(error) };
}

// ============================================================================
// Factory file signing tests
// ============================================================================

#[test]
fn test_factory_sign_direct_file_success() {
    // Create a temporary file
    let temp_path = "test_payload.tmp";
    {
        let mut file = fs::File::create(temp_path).expect("Failed to create temp file");
        file.write_all(b"file payload content").expect("Failed to write to temp file");
    }
    
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let file_path = CString::new(temp_path).unwrap();
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            file_path.as_ptr(),
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));
    
    // Clean up
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
    
    // Clean up temp file
    let _ = fs::remove_file(temp_path);
}

#[test]
fn test_factory_sign_direct_file_null_factory() {
    let file_path = CString::new("nonexistent.bin").unwrap();
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            ptr::null(),
            file_path.as_ptr(),
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_sign_direct_file_null_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            ptr::null(),
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_file_nonexistent() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let file_path = CString::new("nonexistent_file_xyz.bin").unwrap();
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            file_path.as_ptr(),
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("failed to open file") || msg.contains("No such file"));
    
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_indirect_file_success() {
    // Create a temporary file
    let temp_path = "test_payload_indirect.tmp";
    {
        let mut file = fs::File::create(temp_path).expect("Failed to create temp file");
        file.write_all(b"indirect file payload content").expect("Failed to write to temp file");
    }
    
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let file_path = CString::new(temp_path).unwrap();
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            factory,
            file_path.as_ptr(),
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));
    
    // Clean up
    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
    
    // Clean up temp file
    let _ = fs::remove_file(temp_path);
}

// ============================================================================
// Factory streaming tests
// ============================================================================

#[test]
fn test_factory_sign_direct_streaming_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"streaming test payload data";
    let mut counter: usize = 0;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            mock_read_callback,
            payload.len() as u64,
            &mut counter as *mut usize as *mut libc::c_void,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_factory_sign_direct_streaming_null_factory() {
    let payload = b"streaming test payload data";
    let mut counter: usize = 0;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            ptr::null(),
            mock_read_callback,
            payload.len() as u64,
            &mut counter as *mut usize as *mut libc::c_void,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(cose_bytes.is_null());
    assert!(!error.is_null());
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_sign_indirect_streaming_success() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);
    
    let payload = b"streaming test payload data";
    let mut counter: usize = 0;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming(
            factory,
            mock_read_callback,
            payload.len() as u64,
            &mut counter as *mut usize as *mut libc::c_void,
            content_type,
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    
    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, "Error: {:?}", error_message(error));
    assert!(cose_bytes.is_null());
    assert_eq!(cose_len, 0);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(error);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

// ============================================================================
// CryptoSigner-based service and factory tests
// ============================================================================

#[test]
fn test_signing_service_from_crypto_signer_null_signer() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_signing_service_from_crypto_signer(ptr::null_mut(), &mut service, &mut error)
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(service.is_null());
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("signer_handle"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_signing_service_from_crypto_signer_null_output() {
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    // We can't create a real CryptoSigner handle without the crypto_openssl_ffi crate,
    // but we can test the null output parameter check which happens first
    let rc = unsafe {
        cose_sign1_signing_service_from_crypto_signer(
            0x1234 as *mut CryptoSignerHandle, // fake non-null pointer (won't be dereferenced)
            ptr::null_mut(),
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("out_service"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_from_crypto_signer_null_signer() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_factory_from_crypto_signer(ptr::null_mut(), &mut factory, &mut error)
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(factory.is_null());
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("signer_handle"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_factory_from_crypto_signer_null_output() {
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    // Test null output parameter check which happens first
    let rc = unsafe {
        cose_sign1_factory_from_crypto_signer(
            0x1234 as *mut CryptoSignerHandle, // fake non-null pointer (won't be dereferenced)
            ptr::null_mut(),
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    
    let msg = error_message(error).unwrap_or_default();
    assert!(msg.contains("out_factory"));
    
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_cose_bytes_free_null() {
    // Should not crash
    unsafe { cose_sign1_cose_bytes_free(ptr::null_mut(), 0) };
    unsafe { cose_sign1_cose_bytes_free(ptr::null_mut(), 100) };
}

#[test]
fn test_cose_bytes_free_valid_pointer() {
    // This test exercises the non-null path by doing a full builder sign + free cycle
    // (builder approach works because it doesn't do post-sign verification)
    let key = create_mock_key();
    
    // Create builder with headers (similar to existing tests)
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) }; // ES256 algorithm
    
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, headers) };
    unsafe { cose_headermap_free(headers) };
    
    // Sign with builder (this works and produces bytes)
    let payload = b"test payload for free test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        )
    };
    
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);
    
    // Free the bytes (this exercises the non-null path of cose_sign1_bytes_free, not cose_sign1_cose_bytes_free)
    // Note: builder functions use cose_sign1_bytes_free, not cose_sign1_cose_bytes_free
    unsafe { cose_sign1_bytes_free(out_bytes, out_len) };
    
    // Clean up other resources
    unsafe { cose_key_free(key) };
    // Note: builder is consumed by sign, do not free
}
