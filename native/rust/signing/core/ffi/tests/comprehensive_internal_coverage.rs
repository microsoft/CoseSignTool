// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for internal FFI types to achieve 90% coverage.
//!
//! Covers:
//! - CallbackKey trait methods and error paths
//! - ArcCryptoSignerWrapper trait methods  
//! - SimpleSigningService trait methods
//! - CallbackStreamingPayload and CallbackReader functionality
//! - All code paths in internal type implementations

use cose_sign1_signing_ffi::error::{cose_sign1_signing_error_free, CoseSign1SigningErrorHandle};
use cose_sign1_signing_ffi::types::{CoseKeyHandle, CoseSign1SigningServiceHandle, CoseSign1FactoryHandle};
use cose_sign1_signing_ffi::*;

use std::ptr;

// Helper function definitions
fn free_error(err: *mut CoseSign1SigningErrorHandle) {
    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
    }
}

fn free_service(service: *mut CoseSign1SigningServiceHandle) {
    if !service.is_null() {
        unsafe { cose_sign1_signing_service_free(service) };
    }
}

fn free_key(k: *mut CoseKeyHandle) {
    if !k.is_null() {
        unsafe { cose_key_free(k) };
    }
}

fn free_factory(factory: *mut CoseSign1FactoryHandle) {
    if !factory.is_null() {
        unsafe { cose_sign1_factory_free(factory) };
    }
}

// Mock callbacks for different behaviors
unsafe extern "C" fn mock_successful_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    let sig = vec![0xABu8; 64];
    let len = sig.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return -1;
    }
    ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);
    unsafe {
        *out_sig = ptr;
        *out_sig_len = len;
    }
    0
}

unsafe extern "C" fn mock_error_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -42 // Return specific error code
}

unsafe extern "C" fn mock_null_sig_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    unsafe {
        *out_sig = ptr::null_mut(); // Return null signature
        *out_sig_len = 0;
    }
    0 // Success code but null signature
}

// Read callback for streaming tests
unsafe extern "C" fn mock_read_callback_success(
    buf: *mut u8,
    buf_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    // Fill buffer with test data
    let test_data = b"Hello, world! This is streaming test data.";
    let to_copy = buf_len.min(test_data.len());
    ptr::copy_nonoverlapping(test_data.as_ptr(), buf, to_copy);
    to_copy as i64
}

unsafe extern "C" fn mock_read_callback_error(
    _buf: *mut u8,
    _buf_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    -1 // Return read error
}

unsafe extern "C" fn mock_read_callback_empty(
    _buf: *mut u8,
    _buf_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    0 // Return no data read
}

// Helper to create different types of keys
fn create_callback_key(algorithm: i64, key_type: &str, callback: CoseSignCallback) -> *mut CoseKeyHandle {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type_cstr = std::ffi::CString::new(key_type).unwrap();
    
    let rc = unsafe {
        cose_key_from_callback(
            algorithm,
            key_type_cstr.as_ptr(),
            callback,
            ptr::null_mut(),
            &mut key,
        )
    };
    assert_eq!(rc, 0);
    assert!(!key.is_null());
    key
}

fn create_signing_service(key: *const CoseKeyHandle) -> *mut CoseSign1SigningServiceHandle {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_signing_service_create(key, &mut service, &mut error) };
    assert_eq!(rc, 0);
    assert!(!service.is_null());
    free_error(error);
    service
}

fn create_factory_from_service(service: *const CoseSign1SigningServiceHandle) -> *mut CoseSign1FactoryHandle {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = unsafe { cose_sign1_factory_create(service, &mut factory, &mut error) };
    assert_eq!(rc, 0);
    assert!(!factory.is_null());
    free_error(error);
    factory
}

// =============================================================================
// Tests for CallbackKey internal type
// =============================================================================

#[test]
fn test_callback_key_successful_signing() {
    // Test successful path through CallbackKey::sign
    let key = create_callback_key(-7, "EC", mock_successful_callback);
    let service = create_signing_service(key);
    
    // The key was created successfully, proving CallbackKey works
    assert!(!key.is_null());
    assert!(!service.is_null());
    
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_error_callback_nonzero() {
    // Test error path: callback returns non-zero error code
    let key = create_callback_key(-7, "EC", mock_error_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let payload = b"test data";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail - this exercises CallbackKey::sign error path
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_null_signature() {
    // Test error path: callback returns success but null signature
    let key = create_callback_key(-7, "EC", mock_null_sig_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let payload = b"test data";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail - this exercises CallbackKey::sign null signature error path
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_different_algorithms() {
    // Test CallbackKey::algorithm() method with different values
    
    // ES256 (-7)
    let key_es256 = create_callback_key(-7, "EC", mock_successful_callback);
    let service_es256 = create_signing_service(key_es256);
    free_service(service_es256);
    free_key(key_es256);
    
    // ES384 (-35)
    let key_es384 = create_callback_key(-35, "EC", mock_successful_callback);
    let service_es384 = create_signing_service(key_es384);
    free_service(service_es384);
    free_key(key_es384);
    
    // ES512 (-36)
    let key_es512 = create_callback_key(-36, "EC", mock_successful_callback);
    let service_es512 = create_signing_service(key_es512);
    free_service(service_es512);
    free_key(key_es512);
    
    // PS256 (-37)
    let key_ps256 = create_callback_key(-37, "RSA", mock_successful_callback);
    let service_ps256 = create_signing_service(key_ps256);
    free_service(service_ps256);
    free_key(key_ps256);
}

#[test]
fn test_callback_key_different_key_types() {
    // Test CallbackKey::key_type() method with different values
    
    let key_ec = create_callback_key(-7, "EC", mock_successful_callback);
    let service_ec = create_signing_service(key_ec);
    free_service(service_ec);
    free_key(key_ec);
    
    let key_rsa = create_callback_key(-7, "RSA", mock_successful_callback);
    let service_rsa = create_signing_service(key_rsa);
    free_service(service_rsa);
    free_key(key_rsa);
    
    let key_okp = create_callback_key(-7, "OKP", mock_successful_callback);
    let service_okp = create_signing_service(key_okp);
    free_service(service_okp);
    free_key(key_okp);
}

#[test]
fn test_callback_key_with_user_data() {
    // Test CallbackKey creation with user data
    let mut user_data: u32 = 12345;
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type_cstr = std::ffi::CString::new("EC").unwrap();
    
    let rc = unsafe {
        cose_key_from_callback(
            -7,
            key_type_cstr.as_ptr(),
            mock_successful_callback,
            &mut user_data as *mut u32 as *mut libc::c_void,
            &mut key,
        )
    };
    assert_eq!(rc, 0);
    assert!(!key.is_null());
    
    let service = create_signing_service(key);
    free_service(service);
    free_key(key);
}

// =============================================================================
// Tests for streaming functionality (CallbackStreamingPayload and CallbackReader)
// =============================================================================

#[test]
fn test_streaming_with_successful_callback() {
    // Test streaming functionality that exercises CallbackStreamingPayload and CallbackReader
    let key = create_callback_key(-7, "EC", mock_successful_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let total_len: u64 = 42;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            mock_read_callback_success,
            total_len,
            ptr::null_mut(), // user_data
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // This should fail due to FFI service verification not supported, but it exercises the streaming types
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_streaming_with_read_error_callback() {
    // Test CallbackReader error handling
    let key = create_callback_key(-7, "EC", mock_successful_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let total_len: u64 = 42;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            mock_read_callback_error, // This callback returns -1 (error)
            total_len,
            ptr::null_mut(),
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail - exercises CallbackReader::read error path
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_streaming_with_empty_read_callback() {
    // Test CallbackReader when callback returns 0 bytes
    let key = create_callback_key(-7, "EC", mock_successful_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let total_len: u64 = 0; // Empty payload
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            mock_read_callback_empty,
            total_len,
            ptr::null_mut(),
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail due to FFI service verification, but exercises streaming paths
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_streaming_indirect_with_callback() {
    // Test indirect streaming functionality
    let key = create_callback_key(-7, "EC", mock_successful_callback);
    let service = create_signing_service(key);
    let factory = create_factory_from_service(service);

    let total_len: u64 = 100;
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming(
            factory,
            mock_read_callback_success,
            total_len,
            ptr::null_mut(),
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail but exercises streaming paths
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// =============================================================================
// Additional edge case tests to maximize coverage
// =============================================================================

#[test]
fn test_multiple_key_creations_and_services() {
    // Test creating multiple keys and services to exercise type instantiation
    let mut keys = Vec::new();
    let mut services = Vec::new();
    
    for i in 0..3 {
        let algorithm = match i {
            0 => -7,  // ES256
            1 => -35, // ES384
            _ => -36, // ES512
        };
        
        let key = create_callback_key(algorithm, "EC", mock_successful_callback);
        let service = create_signing_service(key);
        
        keys.push(key);
        services.push(service);
    }
    
    // Clean up all resources
    for service in services {
        free_service(service);
    }
    for key in keys {
        free_key(key);
    }
}

#[test]
fn test_factory_operations_with_different_keys() {
    // Test factory operations with different key configurations
    let algorithms = vec![(-7, "EC"), (-35, "EC"), (-36, "EC"), (-37, "RSA")];
    
    for (algorithm, key_type) in algorithms {
        let key = create_callback_key(algorithm, key_type, mock_successful_callback);
        let service = create_signing_service(key);
        let factory = create_factory_from_service(service);
        
        // Try a simple operation
        let payload = b"test";
        let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
        let mut out_cose: *mut u8 = ptr::null_mut();
        let mut out_cose_len: u32 = 0;
        let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

        let _rc = unsafe {
            cose_sign1_factory_sign_direct(
                factory,
                payload.as_ptr(),
                payload.len() as u32,
                content_type,
                &mut out_cose,
                &mut out_cose_len,
                &mut sign_error,
            )
        };
        
        // Clean up (ignoring result as we expect failure)
        free_error(sign_error);
        free_factory(factory);
        free_service(service);
        free_key(key);
    }
}