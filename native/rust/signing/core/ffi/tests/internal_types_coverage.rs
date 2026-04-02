// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for internal types in signing/core/ffi.
//!
//! Covers:
//! - `CallbackKey::sign` error path (callback returns non-zero, or null signature)
//! - `CallbackKey` creation and usage
//! - Factory operations with error callbacks
//! - File operations with non-existent files

use cose_sign1_signing_ffi::error::{cose_sign1_signing_error_free, CoseSign1SigningErrorHandle};
use cose_sign1_signing_ffi::types::{
    CoseKeyHandle, CoseSign1FactoryHandle, CoseSign1SigningServiceHandle,
};
use cose_sign1_signing_ffi::*;

use std::ptr;

// Helper functions
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

// Mock callback that returns an error code
unsafe extern "C" fn mock_sign_callback_error(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -1 // Return non-zero error
}

// Mock callback that returns null signature
unsafe extern "C" fn mock_sign_callback_null_sig(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    unsafe {
        *out_sig = ptr::null_mut(); // Set to null
        *out_sig_len = 0;
    }
    0 // Return success but null signature
}

// Mock callback that works normally (for accessor tests)
unsafe extern "C" fn mock_sign_callback_normal(
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

// Helper to create a key
fn create_key(
    algorithm: i64,
    key_type_str: &str,
    callback: CoseSignCallback,
) -> *mut CoseKeyHandle {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type = std::ffi::CString::new(key_type_str).unwrap();

    let rc = unsafe {
        cose_key_from_callback(
            algorithm,
            key_type.as_ptr(),
            callback,
            ptr::null_mut(),
            &mut key,
        )
    };
    assert_eq!(rc, 0);
    assert!(!key.is_null());
    key
}

// Helper to create a signing service
fn create_service(key: *const CoseKeyHandle) -> *mut CoseSign1SigningServiceHandle {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_sign1_signing_service_create(key, &mut service, &mut error) };
    assert_eq!(rc, 0);
    assert!(!service.is_null());
    free_error(error);
    service
}

// Helper to create a factory
fn create_factory(service: *const CoseSign1SigningServiceHandle) -> *mut CoseSign1FactoryHandle {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_sign1_factory_create(service, &mut factory, &mut error) };
    assert_eq!(rc, 0);
    assert!(!factory.is_null());
    free_error(error);
    factory
}

#[test]
fn test_callback_key_sign_error_nonzero_rc_via_factory() {
    // Create key with error callback
    let key = create_key(-7, "EC", mock_sign_callback_error);
    let service = create_service(key);
    let factory = create_factory(service);

    // Try to sign - this should fail with callback error
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

    // Should fail due to callback error
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    // Cleanup
    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_sign_null_signature_via_factory() {
    // Create key with null signature callback
    let key = create_key(-7, "EC", mock_sign_callback_null_sig);
    let service = create_service(key);
    let factory = create_factory(service);

    // Try to sign - this should fail due to null signature
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

    // Should fail due to null signature
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    // Cleanup
    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_creation_and_service() {
    // Test that we can create a callback key and use it to create a service
    let key = create_key(-7, "EC", mock_sign_callback_normal);
    let service = create_service(key);

    // Cleanup
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_key_different_algorithms() {
    // Test ES256 (-7)
    let key_es256 = create_key(-7, "EC", mock_sign_callback_normal);
    let service_es256 = create_service(key_es256);
    free_service(service_es256);
    free_key(key_es256);

    // Test ES384 (-35)
    let key_es384 = create_key(-35, "EC", mock_sign_callback_normal);
    let service_es384 = create_service(key_es384);
    free_service(service_es384);
    free_key(key_es384);

    // Test ES512 (-36)
    let key_es512 = create_key(-36, "EC", mock_sign_callback_normal);
    let service_es512 = create_service(key_es512);
    free_service(service_es512);
    free_key(key_es512);
}

#[test]
fn test_callback_key_different_key_types() {
    // Test EC key type
    let key_ec = create_key(-7, "EC", mock_sign_callback_normal);
    let service_ec = create_service(key_ec);
    free_service(service_ec);
    free_key(key_ec);

    // Test RSA key type
    let key_rsa = create_key(-7, "RSA", mock_sign_callback_normal);
    let service_rsa = create_service(key_rsa);
    free_service(service_rsa);
    free_key(key_rsa);
}

#[test]
fn test_factory_chain_creation() {
    // Test full chain: key -> service -> factory
    let key = create_key(-7, "EC", mock_sign_callback_normal);
    let service = create_service(key);
    let factory = create_factory(service);

    // Verify all handles are valid
    assert!(!key.is_null());
    assert!(!service.is_null());
    assert!(!factory.is_null());

    // Cleanup
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_factory_sign_direct_with_normal_callback() {
    // Create full chain with normal callback
    let key = create_key(-7, "EC", mock_sign_callback_normal);
    let service = create_service(key);
    let factory = create_factory(service);

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

    // Factory signing fails because FFI signing service doesn't support verification
    // (This is expected behavior - see factory_service_coverage.rs tests)
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    // Cleanup
    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_callback_reader_negative_returns_io_error() {
    // Test file operations with non-existent file - exercises CallbackReader error paths
    use std::ffi::CString;

    let key = create_key(-7, "EC", mock_sign_callback_normal);
    let service = create_service(key);
    let factory = create_factory(service);

    // Attempt to sign a non-existent file
    let file_path = CString::new("/non/existent/file.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();

    let mut out_cose_bytes: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            file_path.as_ptr(),
            content_type.as_ptr(),
            &mut out_cose_bytes,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail due to file not found
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    // Cleanup
    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn test_indirect_signing_with_error_callback() {
    // Test indirect signing with error callback
    let key = create_key(-7, "EC", mock_sign_callback_error);
    let service = create_service(key);
    let factory = create_factory(service);

    let payload = b"test data for indirect signing";
    let content_type = b"application/octet-stream\0".as_ptr() as *const libc::c_char;
    let mut out_cose: *mut u8 = ptr::null_mut();
    let mut out_cose_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type,
            &mut out_cose,
            &mut out_cose_len,
            &mut sign_error,
        )
    };

    // Should fail
    assert_ne!(rc, 0);
    assert!(!sign_error.is_null());

    // Cleanup
    free_error(sign_error);
    free_factory(factory);
    free_service(service);
    free_key(key);
}
