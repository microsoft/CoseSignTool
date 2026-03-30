// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for streaming signature FFI functions.
//!
//! These tests verify the FFI API contracts (null checks, error handling)
//! for streaming signature functions. Full integration tests with actual
//! certificate-based signing services are in the C/C++ test suites.

use cose_sign1_signing_ffi::*;
use std::ffi::{CStr, CString};
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

#[test]
fn test_file_streaming_null_factory() {
    let path = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Null factory (direct)
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            ptr::null(),
            path.as_ptr(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null factory (indirect)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            ptr::null(),
            path.as_ptr(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };
}

#[test]
fn test_file_streaming_null_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Null path (direct)
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            ptr::null(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null path (indirect)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            factory,
            ptr::null(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Cleanup
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_file_streaming_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path = CString::new("test.bin").unwrap();
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Null content_type (direct)
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            path.as_ptr(),
            ptr::null(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null content_type (indirect)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            factory,
            path.as_ptr(),
            ptr::null(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Cleanup
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_file_streaming_null_outputs() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Null out_cose_bytes (direct)
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            path.as_ptr(),
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null out_cose_bytes (indirect)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            factory,
            path.as_ptr(),
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Cleanup
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_file_streaming_nonexistent_file() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    // Try to sign nonexistent file
    let path = CString::new("/nonexistent/file/path.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Direct
    let rc = unsafe {
        cose_sign1_factory_sign_direct_file(
            factory,
            path.as_ptr(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_ne!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!error.is_null());
    let msg = error_message(error);
    assert!(msg.is_some());
    let msg_str = msg.unwrap();
    assert!(msg_str.contains("file") || msg_str.contains("open") || msg_str.contains("failed"));
    unsafe { cose_sign1_signing_error_free(error) };

    // Indirect
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file(
            factory,
            path.as_ptr(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_ne!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Cleanup
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}

#[test]
fn test_callback_streaming_null_checks() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut cose_bytes: *mut u8 = ptr::null_mut();
    let mut cose_len: u32 = 0;
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    unsafe extern "C" fn dummy_callback(
        _buffer: *mut u8,
        _buffer_len: usize,
        _user_data: *mut libc::c_void,
    ) -> i64 {
        0
    }

    // Null factory (direct)
    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            ptr::null(),
            dummy_callback,
            100,
            ptr::null_mut(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null content_type (direct)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            dummy_callback,
            100,
            ptr::null_mut(),
            ptr::null(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Null out_cose_bytes (direct)
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming(
            factory,
            dummy_callback,
            100,
            ptr::null_mut(),
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!error.is_null());
    unsafe { cose_sign1_signing_error_free(error) };

    // Repeat for indirect
    error = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming(
            ptr::null(),
            dummy_callback,
            100,
            ptr::null_mut(),
            content_type.as_ptr(),
            &mut cose_bytes,
            &mut cose_len,
            &mut error,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    unsafe { cose_sign1_signing_error_free(error) };

    // Cleanup
    unsafe {
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    }
}
