// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Final comprehensive coverage tests for signing FFI factory functions.
//! Targets uncovered lines in lib.rs factory/service/streaming code.

use cose_sign1_signing_ffi::error::{
    cose_sign1_signing_error_free, CoseSign1SigningErrorHandle,
    FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER, FFI_ERR_FACTORY_FAILED,
};
use cose_sign1_signing_ffi::types::{
    CoseSign1BuilderHandle, CoseHeaderMapHandle, CoseKeyHandle,
    CoseSign1SigningServiceHandle, CoseSign1FactoryHandle,
};
use cose_sign1_signing_ffi::*;

use std::ffi::CString;
use std::ptr;

// ============================================================================
// Helper functions
// ============================================================================

fn free_error(err: *mut CoseSign1SigningErrorHandle) {
    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
    }
}

fn free_headers(h: *mut CoseHeaderMapHandle) {
    if !h.is_null() {
        unsafe { cose_headermap_free(h) };
    }
}

#[allow(dead_code)]
fn free_builder(b: *mut CoseSign1BuilderHandle) {
    if !b.is_null() {
        unsafe { cose_sign1_builder_free(b) };
    }
}

fn free_key(k: *mut CoseKeyHandle) {
    if !k.is_null() {
        unsafe { cose_key_free(k) };
    }
}

fn free_service(s: *mut CoseSign1SigningServiceHandle) {
    if !s.is_null() {
        unsafe { cose_sign1_signing_service_free(s) };
    }
}

fn free_factory(f: *mut CoseSign1FactoryHandle) {
    if !f.is_null() {
        unsafe { cose_sign1_factory_free(f) };
    }
}

/// Mock signing callback that produces deterministic signatures
unsafe extern "C" fn mock_sign_callback(
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
    std::ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);
    *out_sig = ptr;
    *out_sig_len = len;
    0
}

/// Streaming read callback for testing
unsafe extern "C" fn mock_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    // Read from the user_data which points to our test data
    let data = user_data as *const u8;
    if data.is_null() {
        return 0;
    }
    
    // Fill buffer with test data (simple pattern)
    let to_read = buffer_len.min(4);
    if to_read > 0 {
        let test_data = b"test";
        std::ptr::copy_nonoverlapping(test_data.as_ptr(), buffer, to_read);
    }
    to_read as i64
}

/// Streaming read callback that returns an error
#[allow(dead_code)]
unsafe extern "C" fn error_read_callback(
    _buffer: *mut u8,
    _buffer_len: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    -1 // Error
}

fn create_mock_key() -> *mut CoseKeyHandle {
    let key_type = CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    key
}

fn create_mock_service() -> *mut CoseSign1SigningServiceHandle {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    free_error(err);
    // Don't free key - it's now owned by service
    service
}

fn create_mock_factory() -> *mut CoseSign1FactoryHandle {
    let service = create_mock_service();
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);
    free_error(err);
    free_service(service);
    factory
}

// ============================================================================
// Signing service tests
// ============================================================================

#[test]
fn test_signing_service_create_success() {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_signing_service_create_inner(key, &mut service, &mut err);
    
    assert_eq!(rc, 0);
    assert!(!service.is_null());
    
    free_error(err);
    free_service(service);
}

#[test]
fn test_signing_service_create_null_out_service() {
    let key = create_mock_key();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_signing_service_create_inner(key, ptr::null_mut(), &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_key(key);
}

#[test]
fn test_signing_service_create_null_key() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_signing_service_create_inner(ptr::null(), &mut service, &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ============================================================================
// Factory creation tests
// ============================================================================

#[test]
fn test_factory_create_success() {
    let service = create_mock_service();
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_create_inner(service, &mut factory, &mut err);
    
    assert_eq!(rc, 0);
    assert!(!factory.is_null());
    
    free_error(err);
    free_factory(factory);
    free_service(service);
}

#[test]
fn test_factory_create_null_out_factory() {
    let service = create_mock_service();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_create_inner(service, ptr::null_mut(), &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_service(service);
}

#[test]
fn test_factory_create_null_service() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_create_inner(ptr::null(), &mut factory, &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    assert!(factory.is_null());
    free_error(err);
}

// ============================================================================
// Factory direct signing tests
// ============================================================================

#[test]
fn test_factory_sign_direct_null_output() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let payload = b"test payload";
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_inner(
        ptr::null(),
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_direct_null_payload_nonzero_len() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_inner(
        factory,
        ptr::null(),
        100, // Non-zero length with null payload
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_null_content_type() {
    let factory = create_mock_factory();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    // Invalid UTF-8 sequence
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// Factory indirect signing tests
// ============================================================================

#[test]
fn test_factory_sign_indirect_null_output() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let payload = b"test payload";
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_inner(
        ptr::null(),
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_indirect_null_payload_nonzero_len() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_inner(
        factory,
        ptr::null(),
        100,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_null_content_type() {
    let factory = create_mock_factory();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// File signing tests
// ============================================================================

#[test]
fn test_factory_sign_direct_file_null_output() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path.as_ptr(),
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_file_null_factory() {
    let file_path = CString::new("/nonexistent/path").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_file_inner(
        ptr::null(),
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_direct_file_null_file_path() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        ptr::null(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_file_null_content_type() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path.as_ptr(),
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_file_invalid_utf8_path() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        invalid_utf8.as_ptr() as *const libc::c_char,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_file_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path.as_ptr(),
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_file_nonexistent_file() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path/to/file.dat").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    // Should fail with invalid argument (file not found)
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// Indirect file signing tests
// ============================================================================

#[test]
fn test_factory_sign_indirect_file_null_output() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        file_path.as_ptr(),
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_file_null_factory() {
    let file_path = CString::new("/nonexistent/path").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_file_inner(
        ptr::null(),
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_indirect_file_null_file_path() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        ptr::null(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_file_null_content_type() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        file_path.as_ptr(),
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_file_invalid_utf8_path() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        invalid_utf8.as_ptr() as *const libc::c_char,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_file_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        file_path.as_ptr(),
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_file_nonexistent_file() {
    let factory = create_mock_factory();
    let file_path = CString::new("/nonexistent/path/to/file.dat").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    // Should fail with invalid argument (file not found)
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// Streaming signing tests
// ============================================================================

#[test]
fn test_factory_sign_direct_streaming_null_output() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_streaming_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_streaming_inner(
        ptr::null(),
        mock_read_callback,
        100,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_direct_streaming_null_content_type() {
    let factory = create_mock_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_direct_streaming_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// Indirect streaming signing tests
// ============================================================================

#[test]
fn test_factory_sign_indirect_streaming_null_output() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_streaming_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_streaming_inner(
        ptr::null(),
        mock_read_callback,
        100,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_factory_sign_indirect_streaming_null_content_type() {
    let factory = create_mock_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_streaming_invalid_utf8_content_type() {
    let factory = create_mock_factory();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_read_callback,
        100,
        ptr::null_mut(),
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
    free_factory(factory);
}

// ============================================================================
// Empty payload tests
// ============================================================================

#[test]
fn test_factory_sign_direct_empty_payload() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    // Empty payload (null pointer with zero length)
    let rc = impl_factory_sign_direct_inner(
        factory,
        ptr::null(),
        0, // Zero length
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    // Should fail because our mock callback doesn't do real signing
    assert!(rc != 0 || rc == FFI_ERR_FACTORY_FAILED);
    free_error(err);
    if !out_bytes.is_null() {
        unsafe { cose_sign1_cose_bytes_free(out_bytes, out_len) };
    }
    free_factory(factory);
}

#[test]
fn test_factory_sign_indirect_empty_payload() {
    let factory = create_mock_factory();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    
    let rc = impl_factory_sign_indirect_inner(
        factory,
        ptr::null(),
        0, // Zero length
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    
    // Should fail because our mock callback doesn't do real signing
    assert!(rc != 0 || rc == FFI_ERR_FACTORY_FAILED);
    free_error(err);
    if !out_bytes.is_null() {
        unsafe { cose_sign1_cose_bytes_free(out_bytes, out_len) };
    }
    free_factory(factory);
}

// ============================================================================
// headermap additional coverage
// ============================================================================

#[test]
fn test_headermap_set_bytes_null_headers() {
    let bytes = b"hello";
    let rc = impl_headermap_set_bytes_inner(ptr::null_mut(), 100, bytes.as_ptr(), bytes.len());
    assert!(rc < 0);
}

#[test]
fn test_headermap_set_text_invalid_utf8() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    let rc = impl_headermap_set_text_inner(headers, 200, invalid_utf8.as_ptr() as *const libc::c_char);
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    
    free_headers(headers);
}
