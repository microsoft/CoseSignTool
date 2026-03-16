// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI coverage tests for cose_sign1_primitives_ffi.
//!
//! These tests target uncovered error paths in the `extern "C"` wrapper functions
//! in lib.rs, including NULL pointer checks, headermap accessors via the C ABI,
//! and key handle operations.

use cose_sign1_primitives_ffi::*;
use std::ptr;

/// Minimal tagged COSE_Sign1 with embedded payload "test" and signature "sig!".
fn minimal_cose_sign1_with_payload() -> Vec<u8> {
    vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x44, 0x73,
        0x69, 0x67, 0x21,
    ]
}

/// Minimal tagged COSE_Sign1 with detached payload.
fn minimal_cose_sign1_detached() -> Vec<u8> {
    vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0xF6, 0x44, 0x73, 0x69, 0x67, 0x21,
    ]
}

/// Parse helper returning message handle.
fn parse_msg(data: &[u8]) -> *mut CoseSign1MessageHandle {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_OK, "parse failed");
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
    msg
}

// ============================================================================
// key_algorithm / key_type via extern "C" wrappers with null output pointers
// ============================================================================

#[test]
fn ffi_key_algorithm_null_out_alg() {
    // key_algorithm_inner: out_alg.is_null() => FFI_ERR_NULL_POINTER
    // Call through the extern "C" wrapper to cover that path.
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let rc = unsafe { cose_key_algorithm(key_handle, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    unsafe { cose_key_free(key_handle) };
}

#[test]
fn ffi_key_type_null_key() {
    // key_type_inner: key null => returns null
    let result = unsafe { cose_key_type(ptr::null()) };
    assert!(result.is_null());
}

#[test]
fn ffi_key_type_valid() {
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let result = unsafe { cose_key_type(key_handle) };
    assert!(!result.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_string_lossy()
        .to_string();
    assert_eq!(s, "unknown"); // CryptoVerifier doesn't have key_type()
    unsafe { cose_sign1_string_free(result) };
    unsafe { cose_key_free(key_handle) };
}

// ============================================================================
// protected/unprotected headers via extern "C" with null inputs
// ============================================================================

#[test]
fn ffi_protected_headers_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = unsafe { cose_sign1_message_protected_headers(msg, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_protected_headers_null_message() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_protected_headers(ptr::null(), &mut headers) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
}

#[test]
fn ffi_unprotected_headers_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = unsafe { cose_sign1_message_unprotected_headers(msg, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_unprotected_headers_null_message() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_unprotected_headers(ptr::null(), &mut headers) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
}

// ============================================================================
// headermap_get_int / get_bytes / get_text via extern "C" with null outputs
// ============================================================================

#[test]
fn ffi_headermap_get_int_null_out_value() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };
    assert_eq!(rc, COSE_SIGN1_OK);

    let rc = unsafe { cose_headermap_get_int(headers, 1, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_headermap_get_bytes_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };

    let rc = unsafe { cose_headermap_get_bytes(headers, 1, ptr::null_mut(), ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_headermap_get_bytes_null_headers() {
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = unsafe { cose_headermap_get_bytes(ptr::null(), 1, &mut ptr, &mut len) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
}

#[test]
fn ffi_headermap_get_bytes_not_found() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };

    // Label 1 is Int(-7), not Bytes - should return HEADER_NOT_FOUND
    let mut out_ptr: *const u8 = ptr::null();
    let mut out_len: usize = 0;
    let rc = unsafe { cose_headermap_get_bytes(headers, 1, &mut out_ptr, &mut out_len) };
    assert_eq!(rc, COSE_SIGN1_ERR_HEADER_NOT_FOUND);

    unsafe { cose_headermap_free(headers) };
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_headermap_get_text_null_headers() {
    let result = unsafe { cose_headermap_get_text(ptr::null(), 1) };
    assert!(result.is_null());
}

#[test]
fn ffi_headermap_get_text_not_found() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };

    // Label 1 is Int, not Text
    let result = unsafe { cose_headermap_get_text(headers, 1) };
    assert!(result.is_null());

    unsafe { cose_headermap_free(headers) };
    unsafe { cose_sign1_message_free(msg) };
}

// ============================================================================
// headermap_contains / headermap_len via extern "C" with null handles
// ============================================================================

#[test]
fn ffi_headermap_contains_null_handle() {
    let result = unsafe { cose_headermap_contains(ptr::null(), 1) };
    assert!(!result);
}

#[test]
fn ffi_headermap_len_null_handle() {
    let result = unsafe { cose_headermap_len(ptr::null()) };
    assert_eq!(result, 0);
}

// ============================================================================
// verify_detached via extern "C" with null key
// ============================================================================

#[test]
fn ffi_verify_detached_null_key() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_message_verify_detached(
            msg,
            ptr::null(),
            b"test".as_ptr(),
            4,
            ptr::null(),
            0,
            &mut verified,
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_verify_detached_null_message() {
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_message_verify_detached(
            ptr::null(),
            ptr::null(),
            b"test".as_ptr(),
            4,
            ptr::null(),
            0,
            &mut verified,
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
}

#[test]
fn ffi_verify_detached_null_out_verified() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_message_verify_detached(
            msg,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
    unsafe { cose_sign1_message_free(msg) };
}

// ============================================================================
// key_free with valid handle (non-null path)
// ============================================================================

#[test]
fn ffi_key_free_valid_handle() {
    let key_handle = create_key_handle(Box::new(MockVerifier));
    assert!(!key_handle.is_null());
    // Exercise the non-null path of cose_key_free
    unsafe { cose_key_free(key_handle) };
}

// ============================================================================
// headermap_free with valid handle (non-null path)
// ============================================================================

#[test]
fn ffi_headermap_free_valid_handle() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert!(!headers.is_null());
    // Exercise the non-null path of cose_headermap_free
    unsafe { cose_headermap_free(headers) };
    unsafe { cose_sign1_message_free(msg) };
}

// ============================================================================
// Mock key used for testing
// ============================================================================

struct MockSigner;

impl cose_sign1_primitives::CryptoSigner for MockSigner {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, cose_sign1_primitives::CryptoError> {
        Ok(vec![0u8; 64])
    }
}

struct MockVerifier;

impl cose_sign1_primitives::CryptoVerifier for MockVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, cose_sign1_primitives::CryptoError> {
        Ok(false)
    }
}
