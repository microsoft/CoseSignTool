// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI coverage tests for cose_sign1_signing_ffi.
//!
//! These tests target uncovered error paths in the `extern "C"` wrapper functions
//! in lib.rs, including NULL pointer checks, builder state validation,
//! error code conversion, and callback key operations.

use cose_sign1_signing_ffi::*;
use std::ffi::CStr;
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
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
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

/// Failing sign callback for error testing.
unsafe extern "C" fn failing_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -1
}

/// Null-signature callback: returns success but null output pointer.
unsafe extern "C" fn null_sig_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    unsafe {
        *out_sig = ptr::null_mut();
        *out_sig_len = 0;
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

/// Helper to create a builder with ES256 protected header.
fn create_builder_with_headers() -> *mut CoseSign1BuilderHandle {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) };

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, headers) };
    unsafe { cose_headermap_free(headers) };

    builder
}

// ============================================================================
// headermap_set_text invalid UTF-8 via extern "C"
// ============================================================================

#[test]
fn ffi_headermap_set_text_invalid_utf8() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Invalid UTF-8 + null terminator
    let invalid = [0xC0u8, 0xAF, 0x00];
    let rc =
        unsafe { cose_headermap_set_text(headers, 3, invalid.as_ptr() as *const libc::c_char) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT);

    unsafe { cose_headermap_free(headers) };
}

// ============================================================================
// key_from_callback invalid UTF-8 via extern "C"
// ============================================================================

#[test]
fn ffi_key_from_callback_invalid_utf8() {
    let invalid = [0xC0u8, 0xAF, 0x00];
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = unsafe {
        cose_key_from_callback(
            -7,
            invalid.as_ptr() as *const libc::c_char,
            mock_sign_callback,
            ptr::null_mut(),
            &mut key,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT);
    assert!(key.is_null());
}

// ============================================================================
// builder_sign via extern "C" with failing key callback
// ============================================================================

#[test]
fn ffi_sign_with_failing_callback_key() {
    let builder = create_builder_with_headers();

    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type = b"EC2\0".as_ptr() as *const libc::c_char;
    let rc = unsafe {
        cose_key_from_callback(
            -7,
            key_type,
            failing_sign_callback,
            ptr::null_mut(),
            &mut key,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_SIGN_FAILED);
    assert!(!err.is_null());
    assert!(out_bytes.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(!msg.is_empty());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

// ============================================================================
// builder_sign with null-signature callback
// ============================================================================

#[test]
fn ffi_sign_with_null_sig_callback_key() {
    let builder = create_builder_with_headers();

    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type = b"EC2\0".as_ptr() as *const libc::c_char;
    let rc = unsafe {
        cose_key_from_callback(-7, key_type, null_sig_callback, ptr::null_mut(), &mut key)
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_SIGN_FAILED);
    assert!(out_bytes.is_null());

    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
    }
    unsafe { cose_key_free(key) };
}

// ============================================================================
// builder_sign null output pointers via extern "C"
// ============================================================================

#[test]
fn ffi_sign_null_out_bytes() {
    let builder = create_builder_with_headers();
    let key = create_mock_key();
    let payload = b"test";
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
    }
    unsafe {
        cose_sign1_builder_free(builder);
        cose_key_free(key);
    };
}

// ============================================================================
// builder_sign null payload with nonzero len via extern "C"
// ============================================================================

#[test]
fn ffi_sign_null_payload_nonzero_len() {
    let builder = create_builder_with_headers();
    let key = create_mock_key();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            ptr::null(),
            10,
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("payload"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

// ============================================================================
// builder_sign null builder via extern "C"
// ============================================================================

#[test]
fn ffi_sign_null_builder() {
    let key = create_mock_key();
    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            ptr::null_mut(),
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("builder"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

// ============================================================================
// builder_sign null key via extern "C"
// ============================================================================

#[test]
fn ffi_sign_null_key() {
    let builder = create_builder_with_headers();
    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            ptr::null(),
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("key"));

    unsafe { cose_sign1_signing_error_free(err) };
    // builder consumed
}

// ============================================================================
// builder_set_unprotected null builder/headers via extern "C"
// ============================================================================

#[test]
fn ffi_builder_set_unprotected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_set_unprotected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_builder_set_unprotected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_set_unprotected(builder, ptr::null()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}

// ============================================================================
// builder_set_external_aad null builder via extern "C"
// ============================================================================

#[test]
fn ffi_builder_set_external_aad_null_builder() {
    let aad = b"extra";
    let rc =
        unsafe { cose_sign1_builder_set_external_aad(ptr::null_mut(), aad.as_ptr(), aad.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// builder_set_protected null builder/headers via extern "C"
// ============================================================================

#[test]
fn ffi_builder_set_protected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_set_protected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_builder_set_protected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_set_protected(builder, ptr::null()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}

// ============================================================================
// builder_set_tagged / set_detached null builder via extern "C"
// ============================================================================

#[test]
fn ffi_builder_set_tagged_null() {
    let rc = unsafe { cose_sign1_builder_set_tagged(ptr::null_mut(), true) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_builder_set_detached_null() {
    let rc = unsafe { cose_sign1_builder_set_detached(ptr::null_mut(), true) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// key_free / builder_free with valid handles (non-null path)
// ============================================================================

#[test]
fn ffi_key_free_valid_handle() {
    let key = create_mock_key();
    assert!(!key.is_null());
    unsafe { cose_key_free(key) };
}

#[test]
fn ffi_builder_free_valid_handle() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    assert!(!builder.is_null());
    unsafe { cose_sign1_builder_free(builder) };
}

// ============================================================================
// bytes_free with valid data
// ============================================================================

#[test]
fn ffi_bytes_free_valid() {
    let builder = create_builder_with_headers();
    let key = create_mock_key();
    let payload = b"hello";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Exercise the non-null path of cose_sign1_bytes_free
    unsafe { cose_sign1_bytes_free(out_bytes, out_len) };
    unsafe { cose_key_free(key) };
}

// ============================================================================
// headermap_set_bytes null handle via extern "C"
// ============================================================================

#[test]
fn ffi_headermap_set_bytes_null_handle() {
    let data = b"test";
    let rc = unsafe { cose_headermap_set_bytes(ptr::null_mut(), 4, data.as_ptr(), data.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// headermap_set_int null handle via extern "C"
// ============================================================================

#[test]
fn ffi_headermap_set_int_null_handle() {
    let rc = unsafe { cose_headermap_set_int(ptr::null_mut(), 1, -7) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// headermap_set_text null handle via extern "C"
// ============================================================================

#[test]
fn ffi_headermap_set_text_null_handle() {
    let text = b"test\0".as_ptr() as *const libc::c_char;
    let rc = unsafe { cose_headermap_set_text(ptr::null_mut(), 3, text) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// error NUL byte in message via impl FFI
// ============================================================================

#[test]
fn ffi_error_message_with_nul_byte() {
    use cose_sign1_signing_ffi::error::{set_error, ErrorInner};

    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("bad\0msg", -1));
    assert!(!err.is_null());

    let msg = unsafe { cose_sign1_signing_error_message(err) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    assert!(s.contains("NUL"));
    unsafe { cose_sign1_string_free(msg) };
    unsafe { cose_sign1_signing_error_free(err) };
}

// ============================================================================
// sign with null out_error (error is silently discarded)
// ============================================================================

#[test]
fn ffi_sign_null_out_error() {
    let builder = create_builder_with_headers();
    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;

    // Pass null for out_error; the null key error should still return the right code
    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            ptr::null(),
            payload.as_ptr(),
            payload.len(),
            &mut out_bytes,
            &mut out_len,
            ptr::null_mut(),
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    // builder consumed
}

// ============================================================================
// headermap_new null output via extern "C"
// ============================================================================

#[test]
fn ffi_headermap_new_null_output() {
    let rc = unsafe { cose_headermap_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// builder_new null output via extern "C"
// ============================================================================

#[test]
fn ffi_builder_new_null_output() {
    let rc = unsafe { cose_sign1_builder_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}
