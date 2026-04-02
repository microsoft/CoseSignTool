// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for cose_sign1_signing_ffi.
//!
//! These tests verify the C calling convention compatibility and handle lifecycle
//! for the builder/signing FFI layer.

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
    let sig = vec![0xAA, 0xBB, 0xCC];
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

/// Helper to create a mock key.
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

#[test]
fn ffi_impl_abi_version() {
    let version = cose_sign1_signing_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_impl_null_free_is_safe() {
    unsafe {
        cose_sign1_builder_free(ptr::null_mut());
        cose_headermap_free(ptr::null_mut());
        cose_key_free(ptr::null_mut());
        cose_sign1_signing_error_free(ptr::null_mut());
        cose_sign1_string_free(ptr::null_mut());
        cose_sign1_bytes_free(ptr::null_mut(), 0);
    }
}

// ============================================================================
// Header map tests
// ============================================================================

#[test]
fn ffi_impl_headermap_create_and_free() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!headers.is_null());

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 0);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_new_null_output() {
    let rc = unsafe { cose_headermap_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_headermap_set_int() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Set algorithm header (label 1, value -7 for ES256)
    let rc = unsafe { cose_headermap_set_int(headers, 1, -7) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 1);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_int_null_handle() {
    let rc = unsafe { cose_headermap_set_int(ptr::null_mut(), 1, -7) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_headermap_set_bytes() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let kid = b"key-id-1";
    let rc = unsafe { cose_headermap_set_bytes(headers, 4, kid.as_ptr(), kid.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 1);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_bytes_null_value_nonzero_len() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let rc = unsafe { cose_headermap_set_bytes(headers, 4, ptr::null(), 10) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_bytes_null_value_zero_len() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Setting null bytes with 0 length should insert empty bytes
    let rc = unsafe { cose_headermap_set_bytes(headers, 4, ptr::null(), 0) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 1);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_text() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let content_type = b"application/cose\0".as_ptr() as *const libc::c_char;
    let rc = unsafe { cose_headermap_set_text(headers, 3, content_type) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 1);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_text_null_value() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let rc = unsafe { cose_headermap_set_text(headers, 3, ptr::null()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_set_multiple() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_headermap_new(&mut headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Set algorithm
    unsafe { cose_headermap_set_int(headers, 1, -7) };
    // Set kid
    let kid = b"test-key";
    unsafe { cose_headermap_set_bytes(headers, 4, kid.as_ptr(), kid.len()) };
    // Set content type
    let ct = b"application/cbor\0".as_ptr() as *const libc::c_char;
    unsafe { cose_headermap_set_text(headers, 3, ct) };

    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 3);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_headermap_len_null_safety() {
    let len = unsafe { cose_headermap_len(ptr::null()) };
    assert_eq!(len, 0);
}

#[test]
fn ffi_impl_headermap_set_bytes_null_handle() {
    let data = b"test";
    let rc = unsafe { cose_headermap_set_bytes(ptr::null_mut(), 4, data.as_ptr(), data.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_headermap_set_text_null_handle() {
    let text = b"test\0".as_ptr() as *const libc::c_char;
    let rc = unsafe { cose_headermap_set_text(ptr::null_mut(), 3, text) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// Key tests
// ============================================================================

#[test]
fn ffi_impl_key_from_callback() {
    let key = create_mock_key();
    unsafe { cose_key_free(key) };
}

#[test]
fn ffi_impl_key_from_callback_null_output() {
    let key_type = b"EC2\0".as_ptr() as *const libc::c_char;
    let rc = unsafe {
        cose_key_from_callback(
            -7,
            key_type,
            mock_sign_callback,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_key_from_callback_null_key_type() {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = unsafe {
        cose_key_from_callback(
            -7,
            ptr::null(),
            mock_sign_callback,
            ptr::null_mut(),
            &mut key,
        )
    };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(key.is_null());
}

// ============================================================================
// Builder tests
// ============================================================================

#[test]
fn ffi_impl_builder_create_and_free() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_builder_new(&mut builder) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(!builder.is_null());

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_new_null_output() {
    let rc = unsafe { cose_sign1_builder_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_builder_set_tagged() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_builder_new(&mut builder) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let rc = unsafe { cose_sign1_builder_set_tagged(builder, false) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_set_tagged_null() {
    let rc = unsafe { cose_sign1_builder_set_tagged(ptr::null_mut(), true) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_builder_set_detached() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_builder_new(&mut builder) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    let rc = unsafe { cose_sign1_builder_set_detached(builder, true) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_set_detached_null() {
    let rc = unsafe { cose_sign1_builder_set_detached(ptr::null_mut(), true) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

#[test]
fn ffi_impl_builder_set_protected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) };

    let rc = unsafe { cose_sign1_builder_set_protected(builder, headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    unsafe {
        cose_headermap_free(headers);
        cose_sign1_builder_free(builder);
    };
}

#[test]
fn ffi_impl_builder_set_protected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_set_protected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_builder_set_protected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_set_protected(builder, ptr::null()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_set_unprotected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    let kid = b"key-1";
    unsafe { cose_headermap_set_bytes(headers, 4, kid.as_ptr(), kid.len()) };

    let rc = unsafe { cose_sign1_builder_set_unprotected(builder, headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    unsafe {
        cose_headermap_free(headers);
        cose_sign1_builder_free(builder);
    };
}

#[test]
fn ffi_impl_builder_set_external_aad() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let aad = b"extra data";
    let rc = unsafe { cose_sign1_builder_set_external_aad(builder, aad.as_ptr(), aad.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Clear AAD by passing null
    let rc = unsafe { cose_sign1_builder_set_external_aad(builder, ptr::null(), 0) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_set_external_aad_null_builder() {
    let aad = b"extra data";
    let rc =
        unsafe { cose_sign1_builder_set_external_aad(ptr::null_mut(), aad.as_ptr(), aad.len()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
}

// ============================================================================
// Signing tests
// ============================================================================

#[test]
fn ffi_impl_sign_basic() {
    // Create protected headers
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) };

    // Create builder
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, headers) };
    unsafe { cose_headermap_free(headers) };

    // Create key
    let key = create_mock_key();

    // Sign
    let payload = b"hello world";
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

    // Verify the output starts with CBOR tag 18 (0xD2) for tagged message
    let output = unsafe { std::slice::from_raw_parts(out_bytes, out_len) };
    assert_eq!(output[0], 0xD2, "Expected CBOR tag 18");

    // Clean up
    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
    // Builder is consumed by sign, do not free
}

#[test]
fn ffi_impl_sign_detached() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) };

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, headers) };
    unsafe { cose_sign1_builder_set_detached(builder, true) };
    unsafe { cose_headermap_free(headers) };

    let key = create_mock_key();

    let payload = b"detached payload";
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

    // The output should contain null payload (0xF6)
    let output = unsafe { std::slice::from_raw_parts(out_bytes, out_len) };
    assert!(
        output.windows(1).any(|w| w[0] == 0xF6),
        "Expected null payload marker"
    );

    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
}

#[test]
fn ffi_impl_sign_untagged() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_tagged(builder, false) };

    let key = create_mock_key();

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

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));

    // Should NOT start with tag 18 (0xD2)
    let output = unsafe { std::slice::from_raw_parts(out_bytes, out_len) };
    assert_ne!(output[0], 0xD2, "Expected no CBOR tag");

    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
}

#[test]
fn ffi_impl_sign_with_unprotected_headers() {
    let mut protected: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut protected) };
    unsafe { cose_headermap_set_int(protected, 1, -7) };

    let mut unprotected: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut unprotected) };
    let kid = b"my-key";
    unsafe { cose_headermap_set_bytes(unprotected, 4, kid.as_ptr(), kid.len()) };

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, protected) };
    unsafe { cose_sign1_builder_set_unprotected(builder, unprotected) };
    unsafe { cose_headermap_free(protected) };
    unsafe { cose_headermap_free(unprotected) };

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

    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
}

#[test]
fn ffi_impl_sign_with_external_aad() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    let aad = b"extra authenticated data";
    unsafe { cose_sign1_builder_set_external_aad(builder, aad.as_ptr(), aad.len()) };

    let key = create_mock_key();

    let payload = b"payload";
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

    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
}

#[test]
fn ffi_impl_sign_null_builder() {
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

#[test]
fn ffi_impl_sign_null_key() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

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
    // Builder was consumed on the null-key path after key check
}

#[test]
fn ffi_impl_sign_null_output() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
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

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_builder_free(builder);
        cose_key_free(key);
    };
}

#[test]
fn ffi_impl_sign_failing_key() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    // Create a failing key
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

#[test]
fn ffi_impl_sign_empty_payload() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let key = create_mock_key();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    // Empty payload (null ptr, 0 len)
    let rc = unsafe {
        cose_sign1_builder_sign(
            builder,
            key,
            ptr::null(),
            0,
            &mut out_bytes,
            &mut out_len,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_bytes.is_null());

    unsafe {
        cose_sign1_bytes_free(out_bytes, out_len);
        cose_key_free(key);
    };
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn ffi_impl_error_null_handle() {
    let msg = unsafe { cose_sign1_signing_error_message(ptr::null()) };
    assert!(msg.is_null());

    let code = unsafe { cose_sign1_signing_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn ffi_impl_sign_null_payload_nonzero_len() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
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

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
    // Builder was consumed
}

#[test]
fn ffi_impl_builder_set_unprotected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_set_unprotected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_builder_set_unprotected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_set_unprotected(builder, ptr::null()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}

// ============================================================================
// Consume (move) header map tests — zero-copy alternatives
// ============================================================================

#[test]
fn ffi_impl_builder_consume_protected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    unsafe { cose_headermap_set_int(headers, 1, -7) };

    // Consume moves ownership — headers must NOT be freed after this
    let rc = unsafe { cose_sign1_builder_consume_protected(builder, headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Only free builder — headers was consumed
    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_consume_protected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_consume_protected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    // Headers was not consumed on failure — must still free
    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_builder_consume_protected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_consume_protected(builder, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_consume_unprotected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };
    let kid = b"key-1";
    unsafe { cose_headermap_set_bytes(headers, 4, kid.as_ptr(), kid.len()) };

    // Consume moves ownership — headers must NOT be freed after this
    let rc = unsafe { cose_sign1_builder_consume_unprotected(builder, headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_OK);

    // Only free builder — headers was consumed
    unsafe { cose_sign1_builder_free(builder) };
}

#[test]
fn ffi_impl_builder_consume_unprotected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut headers) };

    let rc = unsafe { cose_sign1_builder_consume_unprotected(ptr::null_mut(), headers) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    // Headers was not consumed on failure — must still free
    unsafe { cose_headermap_free(headers) };
}

#[test]
fn ffi_impl_builder_consume_unprotected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let rc = unsafe { cose_sign1_builder_consume_unprotected(builder, ptr::null_mut()) };
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe { cose_sign1_builder_free(builder) };
}
