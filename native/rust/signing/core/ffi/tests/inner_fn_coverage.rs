// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests that call inner (non-extern-C) functions directly to ensure LLVM coverage
//! can attribute hits to the catch_unwind + match code paths.

use cose_sign1_signing_ffi::error::{cose_sign1_signing_error_free, CoseSign1SigningErrorHandle};
use cose_sign1_signing_ffi::types::{CoseSign1BuilderHandle, CoseHeaderMapHandle, CoseKeyHandle};
use cose_sign1_signing_ffi::*;

use std::ptr;

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

/// Simple C callback that produces a deterministic "signature".
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
    unsafe {
        *out_sig = ptr;
        *out_sig_len = len;
    }
    0
}

/// C callback that returns an error.
unsafe extern "C" fn fail_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -42
}

/// C callback that returns null signature.
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

// ============================================================================
// headermap inner tests
// ============================================================================

#[test]
fn inner_headermap_new() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = impl_headermap_new_inner(&mut headers);
    assert_eq!(rc, 0);
    assert!(!headers.is_null());
    free_headers(headers);
}

#[test]
fn inner_headermap_new_null() {
    let rc = impl_headermap_new_inner(ptr::null_mut());
    assert!(rc < 0);
}

#[test]
fn inner_headermap_set_int() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let rc = impl_headermap_set_int_inner(headers, 1, -7);
    assert_eq!(rc, 0);
    let len = impl_headermap_len_inner(headers);
    assert_eq!(len, 1);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_int_null() {
    let rc = impl_headermap_set_int_inner(ptr::null_mut(), 1, -7);
    assert!(rc < 0);
}

#[test]
fn inner_headermap_set_bytes() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let bytes = b"hello";
    let rc = impl_headermap_set_bytes_inner(headers, 100, bytes.as_ptr(), bytes.len());
    assert_eq!(rc, 0);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_bytes_null_value_nonzero_len() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let rc = impl_headermap_set_bytes_inner(headers, 100, ptr::null(), 5);
    assert!(rc < 0);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_bytes_null_value_zero_len() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let rc = impl_headermap_set_bytes_inner(headers, 100, ptr::null(), 0);
    assert_eq!(rc, 0);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_text() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let text = std::ffi::CString::new("hello").unwrap();
    let rc = impl_headermap_set_text_inner(headers, 200, text.as_ptr());
    assert_eq!(rc, 0);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_text_null_value() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let rc = impl_headermap_set_text_inner(headers, 200, ptr::null());
    assert!(rc < 0);
    free_headers(headers);
}

#[test]
fn inner_headermap_set_text_null_headers() {
    let text = std::ffi::CString::new("hello").unwrap();
    let rc = impl_headermap_set_text_inner(ptr::null_mut(), 200, text.as_ptr());
    assert!(rc < 0);
}

#[test]
fn inner_headermap_len_null() {
    let len = impl_headermap_len_inner(ptr::null());
    assert_eq!(len, 0);
}

// ============================================================================
// builder inner tests
// ============================================================================

#[test]
fn inner_builder_new() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    let rc = impl_builder_new_inner(&mut builder);
    assert_eq!(rc, 0);
    assert!(!builder.is_null());
    free_builder(builder);
}

#[test]
fn inner_builder_new_null() {
    let rc = impl_builder_new_inner(ptr::null_mut());
    assert!(rc < 0);
}

#[test]
fn inner_builder_set_tagged() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let rc = impl_builder_set_tagged_inner(builder, false);
    assert_eq!(rc, 0);
    free_builder(builder);
}

#[test]
fn inner_builder_set_tagged_null() {
    let rc = impl_builder_set_tagged_inner(ptr::null_mut(), false);
    assert!(rc < 0);
}

#[test]
fn inner_builder_set_detached() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let rc = impl_builder_set_detached_inner(builder, true);
    assert_eq!(rc, 0);
    free_builder(builder);
}

#[test]
fn inner_builder_set_detached_null() {
    let rc = impl_builder_set_detached_inner(ptr::null_mut(), true);
    assert!(rc < 0);
}

#[test]
fn inner_builder_set_protected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    impl_headermap_set_int_inner(headers, 1, -7);

    let rc = impl_builder_set_protected_inner(builder, headers);
    assert_eq!(rc, 0);

    free_headers(headers);
    free_builder(builder);
}

#[test]
fn inner_builder_set_protected_null_builder() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    let rc = impl_builder_set_protected_inner(ptr::null_mut(), headers);
    assert!(rc < 0);
    free_headers(headers);
}

#[test]
fn inner_builder_set_protected_null_headers() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let rc = impl_builder_set_protected_inner(builder, ptr::null());
    assert!(rc < 0);
    free_builder(builder);
}

#[test]
fn inner_builder_set_unprotected() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);

    let rc = impl_builder_set_unprotected_inner(builder, headers);
    assert_eq!(rc, 0);

    free_headers(headers);
    free_builder(builder);
}

#[test]
fn inner_builder_set_unprotected_null() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let rc = impl_builder_set_unprotected_inner(builder, ptr::null());
    assert!(rc < 0);
    free_builder(builder);
}

#[test]
fn inner_builder_set_external_aad() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let aad = b"extra data";
    let rc = impl_builder_set_external_aad_inner(builder, aad.as_ptr(), aad.len());
    assert_eq!(rc, 0);

    // Clear AAD
    let rc = impl_builder_set_external_aad_inner(builder, ptr::null(), 0);
    assert_eq!(rc, 0);

    free_builder(builder);
}

#[test]
fn inner_builder_set_external_aad_null() {
    let rc = impl_builder_set_external_aad_inner(ptr::null_mut(), ptr::null(), 0);
    assert!(rc < 0);
}

// ============================================================================
// sign inner tests
// ============================================================================

#[test]
fn inner_builder_sign_success() {
    // Create key from callback
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert_eq!(rc, 0);

    // Create builder with protected headers
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    impl_headermap_set_int_inner(headers, 1, -7);
    impl_builder_set_protected_inner(builder, headers);
    free_headers(headers);

    // Sign
    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        builder,
        key,
        payload.as_ptr(),
        payload.len(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert_eq!(rc, 0, "sign failed");
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Free output
    unsafe { cose_sign1_bytes_free(out_bytes, out_len) };
    free_error(err);
    free_key(key);
    // builder is consumed by sign, don't free
}

#[test]
fn inner_builder_sign_null_output() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        ptr::null_mut(),
        ptr::null(),
        ptr::null(),
        0,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_builder_sign_null_builder() {
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        ptr::null_mut(),
        ptr::null(),
        ptr::null(),
        0,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_builder_sign_null_key() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        builder,
        ptr::null(),
        b"test".as_ptr(),
        4,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
    // builder consumed
}

#[test]
fn inner_builder_sign_with_callback_error() {
    // Create key that returns an error
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(-7, key_type.as_ptr(), fail_sign_callback, ptr::null_mut(), &mut key);

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    impl_headermap_set_int_inner(headers, 1, -7);
    impl_builder_set_protected_inner(builder, headers);
    free_headers(headers);

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        builder,
        key,
        b"test".as_ptr(),
        4,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0); // Sign should fail
    free_error(err);
    free_key(key);
}

#[test]
fn inner_builder_sign_with_null_sig_callback() {
    // Create key that returns null signature
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(-7, key_type.as_ptr(), null_sig_callback, ptr::null_mut(), &mut key);

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headers);
    impl_headermap_set_int_inner(headers, 1, -7);
    impl_builder_set_protected_inner(builder, headers);
    free_headers(headers);

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        builder,
        key,
        b"test".as_ptr(),
        4,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0); // Sign should fail (null signature)
    free_error(err);
    free_key(key);
}

// ============================================================================
// key_from_callback inner tests
// ============================================================================

#[test]
fn inner_key_from_callback_success() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert_eq!(rc, 0);
    assert!(!key.is_null());
    free_key(key);
}

#[test]
fn inner_key_from_callback_null_out() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let rc = impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert!(rc < 0);
}

#[test]
fn inner_key_from_callback_null_key_type() {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = impl_key_from_callback_inner(
        -7,
        ptr::null(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert!(rc < 0);
}

#[test]
fn inner_builder_sign_with_options() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(-7, key_type.as_ptr(), mock_sign_callback, ptr::null_mut(), &mut key);

    // Builder with unprotected headers and external AAD
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);

    let mut prot_headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut prot_headers);
    impl_headermap_set_int_inner(prot_headers, 1, -7);
    impl_builder_set_protected_inner(builder, prot_headers);
    free_headers(prot_headers);

    let mut unprot_headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut unprot_headers);
    impl_headermap_set_int_inner(unprot_headers, 4, 42); // kid header
    impl_builder_set_unprotected_inner(builder, unprot_headers);
    free_headers(unprot_headers);

    let aad = b"external aad";
    impl_builder_set_external_aad_inner(builder, aad.as_ptr(), aad.len());

    let payload = b"test";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_builder_sign_inner(
        builder,
        key,
        payload.as_ptr(),
        payload.len(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert_eq!(rc, 0);
    assert!(!out_bytes.is_null());
    unsafe { cose_sign1_bytes_free(out_bytes, out_len) };
    free_error(err);
    free_key(key);
}

// ============================================================================
// error inner function tests for impl_ffi
// ============================================================================

#[test]
fn error_inner_new_impl() {
    use cose_sign1_signing_ffi::error::ErrorInner;
    let err = ErrorInner::new("test error", -99);
    assert_eq!(err.message, "test error");
    assert_eq!(err.code, -99);
}

#[test]
fn error_inner_from_cose_error_impl_all_variants() {
    use cose_sign1_primitives::CoseSign1Error;
    use cose_sign1_signing_ffi::error::ErrorInner;

    let e = CoseSign1Error::CborError("bad".into());
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    let e = CoseSign1Error::KeyError(cose_sign1_primitives::CoseKeyError::Crypto(
        cose_sign1_primitives::CryptoError::SigningFailed("err".into())
    ));
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    let e = CoseSign1Error::PayloadError(cose_sign1_primitives::PayloadError::ReadFailed("err".into()));
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    let e = CoseSign1Error::InvalidMessage("err".into());
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    let e = CoseSign1Error::PayloadMissing;
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    let e = CoseSign1Error::SignatureMismatch;
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);
}

#[test]
fn error_inner_null_pointer_impl() {
    use cose_sign1_signing_ffi::error::ErrorInner;
    let err = ErrorInner::null_pointer("param");
    assert!(err.message.contains("param"));
}

#[test]
fn error_set_error_impl() {
    use cose_sign1_signing_ffi::error::{set_error, ErrorInner};

    // Null out_error is safe
    set_error(ptr::null_mut(), ErrorInner::new("test", -1));

    // Valid out_error
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("msg", -42));
    assert!(!err.is_null());

    let code = unsafe { cose_sign1_signing_error_code(err) };
    assert_eq!(code, -42);

    let msg = unsafe { cose_sign1_signing_error_message(err) };
    assert!(!msg.is_null());
    unsafe { cose_sign1_string_free(msg) };
    free_error(err);
}

#[test]
fn error_handle_to_inner_null_impl() {
    use cose_sign1_signing_ffi::error::handle_to_inner;
    let result = unsafe { handle_to_inner(ptr::null()) };
    assert!(result.is_none());
}

#[test]
fn error_code_null_handle_impl() {
    let code = unsafe { cose_sign1_signing_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn error_message_null_handle_impl() {
    let msg = unsafe { cose_sign1_signing_error_message(ptr::null()) };
    assert!(msg.is_null());
}

#[test]
fn inner_key_from_callback_invalid_utf8() {
    // Invalid UTF-8 in key_type should fail with FFI_ERR_INVALID_ARGUMENT
    let invalid = [0xC0u8, 0xAF, 0x00]; // Invalid UTF-8 + null terminator
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = impl_key_from_callback_inner(
        -7,
        invalid.as_ptr() as *const libc::c_char,
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert!(rc < 0);
    assert!(key.is_null());
}
