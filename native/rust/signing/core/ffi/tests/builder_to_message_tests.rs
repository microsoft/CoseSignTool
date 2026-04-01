// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for `_to_message` FFI functions in `cose_sign1_signing_ffi`.
//!
//! These functions return a `*mut CoseSign1MessageHandle` instead of raw bytes.
//! This file covers all seven `_to_message` public FFI entry points plus their
//! inner implementations, along with null-pointer error paths.

use cose_sign1_signing_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

// ============================================================================
// Helpers (mirrored from builder_ffi_smoke.rs)
// ============================================================================

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

/// Mock sign callback that produces a deterministic 64-byte signature.
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

/// Frees a `CoseSign1MessageHandle` returned by the signing FFI.
///
/// The handle is a `Box<MessageInner>` cast to `*mut CoseSign1MessageHandle`,
/// where `MessageInner` is a single-field struct wrapping `CoseSign1Message`.
/// We reconstruct the box with the correct layout so it drops cleanly.
///
/// # Safety
///
/// `handle` must have been returned by a `_to_message` FFI function and not
/// yet freed.
unsafe fn free_message_handle(handle: *mut CoseSign1MessageHandle) {
    if handle.is_null() {
        return;
    }
    // MessageInner is repr(Rust) containing a single CoseSign1Message field.
    // Re-derive the box with the same type alias used by the crate.
    #[repr(C)]
    struct MessageInnerCompat {
        _message: cose_sign1_primitives::CoseSign1Message,
    }
    unsafe {
        drop(Box::from_raw(handle as *mut MessageInnerCompat));
    }
}

/// Mock read callback for streaming tests. Returns the test data in one read.
unsafe extern "C" fn mock_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let data: &[u8] = b"streaming payload data";
    let state = unsafe { &mut *(user_data as *mut StreamState) };
    if state.done {
        return 0; // EOF
    }
    let to_copy = data.len().min(buffer_len);
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, to_copy);
    }
    state.done = true;
    to_copy as i64
}

/// State tracker for mock read callback.
struct StreamState {
    done: bool,
}

// ============================================================================
// 1. cose_sign1_builder_sign_to_message
// ============================================================================

#[test]
fn builder_sign_to_message_happy_path() {
    // Set up protected headers with algorithm ES256
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

    // Sign to message
    let payload = b"hello from builder_sign_to_message";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(
        !out_message.is_null(),
        "out_message should be non-null on success"
    );

    // Clean up (builder consumed by sign)
    unsafe {
        free_message_handle(out_message);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_detached() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_detached(builder, true) };

    let key = create_mock_key();
    let payload = b"detached payload";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_message.is_null());

    unsafe {
        free_message_handle(out_message);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_untagged() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_tagged(builder, false) };

    let key = create_mock_key();
    let payload = b"untagged payload";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_message.is_null());

    unsafe {
        free_message_handle(out_message);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_with_headers() {
    let mut protected: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut protected) };
    unsafe { cose_headermap_set_int(protected, 1, -7) };

    let mut unprotected: *mut CoseHeaderMapHandle = ptr::null_mut();
    unsafe { cose_headermap_new(&mut unprotected) };
    let kid = b"test-key-id";
    unsafe { cose_headermap_set_bytes(unprotected, 4, kid.as_ptr(), kid.len()) };

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };
    unsafe { cose_sign1_builder_set_protected(builder, protected) };
    unsafe { cose_sign1_builder_set_unprotected(builder, unprotected) };
    unsafe { cose_headermap_free(protected) };
    unsafe { cose_headermap_free(unprotected) };

    let key = create_mock_key();
    let payload = b"payload with headers";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_message.is_null());

    unsafe {
        free_message_handle(out_message);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_null_out_message() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let key = create_mock_key();
    let payload = b"test";
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            ptr::null_mut(), // null out_message
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        // Builder is NOT consumed on null-pointer-error; free it.
        cose_sign1_builder_free(builder);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_null_builder() {
    let key = create_mock_key();
    let payload = b"test";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            ptr::null_mut(), // null builder
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

#[test]
fn builder_sign_to_message_null_key() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let payload = b"test";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            ptr::null(), // null key
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        // Builder freed internally when it gets past the out_message null check
        // but builder IS consumed (Box::from_raw is called) even on key-null error.
    };
}

#[test]
fn builder_sign_to_message_null_payload_with_nonzero_len() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let key = create_mock_key();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            ptr::null(), // null payload
            42,          // nonzero len
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

// ============================================================================
// 2. cose_sign1_factory_sign_direct_to_message
// ============================================================================

#[test]
fn factory_sign_direct_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"direct payload";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"test";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_to_message_null_factory() {
    let payload = b"test";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_to_message(
            ptr::null(),
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_direct_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"test";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_to_message_null_payload_nonzero_len() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_to_message(
            factory,
            ptr::null(),
            10,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// 3. cose_sign1_factory_sign_indirect_to_message
// ============================================================================

#[test]
fn factory_sign_indirect_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"indirect payload";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification, so factory operations fail
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"test";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_to_message_null_factory() {
    let payload = b"test";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_to_message(
            ptr::null(),
            payload.as_ptr(),
            payload.len() as u32,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_indirect_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"test";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_to_message(
            factory,
            payload.as_ptr(),
            payload.len() as u32,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// 4. cose_sign1_factory_sign_direct_file_to_message
// ============================================================================

#[test]
fn factory_sign_direct_file_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    // Create a temporary file with test content
    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("test_direct.bin");
    std::fs::write(&file_path, b"direct file content").unwrap();

    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_file_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_file_to_message_null_factory() {
    let path_cstr = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            ptr::null(),
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_direct_file_to_message_null_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            factory,
            ptr::null(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_file_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("test.bin").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            factory,
            path_cstr.as_ptr(),
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// 5. cose_sign1_factory_sign_indirect_file_to_message
// ============================================================================

#[test]
fn factory_sign_indirect_file_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("test_indirect.bin");
    std::fs::write(&file_path, b"indirect file content").unwrap();

    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_file_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_file_to_message_null_factory() {
    let path_cstr = CString::new("test.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            ptr::null(),
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_indirect_file_to_message_null_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            factory,
            ptr::null(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_file_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("test.bin").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            factory,
            path_cstr.as_ptr(),
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// 6. cose_sign1_factory_sign_direct_streaming_to_message
// ============================================================================

#[test]
fn factory_sign_direct_streaming_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let payload_data: &[u8] = b"streaming payload data";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming_to_message(
            factory,
            mock_read_callback,
            payload_data.len() as u64,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_streaming_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming_to_message(
            factory,
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_direct_streaming_to_message_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming_to_message(
            ptr::null(),
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_direct_streaming_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let mut state = StreamState { done: false };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_streaming_to_message(
            factory,
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// 7. cose_sign1_factory_sign_indirect_streaming_to_message
// ============================================================================

#[test]
fn factory_sign_indirect_streaming_to_message_exercises_path() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let payload_data: &[u8] = b"streaming payload data";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming_to_message(
            factory,
            mock_read_callback,
            payload_data.len() as u64,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    // FFI signing service doesn't support post-sign verification
    assert_eq!(
        rc,
        COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
        "Error: {:?}",
        error_message(err)
    );
    assert!(out_message.is_null());
    assert!(!err.is_null());

    let msg = error_message(err).unwrap_or_default();
    assert!(msg.contains("factory failed") && msg.contains("verification not supported"));

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_streaming_to_message_null_out_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming_to_message(
            factory,
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_streaming_to_message_null_factory() {
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming_to_message(
            ptr::null(),
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe { cose_sign1_signing_error_free(err) };
}

#[test]
fn factory_sign_indirect_streaming_to_message_null_content_type() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let mut state = StreamState { done: false };
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_streaming_to_message(
            factory,
            mock_read_callback,
            22,
            &mut state as *mut StreamState as *mut libc::c_void,
            ptr::null(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_NULL_POINTER);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// Inner function tests — exercise the pub inner implementations directly
// ============================================================================

#[test]
fn inner_builder_sign_to_message() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    let key = create_mock_key();
    let payload = b"inner test";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_builder_sign_to_message_inner(
        builder,
        key,
        payload.as_ptr(),
        payload.len(),
        &mut out_message,
        &mut err,
    );

    assert_eq!(rc, COSE_SIGN1_SIGNING_OK, "Error: {:?}", error_message(err));
    assert!(!out_message.is_null());

    unsafe {
        free_message_handle(out_message);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_direct_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"inner direct";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_to_message_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_indirect_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let payload = b"inner indirect";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_to_message_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_direct_file_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("inner_direct.bin");
    std::fs::write(&file_path, b"inner direct file").unwrap();

    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_file_to_message_inner(
        factory,
        path_cstr.as_ptr(),
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_indirect_file_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let tmp_dir = tempfile::tempdir().unwrap();
    let file_path = tmp_dir.path().join("inner_indirect.bin");
    std::fs::write(&file_path, b"inner indirect file").unwrap();

    let path_cstr = CString::new(file_path.to_str().unwrap()).unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_file_to_message_inner(
        factory,
        path_cstr.as_ptr(),
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_direct_streaming_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let payload_data: &[u8] = b"streaming payload data";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_to_message_inner(
        factory,
        mock_read_callback,
        payload_data.len() as u64,
        &mut state as *mut StreamState as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn inner_factory_sign_indirect_streaming_to_message() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut state = StreamState { done: false };
    let payload_data: &[u8] = b"streaming payload data";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_streaming_to_message_inner(
        factory,
        mock_read_callback,
        payload_data.len() as u64,
        &mut state as *mut StreamState as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_message,
        &mut err,
    );

    // FFI signing service doesn't support post-sign verification
    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

// ============================================================================
// Failing sign callback — exercises error path in builder_sign_to_message
// ============================================================================

/// Sign callback that always fails.
unsafe extern "C" fn failing_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -1
}

#[test]
fn builder_sign_to_message_sign_failure() {
    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    unsafe { cose_sign1_builder_new(&mut builder) };

    // Create a key with a failing callback
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

    let payload = b"will fail";
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_builder_sign_to_message(
            builder,
            key,
            payload.as_ptr(),
            payload.len(),
            &mut out_message,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_SIGN1_SIGNING_ERR_SIGN_FAILED);
    assert!(out_message.is_null());
    assert!(!err.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_key_free(key);
    };
}

// ============================================================================
// File-not-found error path for file _to_message functions
// ============================================================================

#[test]
fn factory_sign_direct_file_to_message_nonexistent_file() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("/nonexistent/path/file.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_direct_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_ne!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}

#[test]
fn factory_sign_indirect_file_to_message_nonexistent_file() {
    let key = create_mock_key();
    let service = create_signing_service(key);
    let factory = create_factory(service);

    let path_cstr = CString::new("/nonexistent/path/file.bin").unwrap();
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_message: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_sign1_factory_sign_indirect_file_to_message(
            factory,
            path_cstr.as_ptr(),
            content_type.as_ptr(),
            &mut out_message,
            &mut err,
        )
    };

    assert_ne!(rc, COSE_SIGN1_SIGNING_OK);
    assert!(out_message.is_null());

    unsafe {
        cose_sign1_signing_error_free(err);
        cose_sign1_factory_free(factory);
        cose_sign1_signing_service_free(service);
        cose_key_free(key);
    };
}
