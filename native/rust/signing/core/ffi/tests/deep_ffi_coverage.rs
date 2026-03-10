// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in cose_sign1_signing_ffi/src/lib.rs.
//!
//! The factory sign success-path (Ok) lines (1137-1146, 1258-1267, 1490-1499,
//! 1630-1639, 1754-1763, 1879-1888) are unreachable via the current FFI because
//! `SimpleSigningService::verify_signature` always returns Err. The factory's
//! mandatory post-sign verification prevents the Ok branch from executing.
//!
//! These tests cover the reachable portions:
//! - Factory sign error path through inner functions (exercises the signing pipeline
//!   up to verification, which exercises SimpleSigningService, ArcCryptoSignerWrapper,
//!   and CallbackKey trait impls — lines 2038-2127)
//! - Crypto-signer null pointer paths (lines 899-924, 968-995)
//! - Factory create inner (line 1053-1059)
//! - CallbackReader::len() via streaming (line 1404-1409)
//! - File-based signing error paths (lines 1490-1519, 1630-1659)
//! - Streaming signing error paths (lines 1754-1783, 1879-1908)

use cose_sign1_signing_ffi::error::{cose_sign1_signing_error_free, CoseSign1SigningErrorHandle};
use cose_sign1_signing_ffi::types::{
    CoseKeyHandle, CoseSign1FactoryHandle, CoseSign1SigningServiceHandle,
};
use cose_sign1_signing_ffi::*;

use std::ffi::CString;
use std::ptr;

// ============================================================================
// Helpers
// ============================================================================

fn free_error(err: *mut CoseSign1SigningErrorHandle) {
    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
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

fn free_cose_bytes(ptr: *mut u8, len: u32) {
    if !ptr.is_null() {
        unsafe { cose_sign1_cose_bytes_free(ptr, len) };
    }
}

/// Mock signing callback that produces a deterministic 64-byte signature.
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

/// Creates a callback-based key handle for testing.
fn create_test_key() -> *mut CoseKeyHandle {
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let key_type = CString::new("EC").unwrap();
    let rc = impl_key_from_callback_inner(-7, key_type.as_ptr(), mock_sign_callback, ptr::null_mut(), &mut key);
    assert_eq!(rc, 0, "key creation failed");
    assert!(!key.is_null());
    key
}

/// Creates a signing service from a key handle via the inner function.
fn create_test_service(key: *const CoseKeyHandle) -> *mut CoseSign1SigningServiceHandle {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_signing_service_create_inner(key, &mut service, &mut err);
    assert_eq!(rc, 0, "service creation failed");
    assert!(!service.is_null());
    free_error(err);
    service
}

/// Creates a factory from a signing service via the inner function.
fn create_test_factory(service: *const CoseSign1SigningServiceHandle) -> *mut CoseSign1FactoryHandle {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_create_inner(service, &mut factory, &mut err);
    assert_eq!(rc, 0, "factory creation failed");
    assert!(!factory.is_null());
    free_error(err);
    factory
}

// ============================================================================
// Factory sign direct — exercises error path + all signing pipeline (lines 1137-1166)
// SimpleSigningService::get_cose_signer, ArcCryptoSignerWrapper, CallbackKey
// ============================================================================

#[test]
fn factory_sign_direct_inner_exercises_pipeline() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let payload = b"hello world";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Factory fails at verify step but exercises signing pipeline
    // This covers the Err branch (lines 1148-1153) and exercises
    // SimpleSigningService::get_cose_signer, ArcCryptoSignerWrapper, CallbackKey
    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign indirect — exercises error path (lines 1258-1287)
// ============================================================================

#[test]
fn factory_sign_indirect_inner_exercises_pipeline() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let payload = b"indirect payload data";
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign direct file — exercises pipeline (lines 1490-1519)
// Also exercises CallbackReader::len() (lines 1404-1409) via streaming
// ============================================================================

#[test]
fn factory_sign_direct_file_inner_exercises_pipeline() {
    use std::io::Write;

    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut tmpfile = tempfile::NamedTempFile::new().expect("failed to create temp file");
    tmpfile.write_all(b"file payload for direct signing").unwrap();
    tmpfile.flush().unwrap();

    let file_path = CString::new(tmpfile.path().to_str().unwrap()).unwrap();
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

    // Exercises file-based streaming signing pipeline
    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign indirect file — exercises pipeline (lines 1630-1659)
// ============================================================================

#[test]
fn factory_sign_indirect_file_inner_exercises_pipeline() {
    use std::io::Write;

    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut tmpfile = tempfile::NamedTempFile::new().expect("failed to create temp file");
    tmpfile.write_all(b"file payload for indirect signing").unwrap();
    tmpfile.flush().unwrap();

    let file_path = CString::new(tmpfile.path().to_str().unwrap()).unwrap();
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

    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign direct streaming — exercises pipeline (lines 1754-1783)
// Exercises CallbackStreamingPayload, CallbackReader, CallbackReader::len()
// ============================================================================

/// Streaming read callback backed by a static byte buffer.
struct StreamState {
    data: Vec<u8>,
    offset: usize,
}

unsafe extern "C" fn stream_read_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let state = &mut *(user_data as *mut StreamState);
    let remaining = state.data.len() - state.offset;
    let to_copy = buffer_len.min(remaining);
    if to_copy > 0 {
        std::ptr::copy_nonoverlapping(
            state.data.as_ptr().add(state.offset),
            buffer,
            to_copy,
        );
        state.offset += to_copy;
    }
    to_copy as i64
}

#[test]
fn factory_sign_direct_streaming_inner_exercises_pipeline() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut state = StreamState {
        data: b"streaming payload for direct sign".to_vec(),
        offset: 0,
    };
    let payload_len = state.data.len() as u64;
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        stream_read_callback,
        payload_len,
        &mut state as *mut StreamState as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Exercises streaming signing pipeline incl. CallbackReader::read/len
    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign indirect streaming — exercises pipeline (lines 1879-1908)
// ============================================================================

#[test]
fn factory_sign_indirect_streaming_inner_exercises_pipeline() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut state = StreamState {
        data: b"streaming payload for indirect sign".to_vec(),
        offset: 0,
    };
    let payload_len = state.data.len() as u64;
    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        stream_read_callback,
        payload_len,
        &mut state as *mut StreamState as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Crypto-signer factory paths (lines 899-912, 968-983)
// ============================================================================

#[test]
fn signing_service_from_crypto_signer_null_signer() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_from_crypto_signer_inner(
        ptr::null_mut(),
        &mut service,
        &mut err,
    );

    assert!(rc < 0);
    assert!(service.is_null());
    free_error(err);
}

#[test]
fn signing_service_from_crypto_signer_null_out_service() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_from_crypto_signer_inner(
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

#[test]
fn factory_from_crypto_signer_null_signer() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_from_crypto_signer_inner(
        ptr::null_mut(),
        &mut factory,
        &mut err,
    );

    assert!(rc < 0);
    assert!(factory.is_null());
    free_error(err);
}

#[test]
fn factory_from_crypto_signer_null_out_factory() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_from_crypto_signer_inner(
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

// ============================================================================
// Factory sign with empty payload (null ptr + zero length)
// ============================================================================

#[test]
fn factory_sign_direct_inner_empty_payload() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        ptr::null(),
        0,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Exercises empty payload path (null+0 is allowed)
    // Factory still fails at verify, but exercises the code path
    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn factory_sign_indirect_inner_empty_payload() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let content_type = CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_inner(
        factory,
        ptr::null(),
        0,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert_ne!(rc, 0);

    free_cose_bytes(out_bytes, out_len);
    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Factory sign with nonexistent file — exercises file open error path
// ============================================================================

#[test]
fn factory_sign_direct_file_nonexistent() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let file_path = CString::new("/nonexistent/path/to/file.bin").unwrap();
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

    assert_ne!(rc, 0);
    assert!(out_bytes.is_null());

    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn factory_sign_indirect_file_nonexistent() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let file_path = CString::new("/nonexistent/path/to/file.bin").unwrap();
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

    assert_ne!(rc, 0);
    assert!(out_bytes.is_null());

    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

// ============================================================================
// Streaming with null content_type — exercises null check path
// ============================================================================

#[test]
fn factory_sign_direct_streaming_null_content_type() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut state = StreamState {
        data: b"test".to_vec(),
        offset: 0,
    };
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        stream_read_callback,
        4,
        &mut state as *mut StreamState as *mut libc::c_void,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);

    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}

#[test]
fn factory_sign_indirect_streaming_null_content_type() {
    let key = create_test_key();
    let service = create_test_service(key);
    let factory = create_test_factory(service);

    let mut state = StreamState {
        data: b"test".to_vec(),
        offset: 0,
    };
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        stream_read_callback,
        4,
        &mut state as *mut StreamState as *mut libc::c_void,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);

    free_error(err);
    free_factory(factory);
    free_service(service);
    free_key(key);
}
