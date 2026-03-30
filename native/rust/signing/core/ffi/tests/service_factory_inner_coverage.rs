// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional tests for signing service and factory FFI inner functions.
//!
//! These tests target previously uncovered paths in the signing FFI layer.

use cose_sign1_signing_ffi::error::{
    cose_sign1_signing_error_free, CoseSign1SigningErrorHandle, ErrorInner,
};
use cose_sign1_signing_ffi::types::{
    CoseKeyHandle, CoseSign1FactoryHandle, CoseSign1SigningServiceHandle,
};
use cose_sign1_signing_ffi::*;
use std::ptr;

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

// ============================================================================
// Signing service inner function tests
// ============================================================================

#[test]
fn inner_signing_service_create_success() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert!(!key.is_null());

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_signing_service_create_inner(key, &mut service, &mut err);
    assert_eq!(rc, 0);
    assert!(!service.is_null());

    free_service(service);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_signing_service_create_null_out() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_signing_service_create_inner(key, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_key(key);
    free_error(err);
}

#[test]
fn inner_signing_service_create_null_key() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_signing_service_create_inner(ptr::null(), &mut service, &mut err);
    assert!(rc < 0);
    assert!(service.is_null());

    free_error(err);
}

// ============================================================================
// Factory inner function tests
// ============================================================================

#[test]
fn inner_factory_create_success() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_factory_create_inner(service, &mut factory, &mut err);
    assert_eq!(rc, 0);
    assert!(!factory.is_null());

    free_factory(factory);
    // service ownership transferred to factory
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_create_null_out() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    err = ptr::null_mut();
    let rc = impl_factory_create_inner(service, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_service(service);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_create_null_service() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_create_inner(ptr::null(), &mut factory, &mut err);
    assert!(rc < 0);
    assert!(factory.is_null());

    free_error(err);
}

// ============================================================================
// Factory sign direct inner function tests
// ============================================================================

#[test]
fn inner_factory_sign_direct_null_out_bytes() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        ptr::null_mut(), // null out_bytes
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_out_len() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        ptr::null_mut(), // null out_len
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_factory() {
    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
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
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_content_type() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let payload = b"test payload";
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        ptr::null(), // null content_type
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

// ============================================================================
// Factory sign indirect inner function tests
// ============================================================================

#[test]
fn inner_factory_sign_indirect_null_out_bytes() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        ptr::null_mut(), // null out_bytes
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_null_factory() {
    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
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
    assert!(rc < 0);

    free_error(err);
}

// ============================================================================
// Factory sign direct file inner function tests
// ============================================================================

#[test]
fn inner_factory_sign_direct_file_null_path() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        ptr::null(), // null path
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_file_null_factory() {
    let path = std::ffi::CString::new("test.txt").unwrap();
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_sign_direct_file_inner(
        ptr::null(),
        path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_factory_sign_direct_file_null_content_type() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let path = std::ffi::CString::new("test.txt").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_file_inner(
        factory,
        path.as_ptr(),
        ptr::null(), // null content_type
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

// ============================================================================
// Factory sign indirect file inner function tests
// ============================================================================

#[test]
fn inner_factory_sign_indirect_file_null_path() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        ptr::null(), // null path
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_file_null_factory() {
    let path = std::ffi::CString::new("test.txt").unwrap();
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_sign_indirect_file_inner(
        ptr::null(),
        path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_error(err);
}

// ============================================================================
// Error inner function tests
// ============================================================================

#[test]
fn error_inner_from_cose_error_cbor() {
    use cose_sign1_primitives::CoseSign1Error;
    let err = CoseSign1Error::CborError("bad cbor".into());
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_from_cose_error_key() {
    use cose_sign1_primitives::{CoseKeyError, CoseSign1Error, CryptoError};
    let err = CoseSign1Error::KeyError(CoseKeyError::Crypto(CryptoError::SigningFailed(
        "err".into(),
    )));
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_from_cose_error_payload() {
    use cose_sign1_primitives::{CoseSign1Error, PayloadError};
    let err = CoseSign1Error::PayloadError(PayloadError::ReadFailed("disk error".into()));
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_from_cose_error_invalid_message() {
    use cose_sign1_primitives::CoseSign1Error;
    let err = CoseSign1Error::InvalidMessage("bad".into());
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_from_cose_error_payload_missing() {
    use cose_sign1_primitives::CoseSign1Error;
    let err = CoseSign1Error::PayloadMissing;
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_from_cose_error_sig_mismatch() {
    use cose_sign1_primitives::CoseSign1Error;
    let err = CoseSign1Error::SignatureMismatch;
    let inner = ErrorInner::from_cose_error(&err);
    assert!(inner.code < 0);
    assert!(!inner.message.is_empty());
}

#[test]
fn error_inner_new_and_null_pointer() {
    let inner = ErrorInner::new("test error", -42);
    assert_eq!(inner.message, "test error");
    assert_eq!(inner.code, -42);

    let null_err = ErrorInner::null_pointer("param");
    assert!(null_err.message.contains("param"));
    assert!(null_err.code < 0);
}

#[test]
fn handle_to_inner_null() {
    use cose_sign1_signing_ffi::error::handle_to_inner;
    let result = unsafe { handle_to_inner(ptr::null()) };
    assert!(result.is_none());
}

// ============================================================================
// Crypto signer service inner function tests
// ============================================================================

#[test]
fn inner_signing_service_from_crypto_signer_null_out() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc =
        impl_signing_service_from_crypto_signer_inner(ptr::null_mut(), ptr::null_mut(), &mut err);
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_signing_service_from_crypto_signer_null_signer() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_signing_service_from_crypto_signer_inner(ptr::null_mut(), &mut service, &mut err);
    assert!(rc < 0);
    free_error(err);
}

// ============================================================================
// Crypto signer factory inner function tests
// ============================================================================

#[test]
fn inner_factory_from_crypto_signer_null_out() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_from_crypto_signer_inner(ptr::null_mut(), ptr::null_mut(), &mut err);
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_factory_from_crypto_signer_null_signer() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_from_crypto_signer_inner(ptr::null_mut(), &mut factory, &mut err);
    assert!(rc < 0);
    free_error(err);
}

// ============================================================================
// Factory streaming inner function tests
// ============================================================================

/// Mock read callback for streaming tests.
unsafe extern "C" fn mock_streaming_callback(
    buffer: *mut u8,
    buffer_len: usize,
    user_data: *mut libc::c_void,
) -> i64 {
    let counter_ptr = user_data as *mut usize;
    let counter = unsafe { *counter_ptr };
    let payload = b"streaming payload data";

    if counter >= payload.len() {
        return 0; // EOF
    }

    let remaining = payload.len() - counter;
    let to_copy = std::cmp::min(remaining, buffer_len);

    unsafe {
        std::ptr::copy_nonoverlapping(payload.as_ptr().add(counter), buffer, to_copy);
        *counter_ptr = counter + to_copy;
    }

    to_copy as i64
}

#[test]
fn inner_factory_sign_direct_streaming_null_out_bytes() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut counter: usize = 0;
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        content_type.as_ptr(),
        ptr::null_mut(), // null out_bytes
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_streaming_null_factory() {
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut counter: usize = 0;
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_sign_direct_streaming_inner(
        ptr::null(),
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_factory_sign_direct_streaming_null_content_type() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let mut counter: usize = 0;
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        ptr::null(), // null content_type
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_streaming_null_out_bytes() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut counter: usize = 0;
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        content_type.as_ptr(),
        ptr::null_mut(), // null out_bytes
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_streaming_null_factory() {
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut counter: usize = 0;
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let rc = impl_factory_sign_indirect_streaming_inner(
        ptr::null(),
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_streaming_null_content_type() {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    err = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);

    let mut counter: usize = 0;
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_streaming_callback,
        22,
        &mut counter as *mut _ as *mut libc::c_void,
        ptr::null(), // null content_type
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert!(rc < 0);

    free_factory(factory);
    free_key(key);
    free_error(err);
}
