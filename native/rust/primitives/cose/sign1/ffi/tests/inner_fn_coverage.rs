// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests that call inner (non-extern-C) functions directly to ensure LLVM coverage
//! can attribute hits to the catch_unwind + match code paths.

use cose_sign1_primitives_ffi::message::{
    message_alg_inner, message_is_detached_inner, message_parse_inner,
    message_payload_inner, message_protected_bytes_inner, message_signature_inner,
    message_verify_detached_inner, message_verify_inner,
};
use cose_sign1_primitives_ffi::types::{CoseHeaderMapHandle, CoseSign1MessageHandle};
use cose_sign1_primitives_ffi::{
    create_key_handle, headermap_contains_inner, headermap_get_bytes_inner,
    headermap_get_int_inner, headermap_get_text_inner, headermap_len_inner,
    key_algorithm_inner, key_type_inner, message_protected_headers_inner,
    message_unprotected_headers_inner,
};
use cose_sign1_primitives_ffi::error::{cose_sign1_error_free, CoseSign1ErrorHandle};

use std::ffi::CStr;
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

fn free_error(err: *mut CoseSign1ErrorHandle) {
    if !err.is_null() {
        unsafe { cose_sign1_error_free(err) };
    }
}

fn free_msg(msg: *mut CoseSign1MessageHandle) {
    if !msg.is_null() {
        unsafe { cose_sign1_primitives_ffi::cose_sign1_message_free(msg) };
    }
}

fn free_headers(h: *mut CoseHeaderMapHandle) {
    if !h.is_null() {
        unsafe { cose_sign1_primitives_ffi::cose_headermap_free(h) };
    }
}

fn parse_msg(data: &[u8]) -> *mut CoseSign1MessageHandle {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_parse_inner(data.as_ptr(), data.len(), &mut msg, &mut err);
    assert_eq!(rc, 0, "parse failed");
    free_error(err);
    msg
}

// ============================================================================
// message inner function tests
// ============================================================================

#[test]
fn inner_parse_null_out_message() {
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_parse_inner(ptr::null(), 0, ptr::null_mut(), &mut err);
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_parse_null_data() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_parse_inner(ptr::null(), 0, &mut msg, &mut err);
    assert!(rc < 0);
    assert!(msg.is_null());
    free_error(err);
}

#[test]
fn inner_parse_invalid_cbor() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let bad = [0xFF];
    let rc = message_parse_inner(bad.as_ptr(), bad.len(), &mut msg, &mut err);
    assert!(rc < 0);
    assert!(msg.is_null());
    free_error(err);
}

#[test]
fn inner_parse_valid() {
    let data = minimal_cose_sign1_with_payload();
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_parse_inner(data.as_ptr(), data.len(), &mut msg, &mut err);
    assert_eq!(rc, 0);
    assert!(!msg.is_null());
    free_msg(msg);
}

#[test]
fn inner_protected_bytes_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = message_protected_bytes_inner(msg, &mut ptr, &mut len);
    assert_eq!(rc, 0);
    assert!(len > 0);
    free_msg(msg);
}

#[test]
fn inner_protected_bytes_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_protected_bytes_inner(msg, ptr::null_mut(), ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

#[test]
fn inner_protected_bytes_null_message() {
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = message_protected_bytes_inner(ptr::null(), &mut ptr, &mut len);
    assert!(rc < 0);
}

#[test]
fn inner_signature_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = message_signature_inner(msg, &mut ptr, &mut len);
    assert_eq!(rc, 0);
    assert!(len > 0);
    free_msg(msg);
}

#[test]
fn inner_signature_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_signature_inner(msg, ptr::null_mut(), ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

#[test]
fn inner_alg_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut alg: i64 = 0;
    let rc = message_alg_inner(msg, &mut alg);
    assert_eq!(rc, 0);
    assert_eq!(alg, -7);
    free_msg(msg);
}

#[test]
fn inner_alg_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_alg_inner(msg, ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

#[test]
fn inner_alg_null_message() {
    let mut alg: i64 = 0;
    let rc = message_alg_inner(ptr::null(), &mut alg);
    assert!(rc < 0);
}

#[test]
fn inner_is_detached_embedded() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let is_detached = message_is_detached_inner(msg);
    assert!(!is_detached);
    free_msg(msg);
}

#[test]
fn inner_is_detached_detached() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let is_detached = message_is_detached_inner(msg);
    assert!(is_detached);
    free_msg(msg);
}

#[test]
fn inner_is_detached_null() {
    let is_detached = message_is_detached_inner(ptr::null());
    assert!(!is_detached);
}

#[test]
fn inner_payload_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = message_payload_inner(msg, &mut ptr, &mut len);
    assert_eq!(rc, 0);
    let payload = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert_eq!(payload, b"test");
    free_msg(msg);
}

#[test]
fn inner_payload_detached() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = message_payload_inner(msg, &mut ptr, &mut len);
    assert!(rc < 0); // FFI_ERR_PAYLOAD_MISSING
    free_msg(msg);
}

#[test]
fn inner_payload_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_payload_inner(msg, ptr::null_mut(), ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

// ============================================================================
// verify inner function tests
// ============================================================================

/// A simple mock verifier that always returns Ok(false) for verification.
struct MockVerifier;

impl cose_sign1_primitives::CryptoVerifier for MockVerifier {
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, cose_sign1_primitives::CryptoError> {
        Ok(false) // Signature won't match our test data
    }
}

/// A mock signer for signing operations.
struct MockSigner;

impl cose_sign1_primitives::CryptoSigner for MockSigner {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7 // ES256
    }
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, cose_sign1_primitives::CryptoError> {
        Ok(vec![0u8; 64])
    }
}

/// A mock verifier that always returns an error on verify.
struct FailVerifyKey;

impl cose_sign1_primitives::CryptoVerifier for FailVerifyKey {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, cose_sign1_primitives::CryptoError> {
        Err(cose_sign1_primitives::CryptoError::VerificationFailed(
            "test error".to_string(),
        ))
    }
}

#[test]
fn inner_verify_with_key_returns_ok() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(MockVerifier));

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        msg,
        key_handle,
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert_eq!(rc, 0);
    assert!(!verified); // MockKey always returns false
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_null_out_verified() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        msg,
        ptr::null(),
        ptr::null(),
        0,
        ptr::null_mut(),
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
    free_msg(msg);
}

#[test]
fn inner_verify_null_message() {
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        ptr::null(),
        ptr::null(),
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_verify_null_key() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        msg,
        ptr::null(),
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
    free_msg(msg);
}

#[test]
fn inner_verify_with_external_aad() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let aad = b"extra data";

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        msg,
        key_handle,
        aad.as_ptr(),
        aad.len(),
        &mut verified,
        &mut err,
    );
    assert_eq!(rc, 0);
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_detached_with_key() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let payload = b"test";

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        msg,
        key_handle,
        payload.as_ptr(),
        payload.len(),
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert_eq!(rc, 0);
    assert!(!verified);
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_detached_null_out_verified() {
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        ptr::null(),
        ptr::null(),
        ptr::null(),
        0,
        ptr::null(),
        0,
        ptr::null_mut(),
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_verify_detached_null_message() {
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        ptr::null(),
        ptr::null(),
        ptr::null(),
        0,
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_verify_detached_null_key() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        msg,
        ptr::null(),
        b"test".as_ptr(),
        4,
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
    free_msg(msg);
}

#[test]
fn inner_verify_detached_null_payload() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        msg,
        key_handle,
        ptr::null(),
        0,
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0);
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_detached_with_aad() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let payload = b"test";
    let aad = b"extra";

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        msg,
        key_handle,
        payload.as_ptr(),
        payload.len(),
        aad.as_ptr(),
        aad.len(),
        &mut verified,
        &mut err,
    );
    assert_eq!(rc, 0);
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_with_failing_key() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(FailVerifyKey));

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_inner(
        msg,
        key_handle,
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0); // FFI_ERR_VERIFY_FAILED
    assert!(!verified);
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_verify_detached_with_failing_key() {
    let data = minimal_cose_sign1_detached();
    let msg = parse_msg(&data);
    let key_handle = create_key_handle(Box::new(FailVerifyKey));
    let payload = b"test";

    let mut verified = false;
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let rc = message_verify_detached_inner(
        msg,
        key_handle,
        payload.as_ptr(),
        payload.len(),
        ptr::null(),
        0,
        &mut verified,
        &mut err,
    );
    assert!(rc < 0); // FFI_ERR_VERIFY_FAILED
    free_error(err);
    free_msg(msg);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

// ============================================================================
// headermap / key inner function tests
// ============================================================================

#[test]
fn inner_protected_headers_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = message_protected_headers_inner(msg, &mut headers);
    assert_eq!(rc, 0);
    assert!(!headers.is_null());
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_protected_headers_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_protected_headers_inner(msg, ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

#[test]
fn inner_protected_headers_null_message() {
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = message_protected_headers_inner(ptr::null(), &mut headers);
    assert!(rc < 0);
}

#[test]
fn inner_unprotected_headers_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = message_unprotected_headers_inner(msg, &mut headers);
    assert_eq!(rc, 0);
    assert!(!headers.is_null());
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_unprotected_headers_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let rc = message_unprotected_headers_inner(msg, ptr::null_mut());
    assert!(rc < 0);
    free_msg(msg);
}

#[test]
fn inner_headermap_get_int_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = message_protected_headers_inner(msg, &mut headers);
    assert_eq!(rc, 0);

    let mut val: i64 = 0;
    let rc = headermap_get_int_inner(headers, 1, &mut val);
    assert_eq!(rc, 0);
    assert_eq!(val, -7);

    // Non-existent label
    let rc = headermap_get_int_inner(headers, 99, &mut val);
    assert!(rc < 0);

    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_get_int_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);
    let rc = headermap_get_int_inner(headers, 1, ptr::null_mut());
    assert!(rc < 0);
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_get_int_null_headers() {
    let mut val: i64 = 0;
    let rc = headermap_get_int_inner(ptr::null(), 1, &mut val);
    assert!(rc < 0);
}

#[test]
fn inner_headermap_get_bytes_null() {
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let rc = headermap_get_bytes_inner(ptr::null(), 1, &mut ptr, &mut len);
    assert!(rc < 0);
}

#[test]
fn inner_headermap_get_bytes_null_output() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);
    let rc = headermap_get_bytes_inner(headers, 1, ptr::null_mut(), ptr::null_mut());
    assert!(rc < 0);
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_get_bytes_not_found() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    // Label 1 is an Int (algorithm), not Bytes
    let rc = headermap_get_bytes_inner(headers, 1, &mut ptr, &mut len);
    assert!(rc < 0);
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_get_text_null() {
    let text = headermap_get_text_inner(ptr::null(), 1);
    assert!(text.is_null());
}

#[test]
fn inner_headermap_get_text_not_found() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);
    // Label 1 is Int, not Text
    let text = headermap_get_text_inner(headers, 1);
    assert!(text.is_null());
    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_contains_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);

    assert!(headermap_contains_inner(headers, 1));
    assert!(!headermap_contains_inner(headers, 99));

    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_contains_null() {
    assert!(!headermap_contains_inner(ptr::null(), 1));
}

#[test]
fn inner_headermap_len_valid() {
    let data = minimal_cose_sign1_with_payload();
    let msg = parse_msg(&data);
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    message_protected_headers_inner(msg, &mut headers);

    let len = headermap_len_inner(headers);
    assert_eq!(len, 1);

    free_headers(headers);
    free_msg(msg);
}

#[test]
fn inner_headermap_len_null() {
    let len = headermap_len_inner(ptr::null());
    assert_eq!(len, 0);
}

#[test]
fn inner_key_algorithm_with_mock() {
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let mut alg: i64 = 0;
    let rc = key_algorithm_inner(key_handle, &mut alg);
    assert_eq!(rc, 0);
    assert_eq!(alg, -7);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_key_algorithm_null() {
    let mut alg: i64 = 0;
    let rc = key_algorithm_inner(ptr::null(), &mut alg);
    assert!(rc < 0);
}

#[test]
fn inner_key_algorithm_null_output() {
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let rc = key_algorithm_inner(key_handle, ptr::null_mut());
    assert!(rc < 0);
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_key_type_with_mock() {
    let key_handle = create_key_handle(Box::new(MockVerifier));
    let key_type = key_type_inner(key_handle);
    assert!(!key_type.is_null());
    let s = unsafe { CStr::from_ptr(key_type) }.to_string_lossy().to_string();
    // CryptoVerifier trait doesn't have key_type(), so the FFI returns "unknown"
    assert_eq!(s, "unknown");
    unsafe { cose_sign1_primitives_ffi::cose_sign1_string_free(key_type) };
    unsafe { cose_sign1_primitives_ffi::cose_key_free(key_handle as *mut _) };
}

#[test]
fn inner_key_type_null() {
    let key_type = key_type_inner(ptr::null());
    assert!(key_type.is_null());
}

// ============================================================================
// error inner function tests
// ============================================================================

#[test]
fn error_inner_new() {
    use cose_sign1_primitives_ffi::error::ErrorInner;
    let err = ErrorInner::new("test error", -99);
    assert_eq!(err.message, "test error");
    assert_eq!(err.code, -99);
}

#[test]
fn error_inner_from_cose_error_all_variants() {
    use cose_sign1_primitives::CoseSign1Error;
    use cose_sign1_primitives_ffi::error::ErrorInner;

    // CborError
    let e = CoseSign1Error::CborError("bad cbor".into());
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    // KeyError wrapping CryptoError
    let e = CoseSign1Error::KeyError(cose_sign1_primitives::CoseKeyError::Crypto(
        cose_sign1_primitives::CryptoError::VerificationFailed("err".into())
    ));
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    // PayloadError
    let e = CoseSign1Error::PayloadError(cose_sign1_primitives::PayloadError::ReadFailed("bad".into()));
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    // InvalidMessage
    let e = CoseSign1Error::InvalidMessage("bad msg".into());
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    // PayloadMissing
    let e = CoseSign1Error::PayloadMissing;
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);

    // SignatureMismatch
    let e = CoseSign1Error::SignatureMismatch;
    let inner = ErrorInner::from_cose_error(&e);
    assert!(inner.code < 0);
}

#[test]
fn error_inner_null_pointer() {
    use cose_sign1_primitives_ffi::error::ErrorInner;
    let err = ErrorInner::null_pointer("test_param");
    assert!(err.message.contains("test_param"));
    assert!(err.code < 0);
}

#[test]
fn error_set_error_null_out() {
    use cose_sign1_primitives_ffi::error::{set_error, ErrorInner};
    // Passing null out_error should not crash
    set_error(ptr::null_mut(), ErrorInner::new("test", -1));
}

#[test]
fn error_set_error_valid() {
    use cose_sign1_primitives_ffi::error::{set_error, ErrorInner};
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("test error msg", -42));
    assert!(!err.is_null());

    // Read back code
    let code = unsafe { cose_sign1_primitives_ffi::cose_sign1_error_code(err) };
    assert_eq!(code, -42);

    // Read back message
    let msg = unsafe { cose_sign1_primitives_ffi::cose_sign1_error_message(err) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    assert_eq!(s, "test error msg");
    unsafe { cose_sign1_primitives_ffi::cose_sign1_string_free(msg) };
    free_error(err);
}

#[test]
fn error_handle_to_inner_null() {
    use cose_sign1_primitives_ffi::error::handle_to_inner;
    let result = unsafe { handle_to_inner(ptr::null()) };
    assert!(result.is_none());
}

#[test]
fn error_code_null_handle() {
    let code = unsafe { cose_sign1_primitives_ffi::cose_sign1_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn error_message_null_handle() {
    let msg = unsafe { cose_sign1_primitives_ffi::cose_sign1_error_message(ptr::null()) };
    assert!(msg.is_null());
}

#[test]
fn error_message_nul_byte_in_message() {
    use cose_sign1_primitives_ffi::error::{set_error, ErrorInner};
    // Create an error with a NUL byte embedded in the message
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("bad\0msg", -1));
    assert!(!err.is_null());

    let msg = unsafe { cose_sign1_primitives_ffi::cose_sign1_error_message(err) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    assert!(s.contains("NUL"));
    unsafe { cose_sign1_primitives_ffi::cose_sign1_string_free(msg) };
    free_error(err);
}
