// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for cose_sign1_primitives_ffi.
//!
//! These tests verify the C calling convention compatibility and handle lifecycle.

use cose_sign1_primitives_ffi::*;
use std::ffi::CStr;
use std::ptr;

/// Helper to get error message from an error handle.
fn error_message(err: *const CoseSign1ErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { cose_sign1_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_sign1_string_free(msg) };
    Some(s)
}

/// Creates a minimal COSE_Sign1 message for testing.
///
/// Structure: [ bstr(a1 01 26), {}, h'payload', h'signature' ]
/// - Protected: { 1: -7 } (ES256)
/// - Unprotected: {}
/// - Payload: "test"
/// - Signature: "sig!"
fn minimal_cose_sign1_with_payload() -> Vec<u8> {
    // D2                     -- Tag 18 (COSE_Sign1)
    // 84                     -- Array(4)
    //   43 A1 01 26          -- bstr(3) containing { 1: -7 }
    //   A0                   -- map(0)
    //   44 74 65 73 74       -- bstr(4) "test"
    //   44 73 69 67 21       -- bstr(4) "sig!"
    vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x44, 0x73, 0x69,
        0x67, 0x21,
    ]
}

/// Creates a minimal COSE_Sign1 message with detached payload.
///
/// Structure: [ bstr(a1 01 26), {}, null, h'signature' ]
fn minimal_cose_sign1_detached() -> Vec<u8> {
    // D2                     -- Tag 18 (COSE_Sign1)
    // 84                     -- Array(4)
    //   43 A1 01 26          -- bstr(3) containing { 1: -7 }
    //   A0                   -- map(0)
    //   F6                   -- null
    //   44 73 69 67 21       -- bstr(4) "sig!"
    vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0xF6, 0x44, 0x73, 0x69, 0x67, 0x21,
    ]
}

/// Creates a minimal untagged COSE_Sign1 message.
fn minimal_cose_sign1_untagged() -> Vec<u8> {
    // 84                     -- Array(4)
    //   43 A1 01 26          -- bstr(3) containing { 1: -7 }
    //   A0                   -- map(0)
    //   44 74 65 73 74       -- bstr(4) "test"
    //   44 73 69 67 21       -- bstr(4) "sig!"
    vec![
        0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74, 0x44, 0x73, 0x69, 0x67,
        0x21,
    ]
}

#[test]
fn ffi_abi_version() {
    let version = cose_sign1_ffi_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_null_free_is_safe() {
    // All free functions should handle null safely
    unsafe {
        cose_sign1_message_free(ptr::null_mut());
        cose_sign1_error_free(ptr::null_mut());
        cose_sign1_string_free(ptr::null_mut());
        cose_headermap_free(ptr::null_mut());
        cose_key_free(ptr::null_mut());
    }
}

#[test]
fn ffi_parse_null_inputs() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    // Null out_message should fail
    let rc = unsafe { cose_sign1_message_parse(ptr::null(), 0, ptr::null_mut(), &mut err) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_message"));
    unsafe { cose_sign1_error_free(err) };

    // Null data should fail
    err = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_parse(ptr::null(), 0, &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(msg.is_null());
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("data"));
    unsafe { cose_sign1_error_free(err) };
}

#[test]
fn ffi_parse_invalid_cbor() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let bad_data = [0x00, 0x01, 0x02];
    let rc =
        unsafe { cose_sign1_message_parse(bad_data.as_ptr(), bad_data.len(), &mut msg, &mut err) };

    assert_eq!(rc, COSE_SIGN1_ERR_PARSE_FAILED);
    assert!(msg.is_null());
    assert!(!err.is_null());

    let err_msg = error_message(err).unwrap_or_default();
    assert!(!err_msg.is_empty());

    unsafe { cose_sign1_error_free(err) };
}

#[test]
fn ffi_parse_valid_message_with_payload() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let data = minimal_cose_sign1_with_payload();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };

    assert_eq!(rc, COSE_SIGN1_OK, "Error: {:?}", error_message(err));
    assert!(!msg.is_null());
    assert!(err.is_null());

    // Check it's not detached
    let is_detached = unsafe { cose_sign1_message_is_detached(msg) };
    assert!(!is_detached);

    // Get algorithm
    let mut alg: i64 = 0;
    let rc = unsafe { cose_sign1_message_alg(msg, &mut alg) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(alg, -7); // ES256

    // Get payload
    let mut payload_ptr: *const u8 = ptr::null();
    let mut payload_len: usize = 0;
    let rc = unsafe { cose_sign1_message_payload(msg, &mut payload_ptr, &mut payload_len) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(payload_len, 4);
    let payload = unsafe { std::slice::from_raw_parts(payload_ptr, payload_len) };
    assert_eq!(payload, b"test");

    // Get signature
    let mut sig_ptr: *const u8 = ptr::null();
    let mut sig_len: usize = 0;
    let rc = unsafe { cose_sign1_message_signature(msg, &mut sig_ptr, &mut sig_len) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(sig_len, 4);
    let sig = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) };
    assert_eq!(sig, b"sig!");

    // Get protected header bytes
    let mut prot_ptr: *const u8 = ptr::null();
    let mut prot_len: usize = 0;
    let rc = unsafe { cose_sign1_message_protected_bytes(msg, &mut prot_ptr, &mut prot_len) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(prot_len, 3); // A1 01 26

    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_parse_valid_message_detached() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let data = minimal_cose_sign1_detached();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };

    assert_eq!(rc, COSE_SIGN1_OK, "Error: {:?}", error_message(err));
    assert!(!msg.is_null());

    // Check it's detached
    let is_detached = unsafe { cose_sign1_message_is_detached(msg) };
    assert!(is_detached);

    // Getting payload should return error
    let mut payload_ptr: *const u8 = ptr::null();
    let mut payload_len: usize = 0;
    let rc = unsafe { cose_sign1_message_payload(msg, &mut payload_ptr, &mut payload_len) };
    assert_eq!(rc, COSE_SIGN1_ERR_PAYLOAD_MISSING);

    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_parse_untagged_message() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let data = minimal_cose_sign1_untagged();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };

    assert_eq!(rc, COSE_SIGN1_OK, "Error: {:?}", error_message(err));
    assert!(!msg.is_null());

    // Should still be able to get algorithm
    let mut alg: i64 = 0;
    let rc = unsafe { cose_sign1_message_alg(msg, &mut alg) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(alg, -7);

    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_headermap_accessors() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let data = minimal_cose_sign1_with_payload();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_OK);

    // Get protected headers
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_protected_headers(msg, &mut headers) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert!(!headers.is_null());

    // Check length
    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 1);

    // Check contains
    let contains_alg = unsafe { cose_headermap_contains(headers, 1) };
    assert!(contains_alg);
    let contains_kid = unsafe { cose_headermap_contains(headers, 4) };
    assert!(!contains_kid);

    // Get algorithm value
    let mut alg_val: i64 = 0;
    let rc = unsafe { cose_headermap_get_int(headers, 1, &mut alg_val) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert_eq!(alg_val, -7);

    // Get non-existent int should return not found
    let rc = unsafe { cose_headermap_get_int(headers, 99, &mut alg_val) };
    assert_eq!(rc, COSE_SIGN1_ERR_HEADER_NOT_FOUND);

    unsafe {
        cose_headermap_free(headers);
        cose_sign1_message_free(msg);
    };
}

#[test]
fn ffi_unprotected_headers() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    let data = minimal_cose_sign1_with_payload();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_OK);

    // Get unprotected headers (should be empty in our test message)
    let mut headers: *mut CoseHeaderMapHandle = ptr::null_mut();
    let rc = unsafe { cose_sign1_message_unprotected_headers(msg, &mut headers) };
    assert_eq!(rc, COSE_SIGN1_OK);
    assert!(!headers.is_null());

    // Check length is 0
    let len = unsafe { cose_headermap_len(headers) };
    assert_eq!(len, 0);

    unsafe {
        cose_headermap_free(headers);
        cose_sign1_message_free(msg);
    };
}

#[test]
fn ffi_error_handling() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();

    // Trigger an error
    let bad_data = [0xFF];
    let rc =
        unsafe { cose_sign1_message_parse(bad_data.as_ptr(), bad_data.len(), &mut msg, &mut err) };
    assert!(rc < 0);
    assert!(!err.is_null());

    // Get error code
    let code = unsafe { cose_sign1_error_code(err) };
    assert!(code < 0);

    // Get error message
    let msg_ptr = unsafe { cose_sign1_error_message(err) };
    assert!(!msg_ptr.is_null());

    let msg_str = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(!msg_str.is_empty());

    unsafe {
        cose_sign1_string_free(msg_ptr);
        cose_sign1_error_free(err);
    };
}

#[test]
fn ffi_message_accessors_null_safety() {
    // All accessors should handle null message safely
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;
    let mut alg: i64 = 0;

    let rc = unsafe { cose_sign1_message_protected_bytes(ptr::null(), &mut ptr, &mut len) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let rc = unsafe { cose_sign1_message_signature(ptr::null(), &mut ptr, &mut len) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let rc = unsafe { cose_sign1_message_alg(ptr::null(), &mut alg) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let rc = unsafe { cose_sign1_message_payload(ptr::null(), &mut ptr, &mut len) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let is_detached = unsafe { cose_sign1_message_is_detached(ptr::null()) };
    assert!(!is_detached); // Returns false for null
}

#[test]
fn ffi_headermap_null_safety() {
    let mut val: i64 = 0;
    let mut ptr: *const u8 = ptr::null();
    let mut len: usize = 0;

    let rc = unsafe { cose_headermap_get_int(ptr::null(), 1, &mut val) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let rc = unsafe { cose_headermap_get_bytes(ptr::null(), 1, &mut ptr, &mut len) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let text = unsafe { cose_headermap_get_text(ptr::null(), 1) };
    assert!(text.is_null());

    let contains = unsafe { cose_headermap_contains(ptr::null(), 1) };
    assert!(!contains);

    let len = unsafe { cose_headermap_len(ptr::null()) };
    assert_eq!(len, 0);
}

#[test]
fn ffi_key_null_safety() {
    let mut alg: i64 = 0;

    let rc = unsafe { cose_key_algorithm(ptr::null(), &mut alg) };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);

    let key_type = unsafe { cose_key_type(ptr::null()) };
    assert!(key_type.is_null());
}

#[test]
fn ffi_verify_null_inputs() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let mut verified = false;

    // Parse a valid message first
    let data = minimal_cose_sign1_with_payload();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_OK);

    // Verify with null out_verified should fail
    let rc = unsafe {
        cose_sign1_message_verify(msg, ptr::null(), ptr::null(), 0, ptr::null_mut(), &mut err)
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_sign1_error_free(err) };
    err = ptr::null_mut();

    // Verify with null key should fail
    let rc = unsafe {
        cose_sign1_message_verify(msg, ptr::null(), ptr::null(), 0, &mut verified, &mut err)
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_sign1_error_free(err) };
    err = ptr::null_mut();

    // Verify with null message should fail
    let rc = unsafe {
        cose_sign1_message_verify(ptr::null(), ptr::null(), ptr::null(), 0, &mut verified, &mut err)
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_sign1_error_free(err) };

    unsafe { cose_sign1_message_free(msg) };
}

#[test]
fn ffi_verify_detached_null_inputs() {
    let mut msg: *mut CoseSign1MessageHandle = ptr::null_mut();
    let mut err: *mut CoseSign1ErrorHandle = ptr::null_mut();
    let mut verified = false;

    // Parse a detached message
    let data = minimal_cose_sign1_detached();
    let rc = unsafe { cose_sign1_message_parse(data.as_ptr(), data.len(), &mut msg, &mut err) };
    assert_eq!(rc, COSE_SIGN1_OK);

    // Verify detached with null payload should fail
    let rc = unsafe {
        cose_sign1_message_verify_detached(
            msg,
            ptr::null(),
            ptr::null(),
            0,
            ptr::null(),
            0,
            &mut verified,
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_sign1_error_free(err) };

    unsafe { cose_sign1_message_free(msg) };
}
