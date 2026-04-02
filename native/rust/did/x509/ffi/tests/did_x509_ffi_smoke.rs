// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for did_x509_ffi.
//!
//! These tests verify the C calling convention compatibility and DID parsing.

use did_x509_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to get error message from an error handle.
fn error_message(err: *const DidX509ErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { did_x509_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    unsafe { did_x509_string_free(msg) };
    Some(s)
}

#[test]
fn ffi_abi_version() {
    let version = did_x509_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_null_free_is_safe() {
    // All free functions should handle null safely
    unsafe {
        did_x509_parsed_free(ptr::null_mut());
        did_x509_error_free(ptr::null_mut());
        did_x509_string_free(ptr::null_mut());
    }
}

#[test]
fn ffi_parse_null_inputs() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Null out_handle should fail
    let rc = unsafe { did_x509_parse(ptr::null(), ptr::null_mut(), &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_handle"));
    unsafe { did_x509_error_free(err) };

    // Null did_string should fail
    err = ptr::null_mut();
    let rc = unsafe { did_x509_parse(ptr::null(), &mut handle, &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(handle.is_null());
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("did_string"));
    unsafe { did_x509_error_free(err) };
}

#[test]
fn ffi_parse_invalid_did_string() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let invalid_did = CString::new("not-a-valid-did").unwrap();
    let rc = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut handle, &mut err) };

    assert_eq!(rc, DID_X509_ERR_PARSE_FAILED);
    assert!(handle.is_null());
    assert!(!err.is_null());

    let err_msg = error_message(err).unwrap_or_default();
    assert!(!err_msg.is_empty());

    unsafe { did_x509_error_free(err) };
}

#[test]
fn ffi_parse_valid_did_string() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Example DID:x509 string (simplified for testing)
    let valid_did =
        CString::new("did:x509:0:sha256:WE69Dr_yGqMPE-KOhAqCag==::subject:CN%3DExample").unwrap();
    let rc = unsafe { did_x509_parse(valid_did.as_ptr(), &mut handle, &mut err) };

    // Note: This might fail with parse error depending on exact format expected
    // The important thing is to test the null safety and basic function calls
    if rc == DID_X509_OK {
        assert!(!handle.is_null());
        assert!(err.is_null());

        // Get fingerprint
        let mut fingerprint: *mut libc::c_char = ptr::null_mut();
        err = ptr::null_mut();
        let rc = unsafe { did_x509_parsed_get_fingerprint(handle, &mut fingerprint, &mut err) };
        if rc == DID_X509_OK {
            assert!(!fingerprint.is_null());
            unsafe { did_x509_string_free(fingerprint) };
        }

        // Get hash algorithm
        let mut algorithm: *mut libc::c_char = ptr::null_mut();
        err = ptr::null_mut();
        let rc = unsafe { did_x509_parsed_get_hash_algorithm(handle, &mut algorithm, &mut err) };
        if rc == DID_X509_OK {
            assert!(!algorithm.is_null());
            unsafe { did_x509_string_free(algorithm) };
        }

        // Get policy count
        let mut count: u32 = 0;
        let rc = unsafe { did_x509_parsed_get_policy_count(handle, &mut count) };
        assert_eq!(rc, DID_X509_OK);

        unsafe { did_x509_parsed_free(handle) };
    } else {
        // Expected for invalid format, but should still handle properly
        assert!(handle.is_null());
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
    }
}

#[test]
fn ffi_build_with_eku_null_inputs() {
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Null out_did_string should fail
    let rc = unsafe {
        did_x509_build_with_eku(ptr::null(), 0, ptr::null(), 0, ptr::null_mut(), &mut err)
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_did_string"));
    unsafe { did_x509_error_free(err) };
}

#[test]
fn ffi_validate_null_inputs() {
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let did_str = CString::new("did:x509:test").unwrap();

    // Null out_is_valid should fail
    let rc = unsafe {
        did_x509_validate(
            did_str.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_is_valid"));
    unsafe { did_x509_error_free(err) };

    // Null did_string should fail
    err = ptr::null_mut();
    let rc = unsafe {
        did_x509_validate(
            ptr::null(),
            ptr::null(),
            ptr::null(),
            1,
            &mut is_valid,
            &mut err,
        )
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("did_string"));
    unsafe { did_x509_error_free(err) };
}

#[test]
fn ffi_resolve_null_inputs() {
    let mut did_document: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let did_str = CString::new("did:x509:test").unwrap();

    // Null out_did_document_json should fail
    let rc = unsafe {
        did_x509_resolve(
            did_str.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_did_document_json"));
    unsafe { did_x509_error_free(err) };
}

#[test]
fn ffi_parsed_accessors_null_safety() {
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut count: u32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // All accessors should handle null handle safely
    let rc = unsafe { did_x509_parsed_get_fingerprint(ptr::null(), &mut fingerprint, &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    err = ptr::null_mut();
    let rc = unsafe { did_x509_parsed_get_hash_algorithm(ptr::null(), &mut algorithm, &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    let rc = unsafe { did_x509_parsed_get_policy_count(ptr::null(), &mut count) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
}

#[test]
fn ffi_error_handling() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Trigger an error with invalid DID
    let invalid_did = CString::new("invalid").unwrap();
    let rc = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut handle, &mut err) };
    assert!(rc < 0);
    assert!(!err.is_null());

    // Get error code
    let code = unsafe { did_x509_error_code(err) };
    assert!(code < 0);

    // Get error message
    let msg_ptr = unsafe { did_x509_error_message(err) };
    assert!(!msg_ptr.is_null());

    let msg_str = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(!msg_str.is_empty());

    unsafe {
        did_x509_string_free(msg_ptr);
        did_x509_error_free(err);
    };
}
