// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for cose_sign1_headers_ffi.
//!
//! These tests verify the C calling convention compatibility and CWT claims roundtrip.

use cose_sign1_headers_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to get error message from an error handle.
fn error_message(err: *const CoseCwtErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { cose_cwt_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    unsafe { cose_cwt_string_free(msg) };
    Some(s)
}

#[test]
fn ffi_abi_version() {
    let version = cose_cwt_claims_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_null_free_is_safe() {
    // All free functions should handle null safely
    unsafe {
        cose_cwt_claims_free(ptr::null_mut());
        cose_cwt_error_free(ptr::null_mut());
        cose_cwt_string_free(ptr::null_mut());
        cose_cwt_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn ffi_claims_create_null_inputs() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Null out_handle should fail
    let rc = unsafe { cose_cwt_claims_create(ptr::null_mut(), &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("Failed to create"));
    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_claims_create_and_free() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!handle.is_null());
    assert!(err.is_null());

    // Free claims
    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_claims_set_issuer_roundtrip() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle.is_null());

    // Set issuer
    let issuer = CString::new("test-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(err.is_null());

    // Get issuer back
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!out_issuer.is_null());
    assert!(err.is_null());

    let retrieved = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved, "test-issuer");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_claims_to_cbor_from_cbor_roundtrip() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create claims and set issuer
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let issuer = CString::new("test-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let subject = CString::new("test-subject").unwrap();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 1234567890, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize to CBOR
    let mut cbor_bytes: *mut u8 = ptr::null_mut();
    let mut cbor_len: u32 = 0;
    let rc = unsafe { cose_cwt_claims_to_cbor(handle, &mut cbor_bytes, &mut cbor_len, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!cbor_bytes.is_null());
    assert!(cbor_len > 0);

    // Deserialize from CBOR
    let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_from_cbor(cbor_bytes, cbor_len, &mut handle2, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!handle2.is_null());

    // Verify issuer
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle2, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());

    let retrieved = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved, "test-issuer");

    // Verify subject
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_subject(handle2, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());

    let retrieved_subject = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_subject, "test-subject");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_bytes_free(cbor_bytes, cbor_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
}

#[test]
fn ffi_claims_null_pointer_safety() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let issuer = CString::new("test").unwrap();

    // Set issuer with null handle should fail
    let rc = unsafe { cose_cwt_claims_set_issuer(ptr::null_mut(), issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_cwt_error_free(err) };

    // Set issuer with null issuer should fail
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, ptr::null(), &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_error_handling() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Trigger an error with null handle
    let rc = unsafe { cose_cwt_claims_create(ptr::null_mut(), &mut err) };
    assert!(rc < 0);
    assert!(!err.is_null());

    // Get error code
    let code = unsafe { cose_cwt_error_code(err) };
    assert!(code < 0);

    // Get error message
    let msg_ptr = unsafe { cose_cwt_error_message(err) };
    assert!(!msg_ptr.is_null());

    let msg_str = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(!msg_str.is_empty());

    unsafe {
        cose_cwt_string_free(msg_ptr);
        cose_cwt_error_free(err);
    };
}

#[test]
fn ffi_cwt_claims_all_setters() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle.is_null());

    unsafe {
        // Test all setter functions
        let issuer = CString::new("https://issuer.example.com").unwrap();
        let subject = CString::new("user@example.com").unwrap();
        let audience = CString::new("https://audience.example.com").unwrap();

        // Set issuer
        let rc = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Set subject
        let rc = cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Set audience
        let rc = cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Set expiration time
        let rc = cose_cwt_claims_set_expiration(handle, 1234567890, &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Set not before time
        let rc = cose_cwt_claims_set_not_before(handle, 1234567800, &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Set issued at time
        let rc = cose_cwt_claims_set_issued_at(handle, 1234567850, &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_cwt_claims_serialization() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create and populate claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    unsafe {
        let issuer = CString::new("test-issuer").unwrap();
        let rc = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Serialize to CBOR
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let rc = cose_cwt_claims_to_cbor(handle, &mut out_bytes, &mut out_len, &mut err);
        assert_eq!(rc, COSE_CWT_OK);
        assert!(!out_bytes.is_null());
        assert!(out_len > 0);

        // Clean up
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_cwt_claims_roundtrip() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create and populate claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    unsafe {
        let issuer = CString::new("test-issuer").unwrap();
        let rc = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Serialize to CBOR
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let rc = cose_cwt_claims_to_cbor(handle, &mut out_bytes, &mut out_len, &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Deserialize from CBOR
        let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
        let rc = cose_cwt_claims_from_cbor(out_bytes, out_len, &mut handle2, &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Verify issuer is preserved
        let mut issuer_out: *const libc::c_char = ptr::null();
        let rc = cose_cwt_claims_get_issuer(handle2, &mut issuer_out, &mut err);
        assert_eq!(rc, COSE_CWT_OK);
        assert!(!issuer_out.is_null());

        let issuer_str = CStr::from_ptr(issuer_out).to_string_lossy();
        assert_eq!(issuer_str, "test-issuer");

        // Clean up
        cose_cwt_string_free(issuer_out as *mut _);
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
}

#[test]
fn ffi_cwt_claims_getters() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    unsafe {
        // Set issuer and subject
        let issuer = CString::new("test-issuer").unwrap();
        let subject = CString::new("test-subject").unwrap();

        let rc = cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        let rc = cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err);
        assert_eq!(rc, COSE_CWT_OK);

        // Get issuer
        let mut issuer_out: *const libc::c_char = ptr::null();
        let rc = cose_cwt_claims_get_issuer(handle, &mut issuer_out, &mut err);
        assert_eq!(rc, COSE_CWT_OK);
        assert!(!issuer_out.is_null());

        let issuer_str = CStr::from_ptr(issuer_out).to_string_lossy();
        assert_eq!(issuer_str, "test-issuer");
        cose_cwt_string_free(issuer_out as *mut _);

        // Get subject
        let mut subject_out: *const libc::c_char = ptr::null();
        let rc = cose_cwt_claims_get_subject(handle, &mut subject_out, &mut err);
        assert_eq!(rc, COSE_CWT_OK);
        assert!(!subject_out.is_null());

        let subject_str = CStr::from_ptr(subject_out).to_string_lossy();
        assert_eq!(subject_str, "test-subject");
        cose_cwt_string_free(subject_out as *mut _);

        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_cwt_claims_null_getter_inputs() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Create empty claims
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    unsafe {
        // Test null output pointer
        let rc = cose_cwt_claims_get_issuer(handle, ptr::null_mut(), &mut err);
        assert!(rc < 0);

        // Test null handle
        let mut issuer_out: *const libc::c_char = ptr::null();
        let rc = cose_cwt_claims_get_issuer(ptr::null(), &mut issuer_out, &mut err);
        assert!(rc < 0);

        // Test get on empty claims (should return null in output pointer)
        let rc = cose_cwt_claims_get_issuer(handle, &mut issuer_out, &mut err);
        assert_eq!(rc, COSE_CWT_OK);
        assert!(issuer_out.is_null());

        cose_cwt_claims_free(handle);
    }
}
