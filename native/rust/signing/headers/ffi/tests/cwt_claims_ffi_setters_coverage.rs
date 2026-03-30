// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive FFI coverage tests for CWT claims setters and error handling.
//!
//! These tests target uncovered FFI functions and error paths to improve
//! coverage in headers_ffi lib.rs

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

/// Helper to create a claims handle for testing.
fn create_claims_handle() -> *mut CoseCwtClaimsHandle {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!handle.is_null());
    assert!(err.is_null());

    handle
}

#[test]
fn ffi_abi_version() {
    let version = unsafe { cose_cwt_claims_abi_version() };
    assert_eq!(version, 1);
}

#[test]
fn ffi_create_with_null_out_handle() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_create(ptr::null_mut(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let error_msg = error_message(err);
    assert!(error_msg.is_some());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_create_with_null_error_handle() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_create(&mut handle, ptr::null_mut()) };

    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_issuer_with_null_handle() {
    let issuer = CString::new("test").unwrap();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_issuer(ptr::null_mut(), issuer.as_ptr(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let error_msg = error_message(err);
    assert!(error_msg.is_some());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_issuer_with_null_string() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_issuer(handle, ptr::null(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    let error_msg = error_message(err);
    assert!(error_msg.is_some());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_set_subject_with_null_handle() {
    let subject = CString::new("test").unwrap();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_subject(ptr::null_mut(), subject.as_ptr(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_subject_with_null_string() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_subject(handle, ptr::null(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_set_audience_with_null_handle() {
    let audience = CString::new("test").unwrap();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_audience(ptr::null_mut(), audience.as_ptr(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_audience_with_null_string() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_audience(handle, ptr::null(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_set_issued_at_with_null_handle() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_issued_at(ptr::null_mut(), 1000, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_not_before_with_null_handle() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_not_before(ptr::null_mut(), 1000, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_expiration_with_null_handle() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_set_expiration(ptr::null_mut(), 1000, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_set_timestamp_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test positive timestamps
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 1640995200, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, 1640995100, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, 1672531200, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_negative_timestamp_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test negative timestamps (should be valid)
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, -1000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, -2000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, -500, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_zero_timestamp_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test zero timestamps (epoch)
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 0, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, 0, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, 0, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_max_timestamp_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test maximum timestamp values
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, i64::MAX, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, i64::MAX, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, i64::MAX, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_min_timestamp_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test minimum timestamp values
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, i64::MIN, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, i64::MIN, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, i64::MIN, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_empty_string_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let empty_string = CString::new("").unwrap();

    let rc = unsafe { cose_cwt_claims_set_issuer(handle, empty_string.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_subject(handle, empty_string.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_audience(handle, empty_string.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_set_unicode_string_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let unicode_issuer = CString::new("🏢 Unicode Issuer 中文").unwrap();
    let unicode_subject = CString::new("👤 Unicode Subject العربية").unwrap();
    let unicode_audience = CString::new("🎯 Unicode Audience русский").unwrap();

    let rc = unsafe { cose_cwt_claims_set_issuer(handle, unicode_issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_subject(handle, unicode_subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    let rc = unsafe { cose_cwt_claims_set_audience(handle, unicode_audience.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(err.is_null());

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_to_cbor_with_null_handle() {
    let mut cbor_bytes: *mut u8 = ptr::null_mut();
    let mut cbor_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_cwt_claims_to_cbor(ptr::null_mut(), &mut cbor_bytes, &mut cbor_len, &mut err)
    };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_to_cbor_with_null_out_bytes() {
    let handle = create_claims_handle();
    let mut cbor_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_to_cbor(handle, ptr::null_mut(), &mut cbor_len, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_to_cbor_with_null_out_len() {
    let handle = create_claims_handle();
    let mut cbor_bytes: *mut u8 = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_to_cbor(handle, &mut cbor_bytes, ptr::null_mut(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_from_cbor_with_null_data() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_from_cbor(ptr::null(), 10, &mut handle, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_from_cbor_with_null_out_handle() {
    let cbor_data = vec![0xA0]; // Empty CBOR map
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_cwt_claims_from_cbor(
            cbor_data.as_ptr(),
            cbor_data.len() as u32,
            ptr::null_mut(),
            &mut err,
        )
    };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_from_cbor_with_invalid_data() {
    let invalid_cbor = vec![0xFF, 0xFF, 0xFF]; // Invalid CBOR
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe {
        cose_cwt_claims_from_cbor(
            invalid_cbor.as_ptr(),
            invalid_cbor.len() as u32,
            &mut handle,
            &mut err,
        )
    };

    assert_eq!(rc, COSE_CWT_ERR_CBOR_DECODE_FAILED);
    assert!(!err.is_null());

    let error_msg = error_message(err);
    assert!(error_msg.is_some());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_get_issuer_with_null_handle() {
    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_get_issuer(ptr::null_mut(), &mut out_issuer, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_get_issuer_with_null_out_string() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_get_issuer(handle, ptr::null_mut(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_get_subject_with_null_handle() {
    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_get_subject(ptr::null_mut(), &mut out_subject, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_get_subject_with_null_out_string() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = unsafe { cose_cwt_claims_get_subject(handle, ptr::null_mut(), &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());

    unsafe {
        cose_cwt_error_free(err);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_free_null_handle() {
    // Should not crash
    unsafe { cose_cwt_claims_free(ptr::null_mut()) };
}

#[test]
fn ffi_free_bytes_with_null_ptr() {
    // Should not crash
    unsafe { cose_cwt_bytes_free(ptr::null_mut(), 0) };
}

#[test]
fn ffi_overwrite_existing_claims() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set initial values
    let initial_issuer = CString::new("initial-issuer").unwrap();
    let initial_subject = CString::new("initial-subject").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, initial_issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_subject(handle, initial_subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 1000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Overwrite with new values
    let new_issuer = CString::new("new-issuer").unwrap();
    let new_subject = CString::new("new-subject").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, new_issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_subject(handle, new_subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 2000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Verify new values are set
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_issuer = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_issuer, "new-issuer");

    let mut out_subject: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_subject(handle, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_subject = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_subject, "new-subject");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_claims_free(handle);
    };
}

#[test]
fn ffi_complete_round_trip_all_claims() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set all available claims
    let issuer = CString::new("roundtrip-issuer").unwrap();
    let subject = CString::new("roundtrip-subject").unwrap();
    let audience = CString::new("roundtrip-audience").unwrap();

    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 1640995200, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, 1640995100, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, 1672531200, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize to CBOR
    let mut cbor_bytes: *mut u8 = ptr::null_mut();
    let mut cbor_len: u32 = 0;
    let rc = unsafe { cose_cwt_claims_to_cbor(handle, &mut cbor_bytes, &mut cbor_len, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!cbor_bytes.is_null());
    assert!(cbor_len > 0);

    // Deserialize from CBOR
    let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_from_cbor(cbor_bytes, cbor_len, &mut handle2, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle2.is_null());

    // Verify all claims match
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle2, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_issuer = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_issuer, "roundtrip-issuer");

    let mut out_subject: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_subject(handle2, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_subject = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_subject, "roundtrip-subject");

    // Clean up
    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_bytes_free(cbor_bytes, cbor_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    };
}
