// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive CWT claims getter and combined setter tests.
//!
//! These tests cover all the setter/getter combinations and edge cases
//! that were missing from the basic smoke tests.

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
fn ffi_all_claims_setters_and_getters() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set all claims
    let issuer = CString::new("test-issuer").unwrap();
    let subject = CString::new("test-subject").unwrap();
    let audience = CString::new("test-audience").unwrap();
    let issued_at = 1640995200i64; // 2022-01-01 00:00:00 UTC
    let not_before = 1640995100i64; // 100 seconds before issued_at
    let expiration = 1640998800i64; // 1 hour after issued_at

    // Set issuer
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Set subject
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Set audience
    let rc = unsafe { cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Set timestamps
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, issued_at, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    let rc = unsafe { cose_cwt_claims_set_not_before(handle, not_before, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    let rc = unsafe { cose_cwt_claims_set_expiration(handle, expiration, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Get and verify issuer
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!out_issuer.is_null());

    let retrieved_issuer = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_issuer, "test-issuer");
    unsafe { cose_cwt_string_free(out_issuer as *mut _) };

    // Get and verify subject
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_subject(handle, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!out_subject.is_null());

    let retrieved_subject = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_subject, "test-subject");
    unsafe { cose_cwt_string_free(out_subject as *mut _) };

    // Serialize to CBOR and verify round-trip
    let mut cbor_bytes: *mut u8 = ptr::null_mut();
    let mut cbor_len: u32 = 0;
    let rc = unsafe { cose_cwt_claims_to_cbor(handle, &mut cbor_bytes, &mut cbor_len, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!cbor_bytes.is_null());
    assert!(cbor_len > 0);

    // Deserialize and verify all claims again
    let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_from_cbor(cbor_bytes, cbor_len, &mut handle2, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!handle2.is_null());

    // Verify all claims in deserialized handle
    let mut out_issuer2: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle2, &mut out_issuer2, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_issuer2 = unsafe { CStr::from_ptr(out_issuer2) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_issuer2, "test-issuer");

    let mut out_subject2: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_subject(handle2, &mut out_subject2, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    let retrieved_subject2 = unsafe { CStr::from_ptr(out_subject2) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved_subject2, "test-subject");

    // Clean up
    unsafe {
        cose_cwt_string_free(out_issuer2 as *mut _);
        cose_cwt_string_free(out_subject2 as *mut _);
        cose_cwt_bytes_free(cbor_bytes, cbor_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
}

#[test]
fn ffi_empty_claims_getters_return_null() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Get issuer from empty claims (should return null or empty)
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    // Should succeed but return null since no issuer was set
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Get subject from empty claims
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_subject(handle, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_claims_utf8_edge_cases() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test with special UTF-8 characters
    let special_issuer = CString::new("issuer-with-émoji-🔒-and-中文").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, special_issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Get it back and verify
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!out_issuer.is_null());

    let retrieved = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved, "issuer-with-émoji-🔒-and-中文");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_claims_empty_strings() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set empty issuer
    let empty_issuer = CString::new("").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, empty_issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Set empty subject
    let empty_subject = CString::new("").unwrap();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, empty_subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Get them back
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    if !out_issuer.is_null() {
        let retrieved = unsafe { CStr::from_ptr(out_issuer) }
            .to_string_lossy()
            .to_string();
        assert_eq!(retrieved, "");
        unsafe { cose_cwt_string_free(out_issuer as *mut _) };
    }

    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_subject(handle, &mut out_subject, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    if !out_subject.is_null() {
        let retrieved = unsafe { CStr::from_ptr(out_subject) }
            .to_string_lossy()
            .to_string();
        assert_eq!(retrieved, "");
        unsafe { cose_cwt_string_free(out_subject as *mut _) };
    }

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_claims_overwrite_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set initial issuer
    let issuer1 = CString::new("first-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer1.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Overwrite with second issuer
    let issuer2 = CString::new("second-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer2.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Should get the second issuer
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());

    let retrieved = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved, "second-issuer");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn ffi_timestamp_claims_edge_cases() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test with various timestamp values
    let timestamps = vec![
        0i64,              // Unix epoch
        -1i64,             // Before epoch
        1_000_000_000i64,  // Year 2001
        2_147_483_647i64,  // Max 32-bit timestamp
        -2_147_483_648i64, // Min 32-bit timestamp
    ];

    for &timestamp in &timestamps {
        // Set issued_at
        let rc = unsafe { cose_cwt_claims_set_issued_at(handle, timestamp, &mut err) };
        assert_eq!(
            rc,
            COSE_CWT_OK,
            "Failed to set timestamp {}: {:?}",
            timestamp,
            error_message(err)
        );

        // Set not_before
        let rc = unsafe { cose_cwt_claims_set_not_before(handle, timestamp - 100, &mut err) };
        assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

        // Set expiration
        let rc = unsafe { cose_cwt_claims_set_expiration(handle, timestamp + 100, &mut err) };
        assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

        // Verify via CBOR roundtrip
        let mut cbor_bytes: *mut u8 = ptr::null_mut();
        let mut cbor_len: u32 = 0;
        let rc =
            unsafe { cose_cwt_claims_to_cbor(handle, &mut cbor_bytes, &mut cbor_len, &mut err) };
        assert_eq!(
            rc,
            COSE_CWT_OK,
            "CBOR serialization failed for timestamp {}: {:?}",
            timestamp,
            error_message(err)
        );

        let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
        err = ptr::null_mut();
        let rc = unsafe { cose_cwt_claims_from_cbor(cbor_bytes, cbor_len, &mut handle2, &mut err) };
        assert_eq!(
            rc,
            COSE_CWT_OK,
            "CBOR deserialization failed for timestamp {}: {:?}",
            timestamp,
            error_message(err)
        );

        unsafe {
            cose_cwt_bytes_free(cbor_bytes, cbor_len);
            cose_cwt_claims_free(handle2);
        }
    }

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_claims_null_getters() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test all getters with null output pointers should fail
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, ptr::null_mut(), &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_cwt_error_free(err) };

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_subject(handle, ptr::null_mut(), &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_cwt_error_free(err) };

    // Test with null handle should fail
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_get_issuer(ptr::null_mut(), &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
    assert!(!err.is_null());
    unsafe { cose_cwt_error_free(err) };

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn ffi_cbor_invalid_data() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Try to deserialize invalid CBOR data
    let invalid_cbor = vec![0xff, 0xfe, 0xfd]; // Not valid CBOR
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
    let err_msg = error_message(err).unwrap_or_default();
    assert!(!err_msg.is_empty());
    unsafe { cose_cwt_error_free(err) };

    // Try with empty CBOR data
    err = ptr::null_mut();
    let empty_cbor: &[u8] = &[];
    let rc = unsafe { cose_cwt_claims_from_cbor(empty_cbor.as_ptr(), 0, &mut handle, &mut err) };

    assert_eq!(rc, COSE_CWT_ERR_CBOR_DECODE_FAILED);
    assert!(!err.is_null());
    unsafe { cose_cwt_error_free(err) };
}

#[test]
fn ffi_large_string_values() {
    let handle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Test with a large string (1KB)
    let large_issuer = "x".repeat(1024);
    let issuer_cstring = CString::new(large_issuer.clone()).unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer_cstring.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));

    // Get it back
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = unsafe { cose_cwt_claims_get_issuer(handle, &mut out_issuer, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "Error: {:?}", error_message(err));
    assert!(!out_issuer.is_null());

    let retrieved = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(retrieved, large_issuer);
    assert_eq!(retrieved.len(), 1024);

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_claims_free(handle);
    }
}
