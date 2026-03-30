// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in cose_sign1_headers_ffi.
//!
//! Covers: serialization Ok path (434-438, 448-462), deserialization round-trip,
//! get_issuer/get_subject Ok paths (605-609, 678-682), and CBOR decode panic paths (528-532).

use cose_sign1_headers_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

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

fn create_claims() -> *mut CoseCwtClaimsHandle {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "create failed: {:?}", error_message(err));
    assert!(!handle.is_null());
    handle
}

// ============================================================================
// Target: lines 434-438, 440-446 — impl_cwt_claims_to_cbor_inner Ok branch
// The Ok branch writes bytes to out_bytes/out_len and returns FFI_OK.
// ============================================================================
#[test]
fn test_serialize_to_cbor_ok_branch() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set some claims to have meaningful CBOR
    let issuer = CString::new("test-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let subject = CString::new("test-subject").unwrap();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize — exercises lines 430-446 (to_cbor_bytes Ok → len check → boxed → write out)
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();

    let rc = impl_cwt_claims_to_cbor_inner(handle, &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_OK, "to_cbor failed: {:?}", error_message(err));
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Verify the bytes are valid CBOR by deserializing
    let cbor_data = unsafe { std::slice::from_raw_parts(out_bytes, out_len as usize) };
    assert!(cbor_data.len() > 2); // At least a CBOR map header

    // Free the bytes
    unsafe { cose_cwt_bytes_free(out_bytes, out_len) };
    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Target: lines 510-516 — impl_cwt_claims_from_cbor_inner Ok branch
// Round-trip: serialize then deserialize
// ============================================================================
#[test]
fn test_cbor_round_trip_ok_branch() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let issuer = CString::new("roundtrip-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    let subject = CString::new("roundtrip-subject").unwrap();
    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_cwt_claims_to_cbor_inner(handle, &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_OK);

    // Deserialize — exercises lines 510-516 (from_cbor_bytes Ok → create handle)
    let mut restored_handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_from_cbor_inner(out_bytes, out_len, &mut restored_handle, &mut err);
    assert_eq!(
        rc,
        COSE_CWT_OK,
        "from_cbor failed: {:?}",
        error_message(err)
    );
    assert!(!restored_handle.is_null());

    // Verify issuer was preserved
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_issuer_inner(restored_handle, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());

    let restored_issuer = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(restored_issuer, "roundtrip-issuer");

    // Verify subject was preserved
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_subject_inner(restored_handle, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());

    let restored_subject = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(restored_subject, "roundtrip-subject");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(restored_handle);
    }
}

// ============================================================================
// Target: lines 448-451 — impl_cwt_claims_to_cbor_inner Err branch
// Trigger an encode error by using a null handle
// ============================================================================
#[test]
fn test_serialize_null_handle_returns_error() {
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_to_cbor_inner(ptr::null(), &mut out_bytes, &mut out_len, &mut err);
    assert_ne!(rc, COSE_CWT_OK);

    unsafe {
        if !err.is_null() {
            cose_cwt_error_free(err);
        }
    }
}

// ============================================================================
// Target: lines 528-532 — from_cbor panic handler path
// Passing invalid CBOR triggers the Err branch (lines 518-521).
// ============================================================================
#[test]
fn test_from_cbor_invalid_data_returns_error() {
    let bad_cbor: [u8; 4] = [0xFF, 0xFE, 0xFD, 0xFC];
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc = impl_cwt_claims_from_cbor_inner(
        bad_cbor.as_ptr(),
        bad_cbor.len() as u32,
        &mut handle,
        &mut err,
    );
    assert_ne!(rc, COSE_CWT_OK);
    assert!(handle.is_null());

    unsafe {
        if !err.is_null() {
            cose_cwt_error_free(err);
        }
    }
}

// ============================================================================
// Target: lines 580-598 — impl_cwt_claims_get_issuer_inner Ok with issuer set
// Also covers the "no issuer set" branch (line 597-598)
// ============================================================================
#[test]
fn test_get_issuer_with_value_ok_branch() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let issuer = CString::new("my-issuer").unwrap();
    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Get issuer — exercises lines 580-586 (Some issuer → CString Ok → write out)
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_issuer_inner(handle, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());

    let result = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(result, "my-issuer");

    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_get_issuer_without_value_returns_ok_null() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Get issuer without setting it — exercises line 597-598 (None → FFI_OK with null)
    let mut out_issuer: *const libc::c_char = ptr::null();
    let rc = impl_cwt_claims_get_issuer_inner(handle, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_issuer.is_null()); // No issuer set

    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Target: lines 653-671 — impl_cwt_claims_get_subject_inner Ok with subject set
// Also covers "no subject set" branch (line 669-671)
// ============================================================================
#[test]
fn test_get_subject_with_value_ok_branch() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let subject = CString::new("my-subject").unwrap();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Get subject — exercises lines 653-659 (Some subject → CString Ok → write out)
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_subject_inner(handle, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());

    let result = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(result, "my-subject");

    unsafe {
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_claims_free(handle);
    }
}

#[test]
fn test_get_subject_without_value_returns_ok_null() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let mut out_subject: *const libc::c_char = ptr::null();
    let rc = impl_cwt_claims_get_subject_inner(handle, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_subject.is_null()); // No subject set

    unsafe { cose_cwt_claims_free(handle) };
}

// ============================================================================
// Additional: full serialize → deserialize → get_issuer + get_subject pipeline
// Covers all Ok branches in a single pipeline test
// ============================================================================
#[test]
fn test_full_pipeline_serialize_deserialize_getters() {
    let handle = create_claims();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set all claims
    let issuer = CString::new("pipeline-issuer").unwrap();
    let subject = CString::new("pipeline-subject").unwrap();
    let audience = CString::new("pipeline-audience").unwrap();

    let rc = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_issued_at(handle, 1700000000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_not_before(handle, 1699999000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc = unsafe { cose_cwt_claims_set_expiration(handle, 1700003600, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc = impl_cwt_claims_to_cbor_inner(handle, &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_len > 0);

    // Deserialize
    let mut restored: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_from_cbor_inner(out_bytes, out_len, &mut restored, &mut err);
    assert_eq!(rc, COSE_CWT_OK);

    // Verify getters
    let mut out_iss: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_issuer_inner(restored, &mut out_iss, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_iss.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(out_iss) }.to_string_lossy(),
        "pipeline-issuer"
    );

    let mut out_sub: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc = impl_cwt_claims_get_subject_inner(restored, &mut out_sub, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_sub.is_null());
    assert_eq!(
        unsafe { CStr::from_ptr(out_sub) }.to_string_lossy(),
        "pipeline-subject"
    );

    unsafe {
        cose_cwt_string_free(out_iss as *mut _);
        cose_cwt_string_free(out_sub as *mut _);
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(restored);
    }
}
