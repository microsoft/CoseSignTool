// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_headers_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to extract and free an error message string.
fn take_error_message(err: *const CoseCwtErrorHandle) -> Option<String> {
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
fn abi_version_check() {
    assert_eq!(cose_cwt_claims_abi_version(), 1);
}

#[test]
fn create_with_null_out_handle_returns_null_pointer_error() {
    let rc = impl_cwt_claims_create_inner(ptr::null_mut());
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
}

#[test]
fn set_issuer_with_null_handle_returns_error() {
    let issuer = CString::new("test").unwrap();
    let rc = impl_cwt_claims_set_issuer_inner(ptr::null_mut(), issuer.as_ptr());
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);
}

#[test]
fn set_issuer_with_null_string_returns_error() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let rc = impl_cwt_claims_create_inner(&mut handle);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle.is_null());

    let rc = impl_cwt_claims_set_issuer_inner(handle, ptr::null());
    assert_eq!(rc, COSE_CWT_ERR_NULL_POINTER);

    unsafe { cose_cwt_claims_free(handle) };
}

#[test]
fn full_lifecycle_create_set_serialize_deserialize_free() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    assert_eq!(impl_cwt_claims_create_inner(&mut handle), COSE_CWT_OK);

    let issuer = CString::new("my-issuer").unwrap();
    assert_eq!(impl_cwt_claims_set_issuer_inner(handle, issuer.as_ptr()), COSE_CWT_OK);

    let subject = CString::new("my-subject").unwrap();
    assert_eq!(impl_cwt_claims_set_subject_inner(handle, subject.as_ptr()), COSE_CWT_OK);

    let audience = CString::new("my-audience").unwrap();
    assert_eq!(impl_cwt_claims_set_audience_inner(handle, audience.as_ptr()), COSE_CWT_OK);

    // Serialize to CBOR
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_to_cbor_inner(handle as *const _, &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Deserialize back
    let mut handle2: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err2: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_from_cbor_inner(out_bytes, out_len, &mut handle2, &mut err2);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!handle2.is_null());

    unsafe {
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(handle2);
    }
}

#[test]
fn from_cbor_with_invalid_data_returns_error() {
    let garbage: [u8; 3] = [0xFF, 0xFE, 0xFD];
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc = impl_cwt_claims_from_cbor_inner(garbage.as_ptr(), 3, &mut handle, &mut err);
    assert_ne!(rc, COSE_CWT_OK);
    assert!(handle.is_null());
    if !err.is_null() {
        let msg = take_error_message(err as *const _);
        assert!(msg.is_some());
        unsafe { cose_cwt_error_free(err) };
    }
}

#[test]
fn free_null_handle_does_not_crash() {
    unsafe {
        cose_cwt_claims_free(ptr::null_mut());
        cose_cwt_error_free(ptr::null_mut());
        cose_cwt_string_free(ptr::null_mut());
    }
}

#[test]
fn error_message_for_null_handle_returns_null() {
    let msg = unsafe { cose_cwt_error_message(ptr::null()) };
    assert!(msg.is_null());
}
