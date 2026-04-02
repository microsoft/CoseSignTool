// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to extract and free an error message string.
fn take_error_message(err: *const DidX509ErrorHandle) -> Option<String> {
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

// A valid DID with a 43-char base64url SHA-256 fingerprint.
const VALID_DID: &str =
    "did:x509:0:sha256:WE4P5dd8DnLHSkyHaIjhp4udlkSomeFakeBase64url::eku:1.3.6.1.5.5.7.3.3";

#[test]
fn abi_version() {
    assert_eq!(did_x509_abi_version(), 1);
}

#[test]
fn parse_with_null_did_string_returns_error() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parse_inner(ptr::null(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    assert!(handle.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn parse_with_null_out_handle_returns_error() {
    let did = CString::new(VALID_DID).unwrap();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parse_inner(did.as_ptr(), ptr::null_mut(), &mut err);
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn parse_empty_string_returns_parse_error() {
    let did = CString::new("").unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_ERR_PARSE_FAILED);
    assert!(handle.is_null());
    if !err.is_null() {
        let msg = take_error_message(err as *const _);
        assert!(msg.is_some());
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn parse_valid_did_and_query_fields() {
    let did = CString::new(VALID_DID).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_OK);
    assert!(!handle.is_null());

    // Get fingerprint
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut err2: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parsed_get_fingerprint_inner(handle as *const _, &mut fingerprint, &mut err2);
    assert_eq!(rc, DID_X509_OK);
    assert!(!fingerprint.is_null());
    let fp_str = unsafe { CStr::from_ptr(fingerprint) }.to_string_lossy();
    assert!(!fp_str.is_empty());
    unsafe { did_x509_string_free(fingerprint) };

    // Get hash algorithm
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut err3: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parsed_get_hash_algorithm_inner(handle as *const _, &mut algorithm, &mut err3);
    assert_eq!(rc, DID_X509_OK);
    let alg_str = unsafe { CStr::from_ptr(algorithm) }.to_string_lossy();
    assert_eq!(alg_str, "sha256");
    unsafe { did_x509_string_free(algorithm) };

    // Get policy count
    let mut count: u32 = 0;
    let rc = impl_parsed_get_policy_count_inner(handle as *const _, &mut count);
    assert_eq!(rc, DID_X509_OK);
    assert!(count >= 1);

    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn free_null_handle_does_not_crash() {
    unsafe {
        did_x509_parsed_free(ptr::null_mut());
        did_x509_error_free(ptr::null_mut());
        did_x509_string_free(ptr::null_mut());
    }
}

#[test]
fn build_with_eku_null_cert_returns_error() {
    let oid = CString::new("1.2.3.4").unwrap();
    let oid_ptr: *const libc::c_char = oid.as_ptr();
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Null cert with non-zero length
    let rc = impl_build_with_eku_inner(ptr::null(), 10, &oid_ptr, 1, &mut out_did, &mut err);
    assert_ne!(rc, DID_X509_OK);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn validate_with_null_did_returns_error() {
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let dummy_cert: [u8; 1] = [0];
    let cert_ptr: *const u8 = dummy_cert.as_ptr();
    let cert_len: u32 = 1;

    let rc = impl_validate_inner(
        ptr::null(),
        &cert_ptr as *const *const u8,
        &cert_len,
        1,
        &mut is_valid,
        &mut err,
    );
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn resolve_with_null_did_returns_error() {
    let mut out_json: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let dummy_cert: [u8; 1] = [0];
    let cert_ptr: *const u8 = dummy_cert.as_ptr();
    let cert_len: u32 = 1;

    let rc = impl_resolve_inner(
        ptr::null(),
        &cert_ptr as *const *const u8,
        &cert_len,
        1,
        &mut out_json,
        &mut err,
    );
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn error_message_for_null_handle_returns_null() {
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null());
}

#[test]
fn error_code_for_null_handle_returns_zero() {
    let code = unsafe { did_x509_error_code(ptr::null()) };
    assert_eq!(code, 0);
}
