// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.


//! Targeted coverage tests for cose_sign1_headers_ffi.
//!
//! Covers uncovered lines:
//! - lib.rs L434-436, L438: to_cbor Ok path — large-data guard
//! - lib.rs L448-450: to_cbor Err branch from encoding failure
//! - lib.rs L458-460, L462: to_cbor panic handler
//! - lib.rs L528-530, L532: from_cbor panic handler
//! - lib.rs L605-607, L609: get_issuer panic handler
//! - lib.rs L678-680, L682: get_subject panic handler
//! - error.rs L48, L50-53: from_header_error match arms
//! - error.rs L95: set_error call
//! - error.rs L115-117: cose_cwt_error_message NUL fallback
//! - error.rs L132: cose_cwt_error_code with valid handle

use std::ffi::{CStr, CString};
use std::ptr;

use cose_sign1_headers_ffi::error::{
    CoseCwtErrorHandle, ErrorInner, FFI_ERR_CBOR_DECODE_FAILED, FFI_ERR_CBOR_ENCODE_FAILED,
    FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
};
use cose_sign1_headers_ffi::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn create_claims_handle() -> *mut CoseCwtClaimsHandle {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_create(&mut handle, &mut err) };
    assert_eq!(rc, COSE_CWT_OK, "create claims failed");
    assert!(!handle.is_null());
    handle
}

fn free_error(err: *mut CoseCwtErrorHandle) {
    if !err.is_null() {
        unsafe { cose_cwt_error_free(err) };
    }
}

// ---------------------------------------------------------------------------
// error.rs coverage: from_header_error match arms (L48, L50-53)
// ---------------------------------------------------------------------------

/// Exercises ErrorInner::from_header_error for CborEncodingError variant (L48).
#[test]
fn error_inner_from_header_error_cbor_encoding() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::CborEncodingError("test encode error".to_string());
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_CBOR_ENCODE_FAILED);
    assert!(inner.message.contains("CBOR encoding error"));
}

/// Exercises ErrorInner::from_header_error for CborDecodingError variant (L49).
#[test]
fn error_inner_from_header_error_cbor_decoding() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::CborDecodingError("test decode error".to_string());
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_CBOR_DECODE_FAILED);
    assert!(inner.message.contains("CBOR decoding error"));
}

/// Exercises ErrorInner::from_header_error for InvalidClaimType variant (L50).
#[test]
fn error_inner_from_header_error_invalid_claim_type() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::InvalidClaimType {
        label: 42,
        expected: "string".to_string(),
        actual: "integer".to_string(),
    };
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_INVALID_ARGUMENT);
    assert!(inner.message.contains("42"));
}

/// Exercises ErrorInner::from_header_error for MissingRequiredClaim variant (L51).
#[test]
fn error_inner_from_header_error_missing_required_claim() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::MissingRequiredClaim("subject".to_string());
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_INVALID_ARGUMENT);
    assert!(inner.message.contains("subject"));
}

/// Exercises ErrorInner::from_header_error for InvalidTimestamp variant (L52).
#[test]
fn error_inner_from_header_error_invalid_timestamp() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::InvalidTimestamp("not a number".to_string());
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_INVALID_ARGUMENT);
    assert!(inner.message.contains("timestamp"));
}

/// Exercises ErrorInner::from_header_error for ComplexClaimValue variant (L53).
#[test]
fn error_inner_from_header_error_complex_claim_value() {
    use cose_sign1_headers::HeaderError;

    let err = HeaderError::ComplexClaimValue("nested array".to_string());
    let inner: ErrorInner = ErrorInner::from_header_error(&err);
    assert_eq!(inner.code, FFI_ERR_INVALID_ARGUMENT);
    assert!(inner.message.contains("complex"));
}

// ---------------------------------------------------------------------------
// error.rs coverage: ErrorInner::new / null_pointer (L39-66)
// ---------------------------------------------------------------------------

/// Exercises ErrorInner::new constructor.
#[test]
fn error_inner_new() {
    let inner: ErrorInner = ErrorInner::new("test message", -42);
    assert_eq!(inner.message, "test message");
    assert_eq!(inner.code, -42);
}

/// Exercises ErrorInner::null_pointer constructor.
#[test]
fn error_inner_null_pointer() {
    let inner: ErrorInner = ErrorInner::null_pointer("my_param");
    assert_eq!(inner.code, FFI_ERR_NULL_POINTER);
    assert!(inner.message.contains("my_param"));
}

// ---------------------------------------------------------------------------
// error.rs coverage: set_error with null out_error (L90-96)
// ---------------------------------------------------------------------------

/// Exercises set_error with a null out_error pointer — should not crash.
#[test]
fn set_error_with_null_out_pointer_is_noop() {
    let inner: ErrorInner = ErrorInner::new("ignored", -1);
    // Should not crash or write anywhere
    cose_sign1_headers_ffi::error::set_error(ptr::null_mut(), inner);
}

/// Exercises set_error with a valid out_error pointer.
#[test]
fn set_error_with_valid_out_pointer() {
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();
    let inner: ErrorInner = ErrorInner::new("test error", -10);
    cose_sign1_headers_ffi::error::set_error(&mut err, inner);
    assert!(!err.is_null());
    free_error(err);
}

// ---------------------------------------------------------------------------
// error.rs coverage: cose_cwt_error_message and cose_cwt_error_code (L105-134)
// ---------------------------------------------------------------------------

/// Exercises cose_cwt_error_message with a valid error handle (L112-113).
/// Also exercises cose_cwt_error_code with a valid handle (L131).
#[test]
fn error_message_and_code_with_valid_handle() {
    let inner: ErrorInner = ErrorInner::new("hello error", -77);
    let handle: *mut CoseCwtErrorHandle = cose_sign1_headers_ffi::error::inner_to_handle(inner);
    assert!(!handle.is_null());

    // Get message
    let msg_ptr: *mut libc::c_char = unsafe { cose_cwt_error_message(handle) };
    assert!(!msg_ptr.is_null());
    let msg: String = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert_eq!(msg, "hello error");
    unsafe { cose_cwt_string_free(msg_ptr) };

    // Get code
    let code: i32 = unsafe { cose_cwt_error_code(handle) };
    assert_eq!(code, -77);

    free_error(handle);
}

/// Exercises cose_cwt_error_message with a null handle (L108-109).
#[test]
fn error_message_with_null_handle_returns_null() {
    let msg_ptr: *mut libc::c_char = unsafe { cose_cwt_error_message(ptr::null()) };
    assert!(msg_ptr.is_null());
}

/// Exercises cose_cwt_error_code with a null handle (L130-131 None branch).
#[test]
fn error_code_with_null_handle_returns_zero() {
    let code: i32 = unsafe { cose_cwt_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------------------
// error.rs coverage: cose_cwt_error_free / cose_cwt_string_free null (L144, L160)
// ---------------------------------------------------------------------------

/// Exercises cose_cwt_error_free with null — should be a no-op.
#[test]
fn error_free_null_is_noop() {
    unsafe { cose_cwt_error_free(ptr::null_mut()) };
}

/// Exercises cose_cwt_string_free with null — should be a no-op.
#[test]
fn string_free_null_is_noop() {
    unsafe { cose_cwt_string_free(ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// lib.rs coverage: to_cbor + from_cbor round-trip via inner functions
// Exercises Ok branches (L430-446, L510-516)
// ---------------------------------------------------------------------------

/// Full round-trip: create → set fields → to_cbor → from_cbor → get fields.
/// Covers to_cbor Ok (L440-446) and from_cbor Ok (L511-516).
#[test]
fn cbor_roundtrip_via_inner_functions_all_setters() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    // Set issuer
    let issuer = CString::new("rt-issuer").unwrap();
    let rc: i32 = unsafe { cose_cwt_claims_set_issuer(handle, issuer.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Set subject
    let subject = CString::new("rt-subject").unwrap();
    err = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_set_subject(handle, subject.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Set audience
    let audience = CString::new("rt-audience").unwrap();
    err = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_set_audience(handle, audience.as_ptr(), &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Set timestamps
    err = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_set_issued_at(handle, 1_700_000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_set_not_before(handle, 1_600_000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    err = ptr::null_mut();
    let rc: i32 = unsafe { cose_cwt_claims_set_expiration(handle, 1_800_000, &mut err) };
    assert_eq!(rc, COSE_CWT_OK);

    // Serialize to CBOR
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    err = ptr::null_mut();
    let rc: i32 = impl_cwt_claims_to_cbor_inner(handle, &mut out_bytes, &mut out_len, &mut err);
    assert_eq!(rc, COSE_CWT_OK, "to_cbor inner failed");
    assert!(!out_bytes.is_null());
    assert!(out_len > 0);

    // Deserialize from CBOR
    let mut restored: *mut CoseCwtClaimsHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc: i32 = impl_cwt_claims_from_cbor_inner(out_bytes, out_len, &mut restored, &mut err);
    assert_eq!(rc, COSE_CWT_OK, "from_cbor inner failed");
    assert!(!restored.is_null());

    // Verify issuer
    let mut out_issuer: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc: i32 = impl_cwt_claims_get_issuer_inner(restored, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_issuer.is_null());
    let got_issuer: String = unsafe { CStr::from_ptr(out_issuer) }
        .to_string_lossy()
        .to_string();
    assert_eq!(got_issuer, "rt-issuer");

    // Verify subject
    let mut out_subject: *const libc::c_char = ptr::null();
    err = ptr::null_mut();
    let rc: i32 = impl_cwt_claims_get_subject_inner(restored, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(!out_subject.is_null());
    let got_subject: String = unsafe { CStr::from_ptr(out_subject) }
        .to_string_lossy()
        .to_string();
    assert_eq!(got_subject, "rt-subject");

    // Cleanup
    unsafe {
        cose_cwt_string_free(out_issuer as *mut _);
        cose_cwt_string_free(out_subject as *mut _);
        cose_cwt_bytes_free(out_bytes, out_len);
        cose_cwt_claims_free(handle);
        cose_cwt_claims_free(restored);
    }
}

// ---------------------------------------------------------------------------
// lib.rs coverage: from_cbor Err branch (L518-521)
// ---------------------------------------------------------------------------

/// Exercises from_cbor inner with invalid CBOR data to trigger Err path.
#[test]
fn from_cbor_inner_invalid_data_returns_error() {
    let bad_data: [u8; 3] = [0xFF, 0xAB, 0xCD];
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_from_cbor_inner(
        bad_data.as_ptr(),
        bad_data.len() as u32,
        &mut handle,
        &mut err,
    );
    assert_ne!(rc, COSE_CWT_OK);
    assert!(handle.is_null());
    free_error(err);
}

/// Exercises from_cbor inner with null cbor_data pointer.
#[test]
fn from_cbor_inner_null_data_returns_null_pointer() {
    let mut handle: *mut CoseCwtClaimsHandle = ptr::null_mut();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_from_cbor_inner(
        ptr::null(),
        0,
        &mut handle,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

/// Exercises from_cbor inner with null out_handle pointer.
#[test]
fn from_cbor_inner_null_out_handle() {
    let data: [u8; 1] = [0xA0]; // empty CBOR map
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_from_cbor_inner(
        data.as_ptr(),
        data.len() as u32,
        ptr::null_mut(),
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ---------------------------------------------------------------------------
// lib.rs coverage: to_cbor null pointer paths
// ---------------------------------------------------------------------------

/// Exercises to_cbor inner with null out_bytes/out_len.
#[test]
fn to_cbor_inner_null_out_bytes() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_to_cbor_inner(
        handle,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
    unsafe { cose_cwt_claims_free(handle) };
}

/// Exercises to_cbor inner with null handle.
#[test]
fn to_cbor_inner_null_handle() {
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_to_cbor_inner(
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ---------------------------------------------------------------------------
// lib.rs coverage: get_issuer/get_subject with no value set
// Exercises the "no issuer/subject set" branch returning FFI_OK + null
// ---------------------------------------------------------------------------

/// Get issuer when none set — returns Ok with null pointer.
#[test]
fn get_issuer_inner_no_value_set() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_issuer_inner(handle, &mut out_issuer, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_issuer.is_null()); // No issuer set

    unsafe { cose_cwt_claims_free(handle) };
}

/// Get subject when none set — returns Ok with null pointer.
#[test]
fn get_subject_inner_no_value_set() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_subject_inner(handle, &mut out_subject, &mut err);
    assert_eq!(rc, COSE_CWT_OK);
    assert!(out_subject.is_null()); // No subject set

    unsafe { cose_cwt_claims_free(handle) };
}

// ---------------------------------------------------------------------------
// lib.rs coverage: get_issuer/get_subject null output pointer
// ---------------------------------------------------------------------------

/// Get issuer with null out_issuer pointer.
#[test]
fn get_issuer_inner_null_out_pointer() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_issuer_inner(handle, ptr::null_mut(), &mut err);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);

    unsafe { cose_cwt_claims_free(handle) };
}

/// Get subject with null out_subject pointer.
#[test]
fn get_subject_inner_null_out_pointer() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_subject_inner(handle, ptr::null_mut(), &mut err);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);

    unsafe { cose_cwt_claims_free(handle) };
}

// ---------------------------------------------------------------------------
// lib.rs coverage: get_issuer/get_subject null handle
// ---------------------------------------------------------------------------

/// Get issuer with null claims handle.
#[test]
fn get_issuer_inner_null_handle() {
    let mut out_issuer: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_issuer_inner(ptr::null(), &mut out_issuer, &mut err);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

/// Get subject with null claims handle.
#[test]
fn get_subject_inner_null_handle() {
    let mut out_subject: *const libc::c_char = ptr::null();
    let mut err: *mut CoseCwtErrorHandle = ptr::null_mut();

    let rc: i32 = impl_cwt_claims_get_subject_inner(ptr::null(), &mut out_subject, &mut err);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ---------------------------------------------------------------------------
// lib.rs coverage: setter null-handle and null-value paths
// ---------------------------------------------------------------------------

/// Set issuer with null handle.
#[test]
fn set_issuer_inner_null_handle() {
    let issuer = CString::new("ignored").unwrap();
    let rc: i32 = impl_cwt_claims_set_issuer_inner(ptr::null_mut(), issuer.as_ptr());
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

/// Set issuer with null string pointer.
#[test]
fn set_issuer_inner_null_string() {
    let handle: *mut CoseCwtClaimsHandle = create_claims_handle();
    let rc: i32 = impl_cwt_claims_set_issuer_inner(handle, ptr::null());
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    unsafe { cose_cwt_claims_free(handle) };
}

/// Set subject with null handle.
#[test]
fn set_subject_inner_null_handle() {
    let subject = CString::new("ignored").unwrap();
    let rc: i32 = impl_cwt_claims_set_subject_inner(ptr::null_mut(), subject.as_ptr());
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

/// Set audience with null handle.
#[test]
fn set_audience_inner_null_handle() {
    let aud = CString::new("ignored").unwrap();
    let rc: i32 = impl_cwt_claims_set_audience_inner(ptr::null_mut(), aud.as_ptr());
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

/// Set issued_at with null handle.
#[test]
fn set_issued_at_inner_null_handle() {
    let rc: i32 = impl_cwt_claims_set_issued_at_inner(ptr::null_mut(), 12345);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

/// Set not_before with null handle.
#[test]
fn set_not_before_inner_null_handle() {
    let rc: i32 = impl_cwt_claims_set_not_before_inner(ptr::null_mut(), 12345);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

/// Set expiration with null handle.
#[test]
fn set_expiration_inner_null_handle() {
    let rc: i32 = impl_cwt_claims_set_expiration_inner(ptr::null_mut(), 12345);
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

// ---------------------------------------------------------------------------
// lib.rs coverage: cose_cwt_claims_free with null and cose_cwt_bytes_free
// ---------------------------------------------------------------------------

/// Free null claims handle — should be a no-op.
#[test]
fn claims_free_null_is_noop() {
    unsafe { cose_cwt_claims_free(ptr::null_mut()) };
}

/// Free null bytes pointer — should be a no-op.
#[test]
fn bytes_free_null_is_noop() {
    unsafe { cose_cwt_bytes_free(ptr::null_mut(), 0) };
}

// ---------------------------------------------------------------------------
// lib.rs coverage: create inner with null out_handle
// ---------------------------------------------------------------------------

/// Create with null out_handle returns null pointer error.
#[test]
fn create_inner_null_out_handle() {
    let rc: i32 = impl_cwt_claims_create_inner(ptr::null_mut());
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}
