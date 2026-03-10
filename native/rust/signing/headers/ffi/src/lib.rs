// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C/C++ FFI for COSE Sign1 CWT Claims operations.
//!
//! This crate (`cose_sign1_headers_ffi`) provides FFI-safe wrappers for creating and managing
//! CWT (CBOR Web Token) Claims from C and C++ code. It uses `cose_sign1_headers` for types and
//! `cbor_primitives_everparse` for CBOR encoding/decoding.
//!
//! ## Error Handling
//!
//! All functions follow a consistent error handling pattern:
//! - Return value: 0 = success, negative = error code
//! - `out_error` parameter: Set to error handle on failure (caller must free)
//! - Output parameters: Only valid if return is 0
//!
//! ## Memory Management
//!
//! Handles returned by this library must be freed using the corresponding `*_free` function:
//! - `cose_cwt_claims_free` for CWT claims handles
//! - `cose_cwt_error_free` for error handles
//! - `cose_cwt_string_free` for string pointers
//! - `cose_cwt_bytes_free` for byte buffer pointers
//!
//! ## Thread Safety
//!
//! All handles are thread-safe and can be used from multiple threads. However, handles
//! are not internally synchronized, so concurrent mutation requires external synchronization.

pub mod error;
pub mod provider;
pub mod types;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use crate::provider::ffi_cbor_provider;
use cose_sign1_headers::CwtClaims;

use crate::error::{
    set_error, ErrorInner, FFI_ERR_CBOR_DECODE_FAILED, FFI_ERR_CBOR_ENCODE_FAILED,
    FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER, FFI_ERR_PANIC, FFI_OK,
};
use crate::types::{
    cwt_claims_handle_to_inner, cwt_claims_handle_to_inner_mut, cwt_claims_inner_to_handle,
    CwtClaimsInner,
};

// Re-export handle types for library users
pub use crate::types::CoseCwtClaimsHandle;

// Re-export error types for library users
pub use crate::error::{
    CoseCwtErrorHandle, FFI_ERR_CBOR_DECODE_FAILED as COSE_CWT_ERR_CBOR_DECODE_FAILED,
    FFI_ERR_CBOR_ENCODE_FAILED as COSE_CWT_ERR_CBOR_ENCODE_FAILED,
    FFI_ERR_INVALID_ARGUMENT as COSE_CWT_ERR_INVALID_ARGUMENT,
    FFI_ERR_NULL_POINTER as COSE_CWT_ERR_NULL_POINTER,
    FFI_ERR_PANIC as COSE_CWT_ERR_PANIC, FFI_OK as COSE_CWT_OK,
};

pub use crate::error::{
    cose_cwt_error_code, cose_cwt_error_free, cose_cwt_error_message,
    cose_cwt_string_free,
};

/// ABI version for this library.
///
/// Increment when making breaking changes to the FFI interface.
pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_cwt_claims_abi_version() -> u32 {
    ABI_VERSION
}

// ============================================================================
// CWT Claims lifecycle
// ============================================================================

/// Inner implementation for cose_cwt_claims_create.
pub fn impl_cwt_claims_create_inner(
    out_handle: *mut *mut CoseCwtClaimsHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let inner = CwtClaimsInner {
            claims: CwtClaims::new(),
        };

        unsafe {
            *out_handle = cwt_claims_inner_to_handle(inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Creates a new empty CWT claims instance.
///
/// # Safety
///
/// - `out_handle` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_cwt_claims_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_create(
    out_handle: *mut *mut CoseCwtClaimsHandle,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_create_inner(out_handle);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to create CWT claims", result),
        );
    }
    result
}

// ============================================================================
// CWT Claims setters
// ============================================================================

/// Inner implementation for cose_cwt_claims_set_issuer.
pub fn impl_cwt_claims_set_issuer_inner(
    handle: *mut CoseCwtClaimsHandle,
    issuer: *const libc::c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if issuer.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(issuer) };
        let text = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return FFI_ERR_INVALID_ARGUMENT,
        };

        inner.claims.issuer = Some(text);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the issuer (iss, label 1) claim.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `issuer` must be a valid null-terminated C string
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_issuer(
    handle: *mut CoseCwtClaimsHandle,
    issuer: *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_issuer_inner(handle, issuer);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set issuer", result),
        );
    }
    result
}

/// Inner implementation for cose_cwt_claims_set_subject.
pub fn impl_cwt_claims_set_subject_inner(
    handle: *mut CoseCwtClaimsHandle,
    subject: *const libc::c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if subject.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(subject) };
        let text = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return FFI_ERR_INVALID_ARGUMENT,
        };

        inner.claims.subject = Some(text);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the subject (sub, label 2) claim.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `subject` must be a valid null-terminated C string
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_subject(
    handle: *mut CoseCwtClaimsHandle,
    subject: *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_subject_inner(handle, subject);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set subject", result),
        );
    }
    result
}

/// Inner implementation for cose_cwt_claims_set_issued_at.
pub fn impl_cwt_claims_set_issued_at_inner(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        inner.claims.issued_at = Some(unix_timestamp);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the issued at (iat, label 6) claim as Unix timestamp.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_issued_at(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_issued_at_inner(handle, unix_timestamp);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set issued_at", result),
        );
    }
    result
}

/// Inner implementation for cose_cwt_claims_set_not_before.
pub fn impl_cwt_claims_set_not_before_inner(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        inner.claims.not_before = Some(unix_timestamp);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the not before (nbf, label 5) claim as Unix timestamp.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_not_before(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_not_before_inner(handle, unix_timestamp);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set not_before", result),
        );
    }
    result
}

/// Inner implementation for cose_cwt_claims_set_expiration.
pub fn impl_cwt_claims_set_expiration_inner(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        inner.claims.expiration_time = Some(unix_timestamp);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the expiration time (exp, label 4) claim as Unix timestamp.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_expiration(
    handle: *mut CoseCwtClaimsHandle,
    unix_timestamp: i64,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_expiration_inner(handle, unix_timestamp);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set expiration", result),
        );
    }
    result
}

/// Inner implementation for cose_cwt_claims_set_audience.
pub fn impl_cwt_claims_set_audience_inner(
    handle: *mut CoseCwtClaimsHandle,
    audience: *const libc::c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { cwt_claims_handle_to_inner_mut(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if audience.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(audience) };
        let text = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return FFI_ERR_INVALID_ARGUMENT,
        };

        inner.claims.audience = Some(text);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the audience (aud, label 3) claim.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `audience` must be a valid null-terminated C string
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_set_audience(
    handle: *mut CoseCwtClaimsHandle,
    audience: *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = impl_cwt_claims_set_audience_inner(handle, audience);
    if result != FFI_OK && !out_error.is_null() {
        set_error(
            out_error,
            ErrorInner::new("Failed to set audience", result),
        );
    }
    result
}

// ============================================================================
// Serialization
// ============================================================================

/// Inner implementation for cose_cwt_claims_to_cbor.
pub fn impl_cwt_claims_to_cbor_inner(
    handle: *const CoseCwtClaimsHandle,
    out_bytes: *mut *mut u8,
    out_len: *mut u32,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_bytes/out_len"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_bytes = ptr::null_mut();
            *out_len = 0;
        }

        let Some(inner) = (unsafe { cwt_claims_handle_to_inner(handle) }) else {
            set_error(out_error, ErrorInner::null_pointer("handle"));
            return FFI_ERR_NULL_POINTER;
        };

        let _provider = ffi_cbor_provider();
        match inner.claims.to_cbor_bytes() {
            Ok(bytes) => {
                let len = bytes.len();
                if len > u32::MAX as usize {
                    set_error(
                        out_error,
                        ErrorInner::new("CBOR data too large", FFI_ERR_CBOR_ENCODE_FAILED),
                    );
                    return FFI_ERR_CBOR_ENCODE_FAILED;
                }
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_bytes = raw as *mut u8;
                    *out_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_header_error(&err));
                FFI_ERR_CBOR_ENCODE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during CBOR encoding", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Serializes CWT claims to CBOR bytes.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - Caller must free returned bytes with `cose_cwt_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_to_cbor(
    handle: *const CoseCwtClaimsHandle,
    out_bytes: *mut *mut u8,
    out_len: *mut u32,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    impl_cwt_claims_to_cbor_inner(handle, out_bytes, out_len, out_error)
}

/// Inner implementation for cose_cwt_claims_from_cbor.
pub fn impl_cwt_claims_from_cbor_inner(
    cbor_data: *const u8,
    cbor_len: u32,
    out_handle: *mut *mut CoseCwtClaimsHandle,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_handle"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_handle = ptr::null_mut();
        }

        if cbor_data.is_null() {
            set_error(out_error, ErrorInner::null_pointer("cbor_data"));
            return FFI_ERR_NULL_POINTER;
        }

        let data = unsafe { slice::from_raw_parts(cbor_data, cbor_len as usize) };

        let _provider = ffi_cbor_provider();
        match CwtClaims::from_cbor_bytes(data) {
            Ok(claims) => {
                let inner = CwtClaimsInner { claims };
                unsafe {
                    *out_handle = cwt_claims_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_header_error(&err));
                FFI_ERR_CBOR_DECODE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during CBOR decoding", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Deserializes CWT claims from CBOR bytes.
///
/// # Safety
///
/// - `cbor_data` must be valid for reads of `cbor_len` bytes
/// - `out_handle` must be valid for writes
/// - Caller must free returned handle with `cose_cwt_claims_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_from_cbor(
    cbor_data: *const u8,
    cbor_len: u32,
    out_handle: *mut *mut CoseCwtClaimsHandle,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    impl_cwt_claims_from_cbor_inner(cbor_data, cbor_len, out_handle, out_error)
}

// ============================================================================
// Getters
// ============================================================================

/// Inner implementation for cose_cwt_claims_get_issuer.
pub fn impl_cwt_claims_get_issuer_inner(
    handle: *const CoseCwtClaimsHandle,
    out_issuer: *mut *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_issuer.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_issuer"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_issuer = ptr::null();
        }

        let Some(inner) = (unsafe { cwt_claims_handle_to_inner(handle) }) else {
            set_error(out_error, ErrorInner::null_pointer("handle"));
            return FFI_ERR_NULL_POINTER;
        };

        if let Some(ref issuer) = inner.claims.issuer {
            match std::ffi::CString::new(issuer.as_str()) {
                Ok(c_str) => {
                    unsafe {
                        *out_issuer = c_str.into_raw();
                    }
                    FFI_OK
                }
                Err(_) => {
                    set_error(
                        out_error,
                        ErrorInner::new("issuer contains NUL byte", FFI_ERR_INVALID_ARGUMENT),
                    );
                    FFI_ERR_INVALID_ARGUMENT
                }
            }
        } else {
            // No issuer set - return null pointer, which is valid
            FFI_OK
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during get issuer", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Gets the issuer (iss, label 1) claim.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `out_issuer` must be valid for writes
/// - Caller must free returned string with `cose_cwt_string_free`
/// - Returns null pointer in `out_issuer` if issuer is not set
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_get_issuer(
    handle: *const CoseCwtClaimsHandle,
    out_issuer: *mut *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    impl_cwt_claims_get_issuer_inner(handle, out_issuer, out_error)
}

/// Inner implementation for cose_cwt_claims_get_subject.
pub fn impl_cwt_claims_get_subject_inner(
    handle: *const CoseCwtClaimsHandle,
    out_subject: *mut *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_subject.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_subject"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_subject = ptr::null();
        }

        let Some(inner) = (unsafe { cwt_claims_handle_to_inner(handle) }) else {
            set_error(out_error, ErrorInner::null_pointer("handle"));
            return FFI_ERR_NULL_POINTER;
        };

        if let Some(ref subject) = inner.claims.subject {
            match std::ffi::CString::new(subject.as_str()) {
                Ok(c_str) => {
                    unsafe {
                        *out_subject = c_str.into_raw();
                    }
                    FFI_OK
                }
                Err(_) => {
                    set_error(
                        out_error,
                        ErrorInner::new("subject contains NUL byte", FFI_ERR_INVALID_ARGUMENT),
                    );
                    FFI_ERR_INVALID_ARGUMENT
                }
            }
        } else {
            // No subject set - return null pointer, which is valid
            FFI_OK
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during get subject", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Gets the subject (sub, label 2) claim.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle
/// - `out_subject` must be valid for writes
/// - Caller must free returned string with `cose_cwt_string_free`
/// - Returns null pointer in `out_subject` if subject is not set
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_get_subject(
    handle: *const CoseCwtClaimsHandle,
    out_subject: *mut *const libc::c_char,
    out_error: *mut *mut CoseCwtErrorHandle,
) -> i32 {
    impl_cwt_claims_get_subject_inner(handle, out_subject, out_error)
}

// ============================================================================
// Memory management
// ============================================================================

/// Frees a CWT claims handle.
///
/// # Safety
///
/// - `handle` must be a valid CWT claims handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_claims_free(handle: *mut CoseCwtClaimsHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle as *mut CwtClaimsInner));
    }
}

/// Frees bytes previously returned by serialization operations.
///
/// # Safety
///
/// - `ptr` must have been returned by `cose_cwt_claims_to_cbor` or be NULL
/// - `len` must be the length returned alongside the bytes
/// - The bytes must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_cwt_bytes_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(slice::from_raw_parts_mut(
            ptr,
            len as usize,
        )));
    }
}
