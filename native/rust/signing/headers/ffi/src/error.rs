// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types and handling for the CWT Claims FFI layer.
//!
//! Provides opaque error handles that can be passed across the FFI boundary
//! and safely queried from C/C++ code.

use std::ffi::CString;
use std::ptr;

use cose_sign1_headers::HeaderError;

/// FFI return status codes.
///
/// Functions return 0 on success and negative values on error.
pub const FFI_OK: i32 = 0;
pub const FFI_ERR_NULL_POINTER: i32 = -1;
pub const FFI_ERR_CBOR_ENCODE_FAILED: i32 = -2;
pub const FFI_ERR_CBOR_DECODE_FAILED: i32 = -3;
pub const FFI_ERR_INVALID_ARGUMENT: i32 = -5;
pub const FFI_ERR_PANIC: i32 = -99;

/// Opaque handle to an error.
///
/// The handle wraps a boxed error and provides safe access to error details.
#[repr(C)]
pub struct CoseCwtErrorHandle {
    _private: [u8; 0],
}

/// Internal error representation.
pub struct ErrorInner {
    pub message: String,
    pub code: i32,
}

impl ErrorInner {
    pub fn new(message: impl Into<String>, code: i32) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }

    pub fn from_header_error(err: &HeaderError) -> Self {
        let code = match err {
            HeaderError::CborEncodingError(_) => FFI_ERR_CBOR_ENCODE_FAILED,
            HeaderError::CborDecodingError(_) => FFI_ERR_CBOR_DECODE_FAILED,
            HeaderError::InvalidClaimType { .. } => FFI_ERR_INVALID_ARGUMENT,
            HeaderError::MissingRequiredClaim(_) => FFI_ERR_INVALID_ARGUMENT,
            HeaderError::InvalidTimestamp(_) => FFI_ERR_INVALID_ARGUMENT,
            HeaderError::ComplexClaimValue(_) => FFI_ERR_INVALID_ARGUMENT,
        };
        Self {
            message: err.to_string(),
            code,
        }
    }

    pub fn null_pointer(name: &str) -> Self {
        Self {
            message: format!("{} must not be null", name),
            code: FFI_ERR_NULL_POINTER,
        }
    }
}

/// Casts an error handle to its inner representation.
///
/// # Safety
///
/// The handle must be valid and non-null.
pub unsafe fn handle_to_inner(
    handle: *const CoseCwtErrorHandle,
) -> Option<&'static ErrorInner> {
    if handle.is_null() {
        return None;
    }
    Some(unsafe { &*(handle as *const ErrorInner) })
}

/// Creates an error handle from an inner representation.
pub fn inner_to_handle(inner: ErrorInner) -> *mut CoseCwtErrorHandle {
    let boxed = Box::new(inner);
    Box::into_raw(boxed) as *mut CoseCwtErrorHandle
}

/// Sets an output error pointer if it's not null.
pub fn set_error(out_error: *mut *mut CoseCwtErrorHandle, inner: ErrorInner) {
    if !out_error.is_null() {
        unsafe {
            *out_error = inner_to_handle(inner);
        }
    }
}

/// Gets the error message as a C string (caller must free).
///
/// # Safety
///
/// - `handle` must be a valid error handle or null
/// - Caller is responsible for freeing the returned string via `cose_cwt_string_free`
#[no_mangle]
pub unsafe extern "C" fn cose_cwt_error_message(
    handle: *const CoseCwtErrorHandle,
) -> *mut libc::c_char {
    let Some(inner) = (unsafe { handle_to_inner(handle) }) else {
        return ptr::null_mut();
    };

    match CString::new(inner.message.as_str()) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => {
            match CString::new("error message contained NUL byte") {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => ptr::null_mut(),
            }
        }
    }
}

/// Gets the error code.
///
/// # Safety
///
/// - `handle` must be a valid error handle or null
#[no_mangle]
pub unsafe extern "C" fn cose_cwt_error_code(handle: *const CoseCwtErrorHandle) -> i32 {
    match unsafe { handle_to_inner(handle) } {
        Some(inner) => inner.code,
        None => 0,
    }
}

/// Frees an error handle.
///
/// # Safety
///
/// - `handle` must be a valid error handle or null
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_cwt_error_free(handle: *mut CoseCwtErrorHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle as *mut ErrorInner));
    }
}

/// Frees a string previously returned by this library.
///
/// # Safety
///
/// - `s` must be a string allocated by this library or null
/// - The string must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_cwt_string_free(s: *mut libc::c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}
