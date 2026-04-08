// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C-ABI projection for `cose_sign1_primitives`.
//!
//! This crate provides C-compatible FFI exports for parsing and verifying COSE_Sign1
//! messages. It wraps the `cose_sign1_primitives` types, allowing C and C++ code to
//! parse COSE_Sign1 messages, access headers and payloads, and verify signatures.
//!
//! # ABI Stability
//!
//! All exported functions use `extern "C"` calling convention.
//! Opaque handle types are passed as `*mut` (owned) or `*const` (borrowed).
//! The ABI version is available via `cose_sign1_ffi_abi_version()`.
//!
//! # Panic Safety
//!
//! All exported functions are wrapped in `catch_unwind` to prevent
//! Rust panics from crossing the FFI boundary.
//!
//! # Error Handling
//!
//! All functions follow a consistent error handling pattern:
//! - Return value: 0 = success, negative = error code
//! - `out_error` parameter: Set to error handle on failure (caller must free)
//! - Output parameters: Only valid if return is 0
//!
//! # Memory Ownership
//!
//! - `*mut T` parameters transfer ownership TO this function (consumed)
//! - `*const T` parameters are borrowed (caller retains ownership)
//! - `*mut *mut T` out-parameters transfer ownership FROM this function (caller must free)
//! - Every handle type has a corresponding `*_free()` function:
//!   - `cose_sign1_message_free` for message handles
//!   - `cose_sign1_error_free` for error handles
//!   - `cose_sign1_string_free` for string pointers
//!   - `cose_headermap_free` for header map handles
//!   - `cose_key_free` for key handles
//!
//! Pointers to internal data (e.g., from `cose_sign1_message_protected_bytes`) are valid
//! only as long as the parent handle is valid.
//!
//! # Thread Safety
//!
//! All functions are thread-safe. Handles are not internally synchronized,
//! so concurrent mutation requires external synchronization.
//!
//! # Example (C)
//!
//! ```c
//! #include "cose_sign1_primitives_ffi.h"
//!
//! int verify_message(const uint8_t* data, size_t len, CoseKeyHandle* key) {
//!     CoseSign1MessageHandle* msg = NULL;
//!     CoseSign1ErrorHandle* err = NULL;
//!     bool verified = false;
//!
//!     // Parse the message
//!     int rc = cose_sign1_message_parse(data, len, &msg, &err);
//!     if (rc != 0) {
//!         char* msg = cose_sign1_error_message(err);
//!         printf("Parse error: %s\n", msg);
//!         cose_sign1_string_free(msg);
//!         cose_sign1_error_free(err);
//!         return rc;
//!     }
//!
//!     // Verify (no external AAD)
//!     rc = cose_sign1_message_verify(msg, key, NULL, 0, &verified, &err);
//!     if (rc != 0) {
//!         char* msg = cose_sign1_error_message(err);
//!         printf("Verify error: %s\n", msg);
//!         cose_sign1_string_free(msg);
//!         cose_sign1_error_free(err);
//!         cose_sign1_message_free(msg);
//!         return rc;
//!     }
//!
//!     printf("Signature valid: %s\n", verified ? "yes" : "no");
//!     cose_sign1_message_free(msg);
//!     return 0;
//! }
//! ```

pub mod error;
pub mod message;
pub mod provider;
pub mod types;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, CryptoVerifier};

use crate::error::{
    FFI_ERR_HEADER_NOT_FOUND, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER, FFI_ERR_PANIC, FFI_OK,
};
use crate::types::{
    headermap_handle_to_inner, headermap_inner_to_handle, key_handle_to_inner, key_inner_to_handle,
    message_handle_to_inner, HeaderMapInner, KeyInner,
};

// Re-export handle types for library users
pub use crate::types::{CoseHeaderMapHandle, CoseKeyHandle, CoseSign1MessageHandle};

// Re-export error codes for library users
pub use crate::error::{
    FFI_ERR_HEADER_NOT_FOUND as COSE_SIGN1_ERR_HEADER_NOT_FOUND,
    FFI_ERR_INVALID_ARGUMENT as COSE_SIGN1_ERR_INVALID_ARGUMENT,
    FFI_ERR_NULL_POINTER as COSE_SIGN1_ERR_NULL_POINTER, FFI_ERR_PANIC as COSE_SIGN1_ERR_PANIC,
    FFI_ERR_PARSE_FAILED as COSE_SIGN1_ERR_PARSE_FAILED,
    FFI_ERR_PAYLOAD_MISSING as COSE_SIGN1_ERR_PAYLOAD_MISSING,
    FFI_ERR_VERIFY_FAILED as COSE_SIGN1_ERR_VERIFY_FAILED, FFI_OK as COSE_SIGN1_OK,
};

pub use crate::error::{
    cose_sign1_error_code, cose_sign1_error_free, cose_sign1_error_message, cose_sign1_string_free,
    CoseSign1ErrorHandle,
};

pub use crate::message::{
    cose_sign1_message_alg, cose_sign1_message_as_bytes, cose_sign1_message_free,
    cose_sign1_message_is_detached, cose_sign1_message_parse, cose_sign1_message_payload,
    cose_sign1_message_protected_bytes, cose_sign1_message_signature, cose_sign1_message_verify,
    cose_sign1_message_verify_detached,
};

/// ABI version for this library.
///
/// Increment when making breaking changes to the FFI interface.
pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
pub extern "C" fn cose_sign1_ffi_abi_version() -> u32 {
    ABI_VERSION
}

// ============================================================================
// Key handle functions
// ============================================================================

/// Frees a key handle.
///
/// # Safety
///
/// - `key` must be a valid key handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_key_free(key: *mut CoseKeyHandle) {
    if key.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(key as *mut KeyInner));
    }
}

/// Inner implementation for cose_key_algorithm.
pub fn key_algorithm_inner(key: *const CoseKeyHandle, out_alg: *mut i64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_alg.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { key_handle_to_inner(key) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        unsafe {
            *out_alg = inner.key.algorithm();
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the algorithm from a key.
///
/// # Safety
///
/// - `key` must be a valid key handle
/// - `out_alg` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_key_algorithm(key: *const CoseKeyHandle, out_alg: *mut i64) -> i32 {
    key_algorithm_inner(key, out_alg)
}

/// Inner implementation for cose_key_type.
pub fn key_type_inner(key: *const CoseKeyHandle) -> *mut libc::c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(_inner) = (unsafe { key_handle_to_inner(key) }) else {
            return ptr::null_mut();
        };

        // CryptoVerifier trait does not provide key_type; return "unknown"
        let key_type = "unknown";
        match std::ffi::CString::new(key_type) {
            Ok(c_str) => c_str.into_raw(),
            Err(_) => ptr::null_mut(),
        }
    }));

    result.unwrap_or(ptr::null_mut())
}

/// Gets the key type from a key.
///
/// # Safety
///
/// - `key` must be a valid key handle
/// - Caller must free the returned string with `cose_sign1_string_free`
#[no_mangle]
pub unsafe extern "C" fn cose_key_type(key: *const CoseKeyHandle) -> *mut libc::c_char {
    key_type_inner(key)
}

// ============================================================================
// Header map functions
// ============================================================================

/// Inner implementation for cose_sign1_message_protected_headers.
pub fn message_protected_headers_inner(
    message: *const CoseSign1MessageHandle,
    out_headers: *mut *mut CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_headers.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_headers = ptr::null_mut();
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        // PERF: consider Arc<CoseHeaderMap> in CoseSign1Message to avoid this clone.
        // The FFI handle needs an independent lifetime from the message, so a clone
        // (or Arc) is required here. Headers are typically small, so cost is low.
        let headers_inner = HeaderMapInner {
            headers: inner.message.protected_headers().clone(),
        };

        unsafe {
            *out_headers = headermap_inner_to_handle(headers_inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the protected header map from a message.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_headers` must be valid for writes
/// - Caller owns the returned header map handle and must free it with `cose_headermap_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_protected_headers(
    message: *const CoseSign1MessageHandle,
    out_headers: *mut *mut CoseHeaderMapHandle,
) -> i32 {
    message_protected_headers_inner(message, out_headers)
}

/// Inner implementation for cose_sign1_message_unprotected_headers.
pub fn message_unprotected_headers_inner(
    message: *const CoseSign1MessageHandle,
    out_headers: *mut *mut CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_headers.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_headers = ptr::null_mut();
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        // PERF: consider Arc<CoseHeaderMap> in CoseSign1Message to avoid this clone.
        // The FFI handle needs an independent lifetime from the message, so a clone
        // (or Arc) is required here. Headers are typically small, so cost is low.
        let headers_inner = HeaderMapInner {
            headers: inner.message.unprotected_headers().clone(),
        };

        unsafe {
            *out_headers = headermap_inner_to_handle(headers_inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the unprotected header map from a message.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_headers` must be valid for writes
/// - Caller owns the returned header map handle and must free it with `cose_headermap_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_unprotected_headers(
    message: *const CoseSign1MessageHandle,
    out_headers: *mut *mut CoseHeaderMapHandle,
) -> i32 {
    message_unprotected_headers_inner(message, out_headers)
}

/// Frees a header map handle.
///
/// # Safety
///
/// - `headers` must be a valid header map handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_free(headers: *mut CoseHeaderMapHandle) {
    if headers.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(headers as *mut HeaderMapInner));
    }
}

/// Inner implementation for cose_headermap_get_int.
pub fn headermap_get_int_inner(
    headers: *const CoseHeaderMapHandle,
    label: i64,
    out_value: *mut i64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_value.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let label_key = CoseHeaderLabel::Int(label);
        match inner.headers.get(&label_key) {
            Some(CoseHeaderValue::Int(v)) => {
                unsafe {
                    *out_value = *v;
                }
                FFI_OK
            }
            Some(CoseHeaderValue::Uint(v)) => {
                if *v <= i64::MAX as u64 {
                    unsafe {
                        *out_value = *v as i64;
                    }
                    FFI_OK
                } else {
                    FFI_ERR_INVALID_ARGUMENT
                }
            }
            _ => FFI_ERR_HEADER_NOT_FOUND,
        }
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets an integer value from a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
/// - `out_value` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_get_int(
    headers: *const CoseHeaderMapHandle,
    label: i64,
    out_value: *mut i64,
) -> i32 {
    headermap_get_int_inner(headers, label, out_value)
}

/// Inner implementation for cose_headermap_get_bytes.
pub fn headermap_get_bytes_inner(
    headers: *const CoseHeaderMapHandle,
    label: i64,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let label_key = CoseHeaderLabel::Int(label);
        match inner.headers.get(&label_key) {
            Some(CoseHeaderValue::Bytes(bytes)) => {
                unsafe {
                    *out_bytes = bytes.as_bytes().as_ptr();
                    *out_len = bytes.len();
                }
                FFI_OK
            }
            _ => FFI_ERR_HEADER_NOT_FOUND,
        }
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets a byte string value from a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - The returned bytes pointer is valid only as long as the header map handle is valid
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_get_bytes(
    headers: *const CoseHeaderMapHandle,
    label: i64,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    headermap_get_bytes_inner(headers, label, out_bytes, out_len)
}

/// Inner implementation for cose_headermap_get_text.
pub fn headermap_get_text_inner(
    headers: *const CoseHeaderMapHandle,
    label: i64,
) -> *mut libc::c_char {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return ptr::null_mut();
        };

        let label_key = CoseHeaderLabel::Int(label);
        match inner.headers.get(&label_key) {
            Some(CoseHeaderValue::Text(text)) => match std::ffi::CString::new(text.as_str()) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            _ => ptr::null_mut(),
        }
    }));

    result.unwrap_or(ptr::null_mut())
}

/// Gets a text string value from a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
/// - Caller must free the returned string with `cose_sign1_string_free`
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_get_text(
    headers: *const CoseHeaderMapHandle,
    label: i64,
) -> *mut libc::c_char {
    headermap_get_text_inner(headers, label)
}

/// Inner implementation for cose_headermap_contains.
pub fn headermap_contains_inner(headers: *const CoseHeaderMapHandle, label: i64) -> bool {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return false;
        };

        let label_key = CoseHeaderLabel::Int(label);
        inner.headers.get(&label_key).is_some()
    }));

    result.unwrap_or(false)
}

/// Checks if a header with the given integer label exists.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_contains(
    headers: *const CoseHeaderMapHandle,
    label: i64,
) -> bool {
    headermap_contains_inner(headers, label)
}

/// Inner implementation for cose_headermap_len.
pub fn headermap_len_inner(headers: *const CoseHeaderMapHandle) -> usize {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return 0;
        };
        inner.headers.len()
    }));

    result.unwrap_or(0)
}

/// Returns the number of headers in the map.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_len(headers: *const CoseHeaderMapHandle) -> usize {
    headermap_len_inner(headers)
}

// ============================================================================
// Key creation helpers (for testing and embedding)
// ============================================================================

/// Creates a key handle from a boxed CryptoVerifier trait object.
///
/// This is not exported via FFI but is useful for Rust code that needs to
/// create key handles from custom key implementations.
pub fn create_key_handle(key: Box<dyn CryptoVerifier>) -> *mut CoseKeyHandle {
    let inner = KeyInner { key };
    key_inner_to_handle(inner)
}
