// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C/C++ FFI for DID:x509 parsing, building, validation and resolution.
//!
//! This crate (`did_x509_ffi`) provides FFI-safe wrappers for working with DID:x509
//! identifiers from C and C++ code. It uses the `did_x509` crate for core functionality.
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
//! Handles and strings returned by this library must be freed using the corresponding `*_free` function:
//! - `did_x509_parsed_free` for parsed identifier handles
//! - `did_x509_error_free` for error handles
//! - `did_x509_string_free` for string pointers
//!
//! ## Thread Safety
//!
//! All handles are thread-safe and can be used from multiple threads. However, handles
//! are not internally synchronized, so concurrent mutation requires external synchronization.

pub mod error;
pub mod types;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use did_x509::{DidX509Builder, DidX509Parser, DidX509Policy, DidX509Resolver, DidX509Validator};

use crate::error::{
    set_error, ErrorInner, FFI_ERR_BUILD_FAILED, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PANIC, FFI_ERR_PARSE_FAILED, FFI_ERR_RESOLVE_FAILED, FFI_ERR_VALIDATE_FAILED, FFI_OK,
};
use crate::types::{parsed_handle_to_inner, parsed_inner_to_handle, ParsedInner};

// Re-export handle types for library users
pub use crate::types::DidX509ParsedHandle;

// Re-export error types for library users
pub use crate::error::{
    DidX509ErrorHandle, FFI_ERR_BUILD_FAILED as DID_X509_ERR_BUILD_FAILED,
    FFI_ERR_INVALID_ARGUMENT as DID_X509_ERR_INVALID_ARGUMENT,
    FFI_ERR_NULL_POINTER as DID_X509_ERR_NULL_POINTER, FFI_ERR_PANIC as DID_X509_ERR_PANIC,
    FFI_ERR_PARSE_FAILED as DID_X509_ERR_PARSE_FAILED,
    FFI_ERR_RESOLVE_FAILED as DID_X509_ERR_RESOLVE_FAILED,
    FFI_ERR_VALIDATE_FAILED as DID_X509_ERR_VALIDATE_FAILED, FFI_OK as DID_X509_OK,
};

pub use crate::error::{
    did_x509_error_code, did_x509_error_free, did_x509_error_message, did_x509_string_free,
};

/// Handle a panic from catch_unwind by setting the error and returning FFI_ERR_PANIC.
#[cfg_attr(coverage_nightly, coverage(off))]
fn handle_panic(out_error: *mut *mut DidX509ErrorHandle, context: &str) -> i32 {
    set_error(
        out_error,
        ErrorInner::new(format!("panic during {}", context), FFI_ERR_PANIC),
    );
    FFI_ERR_PANIC
}

/// Handle a NUL byte in a CString by setting the error and returning FFI_ERR_INVALID_ARGUMENT.
fn handle_nul_byte(out_error: *mut *mut DidX509ErrorHandle, field: &str) -> i32 {
    set_error(
        out_error,
        ErrorInner::new(
            format!("{} contained NUL byte", field),
            FFI_ERR_INVALID_ARGUMENT,
        ),
    );
    FFI_ERR_INVALID_ARGUMENT
}

/// ABI version for this library.
///
/// Increment when making breaking changes to the FFI interface.
pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
pub extern "C" fn did_x509_abi_version() -> u32 {
    ABI_VERSION
}

// ============================================================================
// Parsing functions
// ============================================================================

/// Inner implementation for did_x509_parse.
pub fn impl_parse_inner(
    did_string: *const libc::c_char,
    out_handle: *mut *mut DidX509ParsedHandle,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_handle"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_handle = ptr::null_mut();
        }

        if did_string.is_null() {
            set_error(out_error, ErrorInner::null_pointer("did_string"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(did_string) };
        let did_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid UTF-8 in DID string", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        match DidX509Parser::parse(did_str) {
            Ok(parsed) => {
                let inner = ParsedInner { parsed };
                unsafe {
                    *out_handle = parsed_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_did_error(&err));
                FFI_ERR_PARSE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "parsing"),
    }
}

/// Parse a DID:x509 string into components.
///
/// # Safety
///
/// - `did_string` must be a valid null-terminated C string
/// - `out_handle` must be valid for writes
/// - Caller owns the returned handle and must free it with `did_x509_parsed_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_parse(
    did_string: *const libc::c_char,
    out_handle: *mut *mut DidX509ParsedHandle,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_parse_inner(did_string, out_handle, out_error)
}

/// Inner implementation for did_x509_parsed_get_fingerprint.
pub fn impl_parsed_get_fingerprint_inner(
    handle: *const DidX509ParsedHandle,
    out_fingerprint: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_fingerprint.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_fingerprint"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_fingerprint = ptr::null_mut();
        }

        let Some(inner) = (unsafe { parsed_handle_to_inner(handle) }) else {
            set_error(out_error, ErrorInner::null_pointer("handle"));
            return FFI_ERR_NULL_POINTER;
        };

        match std::ffi::CString::new(inner.parsed.ca_fingerprint_hex.as_str()) {
            Ok(c_str) => {
                unsafe {
                    *out_fingerprint = c_str.into_raw();
                }
                FFI_OK
            }
            Err(_) => handle_nul_byte(out_error, "fingerprint"),
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "fingerprint extraction"),
    }
}

/// Get fingerprint hex from parsed DID.
///
/// # Safety
///
/// - `handle` must be a valid parsed DID handle
/// - `out_fingerprint` must be valid for writes
/// - Caller is responsible for freeing the returned string via `did_x509_string_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_parsed_get_fingerprint(
    handle: *const DidX509ParsedHandle,
    out_fingerprint: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_parsed_get_fingerprint_inner(handle, out_fingerprint, out_error)
}

/// Inner implementation for did_x509_parsed_get_hash_algorithm.
pub fn impl_parsed_get_hash_algorithm_inner(
    handle: *const DidX509ParsedHandle,
    out_algorithm: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_algorithm.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_algorithm"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_algorithm = ptr::null_mut();
        }

        let Some(inner) = (unsafe { parsed_handle_to_inner(handle) }) else {
            set_error(out_error, ErrorInner::null_pointer("handle"));
            return FFI_ERR_NULL_POINTER;
        };

        match std::ffi::CString::new(inner.parsed.hash_algorithm.as_str()) {
            Ok(c_str) => {
                unsafe {
                    *out_algorithm = c_str.into_raw();
                }
                FFI_OK
            }
            Err(_) => handle_nul_byte(out_error, "hash algorithm"),
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "hash algorithm extraction"),
    }
}

/// Get hash algorithm from parsed DID.
///
/// # Safety
///
/// - `handle` must be a valid parsed DID handle
/// - `out_algorithm` must be valid for writes
/// - Caller is responsible for freeing the returned string via `did_x509_string_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_parsed_get_hash_algorithm(
    handle: *const DidX509ParsedHandle,
    out_algorithm: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_parsed_get_hash_algorithm_inner(handle, out_algorithm, out_error)
}

/// Inner implementation for did_x509_parsed_get_policy_count.
pub fn impl_parsed_get_policy_count_inner(
    handle: *const DidX509ParsedHandle,
    out_count: *mut u32,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_count.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { parsed_handle_to_inner(handle) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        unsafe {
            *out_count = inner.parsed.policies.len() as u32;
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Get policy count from parsed DID.
///
/// # Safety
///
/// - `handle` must be a valid parsed DID handle
/// - `out_count` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn did_x509_parsed_get_policy_count(
    handle: *const DidX509ParsedHandle,
    out_count: *mut u32,
) -> i32 {
    impl_parsed_get_policy_count_inner(handle, out_count)
}

/// Frees a parsed DID handle.
///
/// # Safety
///
/// - `handle` must be a valid parsed DID handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn did_x509_parsed_free(handle: *mut DidX509ParsedHandle) {
    if handle.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(handle as *mut ParsedInner));
    }
}

// ============================================================================
// Building functions
// ============================================================================

/// Inner implementation for did_x509_build_with_eku.
pub fn impl_build_with_eku_inner(
    ca_cert_der: *const u8,
    ca_cert_len: u32,
    eku_oids: *const *const libc::c_char,
    eku_count: u32,
    out_did_string: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_did_string.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_did_string"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_did_string = ptr::null_mut();
        }

        if ca_cert_der.is_null() && ca_cert_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("ca_cert_der"));
            return FFI_ERR_NULL_POINTER;
        }

        if eku_oids.is_null() && eku_count > 0 {
            set_error(out_error, ErrorInner::null_pointer("eku_oids"));
            return FFI_ERR_NULL_POINTER;
        }

        let cert_bytes = if ca_cert_der.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(ca_cert_der, ca_cert_len as usize) }
        };

        // Collect EKU OIDs
        let mut oids = Vec::new();
        for i in 0..eku_count {
            let oid_ptr = unsafe { *eku_oids.add(i as usize) };
            if oid_ptr.is_null() {
                set_error(
                    out_error,
                    ErrorInner::new(format!("eku_oids[{}] is null", i), FFI_ERR_NULL_POINTER),
                );
                return FFI_ERR_NULL_POINTER;
            }
            let c_str = unsafe { std::ffi::CStr::from_ptr(oid_ptr) };
            match c_str.to_str() {
                Ok(s) => oids.push(s.to_string()),
                Err(_) => {
                    set_error(
                        out_error,
                        ErrorInner::new(
                            format!("eku_oids[{}] contained invalid UTF-8", i),
                            FFI_ERR_INVALID_ARGUMENT,
                        ),
                    );
                    return FFI_ERR_INVALID_ARGUMENT;
                }
            }
        }

        let policy = DidX509Policy::Eku(oids);
        match DidX509Builder::build_sha256(cert_bytes, &[policy]) {
            Ok(did_string) => match std::ffi::CString::new(did_string) {
                Ok(c_str) => {
                    unsafe {
                        *out_did_string = c_str.into_raw();
                    }
                    FFI_OK
                }
                Err(_) => handle_nul_byte(out_error, "DID string"),
            },
            Err(err) => {
                set_error(out_error, ErrorInner::from_did_error(&err));
                FFI_ERR_BUILD_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "building"),
    }
}
///
/// # Safety
///
/// - `ca_cert_der` must be valid for reads of `ca_cert_len` bytes
/// - `eku_oids` must be an array of `eku_count` valid null-terminated C strings
/// - `out_did_string` must be valid for writes
/// - Caller is responsible for freeing the returned string via `did_x509_string_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_build_with_eku(
    ca_cert_der: *const u8,
    ca_cert_len: u32,
    eku_oids: *const *const libc::c_char,
    eku_count: u32,
    out_did_string: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_build_with_eku_inner(
        ca_cert_der,
        ca_cert_len,
        eku_oids,
        eku_count,
        out_did_string,
        out_error,
    )
}

/// Inner implementation for did_x509_build_from_chain.
pub fn impl_build_from_chain_inner(
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_did_string: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_did_string.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_did_string"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_did_string = ptr::null_mut();
        }

        if chain_certs.is_null() || chain_cert_lens.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("chain_certs/chain_cert_lens"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        if chain_count == 0 {
            set_error(
                out_error,
                ErrorInner::new("chain_count must be > 0", FFI_ERR_INVALID_ARGUMENT),
            );
            return FFI_ERR_INVALID_ARGUMENT;
        }

        // Collect certificate slices
        let mut certs: Vec<&[u8]> = Vec::new();
        for i in 0..chain_count {
            let cert_ptr = unsafe { *chain_certs.add(i as usize) };
            let cert_len = unsafe { *chain_cert_lens.add(i as usize) };
            if cert_ptr.is_null() && cert_len > 0 {
                set_error(
                    out_error,
                    ErrorInner::new(format!("chain_certs[{}] is null", i), FFI_ERR_NULL_POINTER),
                );
                return FFI_ERR_NULL_POINTER;
            }
            let cert_slice = if cert_ptr.is_null() {
                &[] as &[u8]
            } else {
                unsafe { slice::from_raw_parts(cert_ptr, cert_len as usize) }
            };
            certs.push(cert_slice);
        }

        match DidX509Builder::build_from_chain_with_eku(&certs) {
            Ok(did_string) => match std::ffi::CString::new(did_string) {
                Ok(c_str) => {
                    unsafe {
                        *out_did_string = c_str.into_raw();
                    }
                    FFI_OK
                }
                Err(_) => handle_nul_byte(out_error, "DID string"),
            },
            Err(err) => {
                set_error(out_error, ErrorInner::from_did_error(&err));
                FFI_ERR_BUILD_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "building from chain"),
    }
}
/// Build DID:x509 from cert chain (leaf-first) with auto EKU extraction.
///
/// # Safety
///
/// - `chain_certs` must be an array of `chain_count` pointers to certificate DER data
/// - `chain_cert_lens` must be an array of `chain_count` certificate lengths
/// - `out_did_string` must be valid for writes
/// - Caller is responsible for freeing the returned string via `did_x509_string_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_build_from_chain(
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_did_string: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_build_from_chain_inner(
        chain_certs,
        chain_cert_lens,
        chain_count,
        out_did_string,
        out_error,
    )
}

// ============================================================================
// Validation functions
// ============================================================================

/// Inner implementation for did_x509_validate.
pub fn impl_validate_inner(
    did_string: *const libc::c_char,
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_is_valid: *mut i32,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_is_valid.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_is_valid"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_is_valid = 0;
        }

        if did_string.is_null() {
            set_error(out_error, ErrorInner::null_pointer("did_string"));
            return FFI_ERR_NULL_POINTER;
        }

        if chain_certs.is_null() || chain_cert_lens.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("chain_certs/chain_cert_lens"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        if chain_count == 0 {
            set_error(
                out_error,
                ErrorInner::new("chain_count must be > 0", FFI_ERR_INVALID_ARGUMENT),
            );
            return FFI_ERR_INVALID_ARGUMENT;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(did_string) };
        let did_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid UTF-8 in DID string", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Collect certificate slices
        let mut certs: Vec<&[u8]> = Vec::new();
        for i in 0..chain_count {
            let cert_ptr = unsafe { *chain_certs.add(i as usize) };
            let cert_len = unsafe { *chain_cert_lens.add(i as usize) };
            if cert_ptr.is_null() && cert_len > 0 {
                set_error(
                    out_error,
                    ErrorInner::new(format!("chain_certs[{}] is null", i), FFI_ERR_NULL_POINTER),
                );
                return FFI_ERR_NULL_POINTER;
            }
            let cert_slice = if cert_ptr.is_null() {
                &[] as &[u8]
            } else {
                unsafe { slice::from_raw_parts(cert_ptr, cert_len as usize) }
            };
            certs.push(cert_slice);
        }

        match DidX509Validator::validate(did_str, &certs) {
            Ok(result) => {
                unsafe {
                    *out_is_valid = if result.is_valid { 1 } else { 0 };
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_did_error(&err));
                FFI_ERR_VALIDATE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "validation"),
    }
}

/// Validate DID against certificate chain.
///
/// # Safety
///
/// - `did_string` must be a valid null-terminated C string
/// - `chain_certs` must be an array of `chain_count` pointers to certificate DER data
/// - `chain_cert_lens` must be an array of `chain_count` certificate lengths
/// - `out_is_valid` must be valid for writes (set to 1 if valid, 0 if invalid)
#[no_mangle]
pub unsafe extern "C" fn did_x509_validate(
    did_string: *const libc::c_char,
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_is_valid: *mut i32,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_validate_inner(
        did_string,
        chain_certs,
        chain_cert_lens,
        chain_count,
        out_is_valid,
        out_error,
    )
}

// ============================================================================
// Resolution functions
// ============================================================================

/// Inner implementation for did_x509_resolve.
pub fn impl_resolve_inner(
    did_string: *const libc::c_char,
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_did_document_json: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_did_document_json.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_did_document_json"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_did_document_json = ptr::null_mut();
        }

        if did_string.is_null() {
            set_error(out_error, ErrorInner::null_pointer("did_string"));
            return FFI_ERR_NULL_POINTER;
        }

        if chain_certs.is_null() || chain_cert_lens.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("chain_certs/chain_cert_lens"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        if chain_count == 0 {
            set_error(
                out_error,
                ErrorInner::new("chain_count must be > 0", FFI_ERR_INVALID_ARGUMENT),
            );
            return FFI_ERR_INVALID_ARGUMENT;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(did_string) };
        let did_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid UTF-8 in DID string", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Collect certificate slices
        let mut certs: Vec<&[u8]> = Vec::new();
        for i in 0..chain_count {
            let cert_ptr = unsafe { *chain_certs.add(i as usize) };
            let cert_len = unsafe { *chain_cert_lens.add(i as usize) };
            if cert_ptr.is_null() && cert_len > 0 {
                set_error(
                    out_error,
                    ErrorInner::new(format!("chain_certs[{}] is null", i), FFI_ERR_NULL_POINTER),
                );
                return FFI_ERR_NULL_POINTER;
            }
            let cert_slice = if cert_ptr.is_null() {
                &[] as &[u8]
            } else {
                unsafe { slice::from_raw_parts(cert_ptr, cert_len as usize) }
            };
            certs.push(cert_slice);
        }

        match DidX509Resolver::resolve(did_str, &certs) {
            Ok(did_document) => match serde_json::to_string(&did_document) {
                Ok(json_str) => match std::ffi::CString::new(json_str) {
                    Ok(c_str) => {
                        unsafe {
                            *out_did_document_json = c_str.into_raw();
                        }
                        FFI_OK
                    }
                    Err(_) => handle_nul_byte(out_error, "DID document JSON"),
                },
                Err(err) => {
                    set_error(
                        out_error,
                        ErrorInner::new(
                            format!("JSON serialization failed: {}", err),
                            FFI_ERR_RESOLVE_FAILED,
                        ),
                    );
                    FFI_ERR_RESOLVE_FAILED
                }
            },
            Err(err) => {
                set_error(out_error, ErrorInner::from_did_error(&err));
                FFI_ERR_RESOLVE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "resolution"),
    }
}

/// Resolve DID to JSON DID Document.
///
/// # Safety
///
/// - `did_string` must be a valid null-terminated C string
/// - `chain_certs` must be an array of `chain_count` pointers to certificate DER data
/// - `chain_cert_lens` must be an array of `chain_count` certificate lengths
/// - `out_did_document_json` must be valid for writes
/// - Caller is responsible for freeing the returned string via `did_x509_string_free`
#[no_mangle]
pub unsafe extern "C" fn did_x509_resolve(
    did_string: *const libc::c_char,
    chain_certs: *const *const u8,
    chain_cert_lens: *const u32,
    chain_count: u32,
    out_did_document_json: *mut *mut libc::c_char,
    out_error: *mut *mut DidX509ErrorHandle,
) -> i32 {
    impl_resolve_inner(
        did_string,
        chain_certs,
        chain_cert_lens,
        chain_count,
        out_did_document_json,
        out_error,
    )
}
