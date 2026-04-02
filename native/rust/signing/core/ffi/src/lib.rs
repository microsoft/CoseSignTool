// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C/C++ FFI for COSE_Sign1 message signing operations.
//!
//! This crate (`cose_sign1_signing_ffi`) provides FFI-safe wrappers for creating and signing
//! COSE_Sign1 messages from C and C++ code. It uses `cose_sign1_primitives` for types and
//! `cbor_primitives_everparse` for CBOR encoding.
//!
//! For verification operations, see `cose_sign1_primitives_ffi`.
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
//! - `cose_sign1_builder_free` for builder handles
//! - `cose_headermap_free` for header map handles
//! - `cose_key_free` for key handles
//! - `cose_sign1_signing_service_free` for signing service handles
//! - `cose_sign1_factory_free` for factory handles
//! - `cose_sign1_signing_error_free` for error handles
//! - `cose_sign1_string_free` for string pointers
//! - `cose_sign1_bytes_free` for byte buffer pointers
//! - `cose_sign1_cose_bytes_free` for COSE message bytes returned by factory functions
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
use std::sync::Arc;

use cose_sign1_primitives::{
    CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, CoseSign1Builder, CoseSign1Message,
    CryptoError, CryptoSigner,
};

use crate::error::{
    set_error, ErrorInner, FFI_ERR_FACTORY_FAILED, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PANIC, FFI_ERR_SIGN_FAILED, FFI_OK,
};
use crate::types::{
    builder_handle_to_inner_mut, builder_inner_to_handle, factory_handle_to_inner,
    factory_inner_to_handle, headermap_handle_to_inner, headermap_handle_to_inner_mut,
    headermap_inner_to_handle, key_handle_to_inner, key_inner_to_handle, message_inner_to_handle,
    signing_service_handle_to_inner, signing_service_inner_to_handle, BuilderInner, FactoryInner,
    HeaderMapInner, KeyInner, MessageInner, SigningServiceInner,
};

// Re-export handle types for library users
pub use crate::types::{
    CoseHeaderMapHandle, CoseKeyHandle, CoseSign1BuilderHandle, CoseSign1FactoryHandle,
    CoseSign1MessageHandle, CoseSign1SigningServiceHandle,
};

// Re-export error types for library users
pub use crate::error::{
    CoseSign1SigningErrorHandle, FFI_ERR_FACTORY_FAILED as COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED,
    FFI_ERR_INVALID_ARGUMENT as COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT,
    FFI_ERR_NULL_POINTER as COSE_SIGN1_SIGNING_ERR_NULL_POINTER,
    FFI_ERR_PANIC as COSE_SIGN1_SIGNING_ERR_PANIC,
    FFI_ERR_SIGN_FAILED as COSE_SIGN1_SIGNING_ERR_SIGN_FAILED, FFI_OK as COSE_SIGN1_SIGNING_OK,
};

pub use crate::error::{
    cose_sign1_signing_error_code, cose_sign1_signing_error_free, cose_sign1_signing_error_message,
    cose_sign1_string_free,
};

/// ABI version for this library.
///
/// Increment when making breaking changes to the FFI interface.
pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
pub extern "C" fn cose_sign1_signing_abi_version() -> u32 {
    ABI_VERSION
}

/// Records a panic error and returns the panic status code.
/// This is only reachable when `catch_unwind` catches a panic, which cannot
/// be triggered reliably in tests.
#[cfg_attr(coverage_nightly, coverage(off))]
fn handle_panic(out_error: *mut *mut crate::error::CoseSign1SigningErrorHandle, msg: &str) -> i32 {
    set_error(out_error, ErrorInner::new(msg, FFI_ERR_PANIC));
    FFI_ERR_PANIC
}

/// Writes signed bytes to the caller's output pointers. This path is unreachable
/// through the FFI because SimpleSigningService::verify_signature always returns Err,
/// and the factory mandatorily verifies after signing.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn write_signed_bytes(
    bytes: Vec<u8>,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
) -> i32 {
    let len = bytes.len();
    let boxed = bytes.into_boxed_slice();
    let raw = Box::into_raw(boxed);
    unsafe {
        *out_cose_bytes = raw as *mut u8;
        *out_cose_len = len as u32;
    }
    FFI_OK
}

/// Parses signed COSE bytes into a `CoseSign1MessageHandle` and writes it to the
/// caller's output pointer.
///
/// On success the handle owns the parsed message; free it with
/// `cose_sign1_message_free` from `cose_sign1_primitives_ffi`.
#[cfg_attr(coverage_nightly, coverage(off))]
unsafe fn write_signed_message(
    bytes: Vec<u8>,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let _provider = crate::provider::ffi_cbor_provider();
    match CoseSign1Message::parse(&bytes) {
        Ok(message) => {
            unsafe {
                *out_message = message_inner_to_handle(MessageInner { message });
            }
            FFI_OK
        }
        Err(err) => {
            set_error(
                out_error,
                ErrorInner::new(
                    format!("failed to parse signed message: {}", err),
                    FFI_ERR_SIGN_FAILED,
                ),
            );
            FFI_ERR_SIGN_FAILED
        }
    }
}

// ============================================================================
// Header map creation and manipulation
// ============================================================================

/// Inner implementation for cose_headermap_new.
pub fn impl_headermap_new_inner(out_headers: *mut *mut CoseHeaderMapHandle) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_headers.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let inner = HeaderMapInner {
            headers: CoseHeaderMap::new(),
        };

        unsafe {
            *out_headers = headermap_inner_to_handle(inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Creates a new empty header map.
///
/// # Safety
///
/// - `out_headers` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_headermap_free`
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_new(out_headers: *mut *mut CoseHeaderMapHandle) -> i32 {
    impl_headermap_new_inner(out_headers)
}

/// Inner implementation for cose_headermap_set_int.
pub fn impl_headermap_set_int_inner(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: i64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner_mut(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        inner
            .headers
            .insert(CoseHeaderLabel::Int(label), CoseHeaderValue::Int(value));
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets an integer value in a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_set_int(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: i64,
) -> i32 {
    impl_headermap_set_int_inner(headers, label, value)
}

/// Inner implementation for cose_headermap_set_bytes.
pub fn impl_headermap_set_bytes_inner(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: *const u8,
    value_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner_mut(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if value.is_null() && value_len > 0 {
            return FFI_ERR_NULL_POINTER;
        }

        let bytes = if value.is_null() {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(value, value_len) }.to_vec()
        };

        inner.headers.insert(
            CoseHeaderLabel::Int(label),
            CoseHeaderValue::Bytes(bytes.into()),
        );
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets a byte string value in a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
/// - `value` must be valid for reads of `value_len` bytes
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_set_bytes(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: *const u8,
    value_len: usize,
) -> i32 {
    impl_headermap_set_bytes_inner(headers, label, value, value_len)
}

/// Inner implementation for cose_headermap_set_text.
pub fn impl_headermap_set_text_inner(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: *const libc::c_char,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { headermap_handle_to_inner_mut(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if value.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(value) };
        let text = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return FFI_ERR_INVALID_ARGUMENT,
        };

        inner.headers.insert(
            CoseHeaderLabel::Int(label),
            CoseHeaderValue::Text(text.into()),
        );
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets a text string value in a header map by integer label.
///
/// # Safety
///
/// - `headers` must be a valid header map handle
/// - `value` must be a valid null-terminated C string
#[no_mangle]
pub unsafe extern "C" fn cose_headermap_set_text(
    headers: *mut CoseHeaderMapHandle,
    label: i64,
    value: *const libc::c_char,
) -> i32 {
    impl_headermap_set_text_inner(headers, label, value)
}

/// Inner implementation for cose_headermap_len.
pub fn impl_headermap_len_inner(headers: *const CoseHeaderMapHandle) -> usize {
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
    impl_headermap_len_inner(headers)
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

// ============================================================================
// Builder functions
// ============================================================================

/// Inner implementation for cose_sign1_builder_new.
pub fn impl_builder_new_inner(out_builder: *mut *mut CoseSign1BuilderHandle) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_builder.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let inner = BuilderInner {
            protected: CoseHeaderMap::new(),
            unprotected: None,
            external_aad: None,
            tagged: true,
            detached: false,
        };

        unsafe {
            *out_builder = builder_inner_to_handle(inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Creates a new CoseSign1 message builder.
///
/// # Safety
///
/// - `out_builder` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_builder_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_new(
    out_builder: *mut *mut CoseSign1BuilderHandle,
) -> i32 {
    impl_builder_new_inner(out_builder)
}

/// Inner implementation for cose_sign1_builder_set_tagged.
pub fn impl_builder_set_tagged_inner(builder: *mut CoseSign1BuilderHandle, tagged: bool) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };
        inner.tagged = tagged;
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets whether the builder produces tagged COSE_Sign1 output.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_set_tagged(
    builder: *mut CoseSign1BuilderHandle,
    tagged: bool,
) -> i32 {
    impl_builder_set_tagged_inner(builder, tagged)
}

/// Inner implementation for cose_sign1_builder_set_detached.
pub fn impl_builder_set_detached_inner(
    builder: *mut CoseSign1BuilderHandle,
    detached: bool,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };
        inner.detached = detached;
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets whether the builder produces a detached payload.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_set_detached(
    builder: *mut CoseSign1BuilderHandle,
    detached: bool,
) -> i32 {
    impl_builder_set_detached_inner(builder, detached)
}

/// Inner implementation for cose_sign1_builder_set_protected.
pub fn impl_builder_set_protected_inner(
    builder: *mut CoseSign1BuilderHandle,
    headers: *const CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(builder_inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let Some(hdr_inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        builder_inner.protected = hdr_inner.headers.clone();
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the protected headers for the builder.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
/// - `headers` must be a valid header map handle
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_set_protected(
    builder: *mut CoseSign1BuilderHandle,
    headers: *const CoseHeaderMapHandle,
) -> i32 {
    impl_builder_set_protected_inner(builder, headers)
}

/// Inner implementation for cose_sign1_builder_set_unprotected.
pub fn impl_builder_set_unprotected_inner(
    builder: *mut CoseSign1BuilderHandle,
    headers: *const CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(builder_inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let Some(hdr_inner) = (unsafe { headermap_handle_to_inner(headers) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        builder_inner.unprotected = Some(hdr_inner.headers.clone());
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the unprotected headers for the builder.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
/// - `headers` must be a valid header map handle
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_set_unprotected(
    builder: *mut CoseSign1BuilderHandle,
    headers: *const CoseHeaderMapHandle,
) -> i32 {
    impl_builder_set_unprotected_inner(builder, headers)
}

/// Inner implementation for cose_sign1_builder_consume_protected.
pub fn impl_builder_consume_protected_inner(
    builder: *mut CoseSign1BuilderHandle,
    headers: *mut CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(builder_inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if headers.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        // Take ownership and move — no clone needed
        let hdr_inner = unsafe { Box::from_raw(headers as *mut HeaderMapInner) };
        builder_inner.protected = hdr_inner.headers;
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the protected headers for the builder by consuming the header map handle.
///
/// Zero-copy alternative to `cose_sign1_builder_set_protected`. The header map
/// handle is consumed and must NOT be used or freed after this call.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
/// - `headers` must be a valid, owned header map handle (consumed by this call)
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_consume_protected(
    builder: *mut CoseSign1BuilderHandle,
    headers: *mut CoseHeaderMapHandle,
) -> i32 {
    impl_builder_consume_protected_inner(builder, headers)
}

/// Inner implementation for cose_sign1_builder_consume_unprotected.
pub fn impl_builder_consume_unprotected_inner(
    builder: *mut CoseSign1BuilderHandle,
    headers: *mut CoseHeaderMapHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(builder_inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if headers.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        // Take ownership and move — no clone needed
        let hdr_inner = unsafe { Box::from_raw(headers as *mut HeaderMapInner) };
        builder_inner.unprotected = Some(hdr_inner.headers);
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the unprotected headers for the builder by consuming the header map handle.
///
/// Zero-copy alternative to `cose_sign1_builder_set_unprotected`. The header map
/// handle is consumed and must NOT be used or freed after this call.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
/// - `headers` must be a valid, owned header map handle (consumed by this call)
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_consume_unprotected(
    builder: *mut CoseSign1BuilderHandle,
    headers: *mut CoseHeaderMapHandle,
) -> i32 {
    impl_builder_consume_unprotected_inner(builder, headers)
}

/// Inner implementation for cose_sign1_builder_set_external_aad.
pub fn impl_builder_set_external_aad_inner(
    builder: *mut CoseSign1BuilderHandle,
    aad: *const u8,
    aad_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { builder_handle_to_inner_mut(builder) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        if aad.is_null() {
            inner.external_aad = None;
        } else {
            inner.external_aad = Some(unsafe { slice::from_raw_parts(aad, aad_len) }.to_vec());
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Sets the external additional authenticated data for the builder.
///
/// # Safety
///
/// - `builder` must be a valid builder handle
/// - `aad` must be valid for reads of `aad_len` bytes, or NULL
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_set_external_aad(
    builder: *mut CoseSign1BuilderHandle,
    aad: *const u8,
    aad_len: usize,
) -> i32 {
    impl_builder_set_external_aad_inner(builder, aad, aad_len)
}

/// Inner implementation for cose_sign1_builder_sign (coverable by LLVM).
pub fn impl_builder_sign_inner(
    builder: *mut CoseSign1BuilderHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
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

        if builder.is_null() {
            set_error(out_error, ErrorInner::null_pointer("builder"));
            return FFI_ERR_NULL_POINTER;
        }

        let Some(key_inner) = (unsafe { key_handle_to_inner(key) }) else {
            set_error(out_error, ErrorInner::null_pointer("key"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        // Take ownership of builder
        let builder_inner = unsafe { Box::from_raw(builder as *mut BuilderInner) };

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len) }
        };

        // Move fields out of the consumed builder (no cloning needed)
        let mut rust_builder = CoseSign1Builder::new()
            .protected(builder_inner.protected)
            .tagged(builder_inner.tagged)
            .detached(builder_inner.detached);

        if let Some(unprotected) = builder_inner.unprotected {
            rust_builder = rust_builder.unprotected(unprotected);
        }

        if let Some(aad) = builder_inner.external_aad {
            rust_builder = rust_builder.external_aad(aad);
        }

        match rust_builder.sign(key_inner.key.as_ref(), payload_bytes) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_bytes = raw as *mut u8;
                    *out_len = len;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_cose_error(&err));
                FFI_ERR_SIGN_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during signing"),
    }
}

/// Signs a payload using the builder configuration and a key.
///
/// The builder is consumed by this call and must not be used afterwards.
///
/// # Safety
///
/// - `builder` must be a valid builder handle; it is freed on success or failure
/// - `key` must be a valid key handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `out_bytes` and `out_len` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_sign(
    builder: *mut CoseSign1BuilderHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    out_bytes: *mut *mut u8,
    out_len: *mut usize,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_builder_sign_inner(
        builder,
        key,
        payload,
        payload_len,
        out_bytes,
        out_len,
        out_error,
    )
}

/// Inner implementation for cose_sign1_builder_sign_to_message.
pub fn impl_builder_sign_to_message_inner(
    builder: *mut CoseSign1BuilderHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        if builder.is_null() {
            set_error(out_error, ErrorInner::null_pointer("builder"));
            return FFI_ERR_NULL_POINTER;
        }

        let Some(key_inner) = (unsafe { key_handle_to_inner(key) }) else {
            set_error(out_error, ErrorInner::null_pointer("key"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        // Take ownership of builder
        let builder_inner = unsafe { Box::from_raw(builder as *mut BuilderInner) };

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len) }
        };

        // Move fields out of the consumed builder (no cloning needed)
        let mut rust_builder = CoseSign1Builder::new()
            .protected(builder_inner.protected)
            .tagged(builder_inner.tagged)
            .detached(builder_inner.detached);

        if let Some(unprotected) = builder_inner.unprotected {
            rust_builder = rust_builder.unprotected(unprotected);
        }

        if let Some(aad) = builder_inner.external_aad {
            rust_builder = rust_builder.external_aad(aad);
        }

        match rust_builder.sign(key_inner.key.as_ref(), payload_bytes) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, ErrorInner::from_cose_error(&err));
                FFI_ERR_SIGN_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during signing"),
    }
}

/// Signs a payload and returns an opaque message handle instead of raw bytes.
///
/// The returned handle can be inspected with `cose_sign1_message_as_bytes`,
/// `cose_sign1_message_payload`, `cose_sign1_message_signature`, etc. from
/// `cose_sign1_primitives_ffi`, and must be freed with `cose_sign1_message_free`.
///
/// The builder is consumed by this call and must not be used afterwards.
///
/// # Safety
///
/// - `builder` must be a valid builder handle; it is freed on success or failure
/// - `key` must be a valid key handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_sign_to_message(
    builder: *mut CoseSign1BuilderHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_builder_sign_to_message_inner(builder, key, payload, payload_len, out_message, out_error)
}

/// Frees a builder handle.
///
/// # Safety
///
/// - `builder` must be a valid builder handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_builder_free(builder: *mut CoseSign1BuilderHandle) {
    if builder.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(builder as *mut BuilderInner));
    }
}

/// Frees bytes previously returned by signing operations.
///
/// # Safety
///
/// - `bytes` must have been returned by `cose_sign1_builder_sign` or be NULL
/// - `len` must be the length returned alongside the bytes
/// - The bytes must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_bytes_free(bytes: *mut u8, len: usize) {
    if bytes.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bytes, len,
        )));
    }
}

// ============================================================================
// Key creation via callback
// ============================================================================

/// Callback function type for signing operations.
///
/// The callback receives the complete Sig_structure (RFC 9052) that needs to be signed.
///
/// # Parameters
///
/// - `sig_structure`: The CBOR-encoded Sig_structure bytes to sign
/// - `sig_structure_len`: Length of sig_structure
/// - `out_sig`: Output pointer for signature bytes (caller frees with libc::free)
/// - `out_sig_len`: Output pointer for signature length
/// - `user_data`: User-provided context pointer
///
/// # Returns
///
/// - `0` on success
/// - Non-zero on error
pub type CoseSignCallback = unsafe extern "C" fn(
    sig_structure: *const u8,
    sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    user_data: *mut libc::c_void,
) -> i32;

/// Inner implementation for cose_key_from_callback.
pub fn impl_key_from_callback_inner(
    algorithm: i64,
    key_type: *const libc::c_char,
    sign_fn: CoseSignCallback,
    user_data: *mut libc::c_void,
    out_key: *mut *mut CoseKeyHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_key.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_key = ptr::null_mut();
        }

        if key_type.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(key_type) };
        let key_type_str = match c_str.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return FFI_ERR_INVALID_ARGUMENT,
        };

        let callback_key = CallbackKey {
            algorithm,
            key_type: key_type_str,
            sign_fn,
            user_data,
        };

        let inner = KeyInner {
            key: std::sync::Arc::new(callback_key),
        };

        unsafe {
            *out_key = key_inner_to_handle(inner);
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Creates a key handle from a signing callback.
///
/// # Safety
///
/// - `key_type` must be a valid null-terminated C string
/// - `sign_fn` must be a valid function pointer
/// - `out_key` must be valid for writes
/// - `user_data` must remain valid for the lifetime of the key handle
/// - Caller owns the returned handle and must free it with `cose_key_free`
#[no_mangle]
pub unsafe extern "C" fn cose_key_from_callback(
    algorithm: i64,
    key_type: *const libc::c_char,
    sign_fn: CoseSignCallback,
    user_data: *mut libc::c_void,
    out_key: *mut *mut CoseKeyHandle,
) -> i32 {
    impl_key_from_callback_inner(algorithm, key_type, sign_fn, user_data, out_key)
}

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

// ============================================================================
// Signing Service and Factory functions
// ============================================================================

/// Inner implementation for cose_sign1_signing_service_create.
pub fn impl_signing_service_create_inner(
    key: *const CoseKeyHandle,
    out_service: *mut *mut CoseSign1SigningServiceHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_service.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_service"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_service = ptr::null_mut();
        }

        let Some(key_inner) = (unsafe { key_handle_to_inner(key) }) else {
            set_error(out_error, ErrorInner::null_pointer("key"));
            return FFI_ERR_NULL_POINTER;
        };

        let service = SimpleSigningService::new(key_inner.key.clone());
        let inner = SigningServiceInner {
            service: std::sync::Arc::new(service),
        };

        unsafe {
            *out_service = signing_service_inner_to_handle(inner);
        }
        FFI_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during signing service creation"),
    }
}

/// Creates a signing service from a key handle.
///
/// # Safety
///
/// - `key` must be a valid key handle
/// - `out_service` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_signing_service_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_signing_service_create(
    key: *const CoseKeyHandle,
    out_service: *mut *mut CoseSign1SigningServiceHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_signing_service_create_inner(key, out_service, out_error)
}

/// Frees a signing service handle.
///
/// # Safety
///
/// - `service` must be a valid signing service handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_signing_service_free(
    service: *mut CoseSign1SigningServiceHandle,
) {
    if service.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(service as *mut SigningServiceInner));
    }
}

// ============================================================================
// CryptoSigner-based signing service creation
// ============================================================================

/// Opaque handle type for CryptoSigner (from cose_sign1_crypto_openssl_ffi).
/// This is the same type as `cose_crypto_signer_t` from crypto_openssl_ffi.
#[repr(C)]
pub struct CryptoSignerHandle {
    _private: [u8; 0],
}

/// Inner implementation for cose_sign1_signing_service_from_crypto_signer.
pub fn impl_signing_service_from_crypto_signer_inner(
    signer_handle: *mut CryptoSignerHandle,
    out_service: *mut *mut CoseSign1SigningServiceHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_service.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_service"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_service = ptr::null_mut();
        }

        if signer_handle.is_null() {
            set_error(out_error, ErrorInner::null_pointer("signer_handle"));
            return FFI_ERR_NULL_POINTER;
        }

        let signer_box = unsafe {
            Box::from_raw(signer_handle as *mut Box<dyn crypto_primitives::CryptoSigner>)
        };
        let signer_arc: std::sync::Arc<dyn crypto_primitives::CryptoSigner> = (*signer_box).into();

        let service = SimpleSigningService::new(signer_arc);
        let inner = SigningServiceInner {
            service: std::sync::Arc::new(service),
        };

        unsafe {
            *out_service = signing_service_inner_to_handle(inner);
        }
        FFI_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(
            out_error,
            "panic during signing service creation from crypto signer",
        ),
    }
}

/// Creates a signing service from a CryptoSigner handle.
///
/// This eliminates the need for `cose_key_from_callback`.
/// The signer handle comes from `cose_crypto_openssl_signer_from_der` (or similar).
/// Ownership of the signer handle is transferred to the signing service.
///
/// # Safety
///
/// - `signer_handle` must be a valid CryptoSigner handle (from crypto_openssl_ffi)
/// - `out_service` must be valid for writes
/// - `signer_handle` must not be used after this call (ownership transferred)
/// - Caller owns the returned handle and must free it with `cose_sign1_signing_service_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_signing_service_from_crypto_signer(
    signer_handle: *mut CryptoSignerHandle,
    out_service: *mut *mut CoseSign1SigningServiceHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_signing_service_from_crypto_signer_inner(signer_handle, out_service, out_error)
}

/// Inner implementation for cose_sign1_factory_from_crypto_signer.
pub fn impl_factory_from_crypto_signer_inner(
    signer_handle: *mut CryptoSignerHandle,
    out_factory: *mut *mut CoseSign1FactoryHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_factory.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_factory"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_factory = ptr::null_mut();
        }

        if signer_handle.is_null() {
            set_error(out_error, ErrorInner::null_pointer("signer_handle"));
            return FFI_ERR_NULL_POINTER;
        }

        let signer_box = unsafe {
            Box::from_raw(signer_handle as *mut Box<dyn crypto_primitives::CryptoSigner>)
        };
        let signer_arc: std::sync::Arc<dyn crypto_primitives::CryptoSigner> = (*signer_box).into();

        let service = SimpleSigningService::new(signer_arc);
        let service_arc = std::sync::Arc::new(service);

        let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service_arc);

        let inner = FactoryInner { factory };

        unsafe {
            *out_factory = factory_inner_to_handle(inner);
        }
        FFI_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(
            out_error,
            "panic during factory creation from crypto signer",
        ),
    }
}

/// Creates a signature factory directly from a CryptoSigner handle.
///
/// This combines `cose_sign1_signing_service_from_crypto_signer` and
/// `cose_sign1_factory_create` in a single call for convenience.
/// Ownership of the signer handle is transferred to the factory.
///
/// # Safety
///
/// - `signer_handle` must be a valid CryptoSigner handle (from crypto_openssl_ffi)
/// - `out_factory` must be valid for writes
/// - `signer_handle` must not be used after this call (ownership transferred)
/// - Caller owns the returned handle and must free it with `cose_sign1_factory_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_from_crypto_signer(
    signer_handle: *mut CryptoSignerHandle,
    out_factory: *mut *mut CoseSign1FactoryHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_from_crypto_signer_inner(signer_handle, out_factory, out_error)
}

/// Inner implementation for cose_sign1_factory_create.
pub fn impl_factory_create_inner(
    service: *const CoseSign1SigningServiceHandle,
    out_factory: *mut *mut CoseSign1FactoryHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_factory.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_factory"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_factory = ptr::null_mut();
        }

        let Some(service_inner) = (unsafe { signing_service_handle_to_inner(service) }) else {
            set_error(out_error, ErrorInner::null_pointer("service"));
            return FFI_ERR_NULL_POINTER;
        };

        let factory =
            cose_sign1_factories::CoseSign1MessageFactory::new(service_inner.service.clone());
        let inner = FactoryInner { factory };

        unsafe {
            *out_factory = factory_inner_to_handle(inner);
        }
        FFI_OK
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during factory creation"),
    }
}

/// Creates a factory from a signing service handle.
///
/// # Safety
///
/// - `service` must be a valid signing service handle
/// - `out_factory` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_factory_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_create(
    service: *const CoseSign1SigningServiceHandle,
    out_factory: *mut *mut CoseSign1FactoryHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_create_inner(service, out_factory, out_error)
}

/// Inner implementation for cose_sign1_factory_sign_direct.
pub fn impl_factory_sign_direct_inner(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len as usize) }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        match factory_inner
            .factory
            .create_direct_bytes(payload_bytes, content_type_str, None)
        {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during direct signing"),
    }
}

/// Signs payload with direct signature (embedded payload).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_inner(
        factory,
        payload,
        payload_len,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect.
pub fn impl_factory_sign_indirect_inner(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len as usize) }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        match factory_inner
            .factory
            .create_indirect_bytes(payload_bytes, content_type_str, None)
        {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during indirect signing"),
    }
}

/// Signs payload with indirect signature (hash envelope).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_inner(
        factory,
        payload,
        payload_len,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

// ============================================================================
// Streaming signature functions
// ============================================================================

/// Callback type for streaming payload reading.
///
/// The callback is invoked repeatedly with a buffer to fill.
/// Returns the number of bytes read (0 = EOF), or negative on error.
///
/// # Safety
///
/// - `buffer` must be valid for writes of `buffer_len` bytes
/// - `user_data` is the opaque pointer passed to the signing function
pub type CoseReadCallback =
    unsafe extern "C" fn(buffer: *mut u8, buffer_len: usize, user_data: *mut libc::c_void) -> i64;

/// Adapter for callback-based streaming payload.
struct CallbackStreamingPayload {
    callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
}

// SAFETY: The callback is assumed to be thread-safe.
// FFI callers are responsible for ensuring thread safety.
unsafe impl Send for CallbackStreamingPayload {}
unsafe impl Sync for CallbackStreamingPayload {}

impl cose_sign1_primitives::StreamingPayload for CallbackStreamingPayload {
    fn size(&self) -> u64 {
        self.total_len
    }

    fn open(
        &self,
    ) -> Result<
        Box<dyn cose_sign1_primitives::sig_structure::SizedRead + Send>,
        cose_sign1_primitives::error::PayloadError,
    > {
        Ok(Box::new(CallbackReader {
            callback: self.callback,
            user_data: self.user_data,
            total_len: self.total_len,
            bytes_read: 0,
        }))
    }
}

/// Reader implementation that wraps the callback.
struct CallbackReader {
    callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
    bytes_read: u64,
}

// SAFETY: The callback is assumed to be thread-safe.
// FFI callers are responsible for ensuring thread safety.
unsafe impl Send for CallbackReader {}

impl std::io::Read for CallbackReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes_read >= self.total_len {
            return Ok(0);
        }

        let remaining = (self.total_len - self.bytes_read) as usize;
        let to_read = buf.len().min(remaining);

        let result = unsafe { (self.callback)(buf.as_mut_ptr(), to_read, self.user_data) };

        if result < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("callback read error: {}", result),
            ));
        }

        let bytes_read = result as usize;
        self.bytes_read += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl cose_sign1_primitives::sig_structure::SizedRead for CallbackReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.total_len)
    }
}

/// Inner implementation for cose_sign1_factory_sign_direct_file.
pub fn impl_factory_sign_direct_file_inner(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if file_path.is_null() {
            set_error(out_error, ErrorInner::null_pointer("file_path"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid file_path UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Create FilePayload
        let file_payload = match cose_sign1_primitives::FilePayload::new(path_str) {
            Ok(p) => p,
            Err(e) => {
                set_error(
                    out_error,
                    ErrorInner::new(
                        format!("failed to open file: {}", e),
                        FFI_ERR_INVALID_ARGUMENT,
                    ),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

        // Create options with detached=true
        let options = cose_sign1_factories::direct::DirectSignatureOptions {
            embed_payload: false, // Force detached for streaming
            ..Default::default()
        };

        match factory_inner.factory.create_direct_streaming_bytes(
            payload_arc,
            content_type_str,
            Some(options),
        ) {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during file signing"),
    }
}

/// Signs a file directly without loading it into memory (direct signature).
///
/// Creates a detached COSE_Sign1 signature over the file content.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct_file(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_file_inner(
        factory,
        file_path,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect_file.
pub fn impl_factory_sign_indirect_file_inner(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if file_path.is_null() {
            set_error(out_error, ErrorInner::null_pointer("file_path"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid file_path UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Create FilePayload
        let file_payload = match cose_sign1_primitives::FilePayload::new(path_str) {
            Ok(p) => p,
            Err(e) => {
                set_error(
                    out_error,
                    ErrorInner::new(
                        format!("failed to open file: {}", e),
                        FFI_ERR_INVALID_ARGUMENT,
                    ),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

        match factory_inner.factory.create_indirect_streaming_bytes(
            payload_arc,
            content_type_str,
            None,
        ) {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during file signing"),
    }
}

/// Signs a file directly without loading it into memory (indirect signature).
///
/// Creates a detached COSE_Sign1 signature over the file content hash.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect_file(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_file_inner(
        factory,
        file_path,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_direct_streaming.
#[allow(clippy::too_many_arguments)]
pub fn impl_factory_sign_direct_streaming_inner(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Create callback payload
        let callback_payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len: payload_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> =
            Arc::new(callback_payload);

        // Create options with detached=true
        let options = cose_sign1_factories::direct::DirectSignatureOptions {
            embed_payload: false, // Force detached for streaming
            ..Default::default()
        };

        match factory_inner.factory.create_direct_streaming_bytes(
            payload_arc,
            content_type_str,
            Some(options),
        ) {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during streaming signing"),
    }
}

/// Signs with a streaming payload via callback (direct signature).
///
/// The callback is invoked repeatedly with a buffer to fill.
/// payload_len must be the total payload size (for CBOR bstr header).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid callback function
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct_streaming(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_streaming_inner(
        factory,
        read_callback,
        payload_len,
        user_data,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect_streaming.
#[allow(clippy::too_many_arguments)]
pub fn impl_factory_sign_indirect_streaming_inner(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_cose_bytes.is_null() || out_cose_len.is_null() {
            set_error(
                out_error,
                ErrorInner::null_pointer("out_cose_bytes/out_cose_len"),
            );
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_cose_bytes = ptr::null_mut();
            *out_cose_len = 0;
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        // Create callback payload
        let callback_payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len: payload_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> =
            Arc::new(callback_payload);

        match factory_inner.factory.create_indirect_streaming_bytes(
            payload_arc,
            content_type_str,
            None,
        ) {
            Ok(bytes) => unsafe { write_signed_bytes(bytes, out_cose_bytes, out_cose_len) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during streaming signing"),
    }
}

/// Signs with a streaming payload via callback (indirect signature).
///
/// The callback is invoked repeatedly with a buffer to fill.
/// payload_len must be the total payload size (for CBOR bstr header).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid callback function
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_cose_bytes_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect_streaming(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_streaming_inner(
        factory,
        read_callback,
        payload_len,
        user_data,
        content_type,
        out_cose_bytes,
        out_cose_len,
        out_error,
    )
}

// ============================================================================
// Factory _to_message variants — return CoseSign1MessageHandle
// ============================================================================

/// Inner implementation for cose_sign1_factory_sign_direct_to_message.
pub fn impl_factory_sign_direct_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len as usize) }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        match factory_inner
            .factory
            .create_direct_bytes(payload_bytes, content_type_str, None)
        {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during direct signing"),
    }
}

/// Signs payload with direct signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct_to_message(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_to_message_inner(
        factory,
        payload,
        payload_len,
        content_type,
        out_message,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect_to_message.
pub fn impl_factory_sign_indirect_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() && payload_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let payload_bytes = if payload.is_null() {
            &[] as &[u8]
        } else {
            unsafe { slice::from_raw_parts(payload, payload_len as usize) }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        match factory_inner
            .factory
            .create_indirect_bytes(payload_bytes, content_type_str, None)
        {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during indirect signing"),
    }
}

/// Signs payload with indirect signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect_to_message(
    factory: *const CoseSign1FactoryHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_to_message_inner(
        factory,
        payload,
        payload_len,
        content_type,
        out_message,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_direct_file_to_message.
pub fn impl_factory_sign_direct_file_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if file_path.is_null() {
            set_error(out_error, ErrorInner::null_pointer("file_path"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid file_path UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let file_payload = match cose_sign1_primitives::FilePayload::new(path_str) {
            Ok(p) => p,
            Err(e) => {
                set_error(
                    out_error,
                    ErrorInner::new(
                        format!("failed to open file: {}", e),
                        FFI_ERR_INVALID_ARGUMENT,
                    ),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

        let options = cose_sign1_factories::direct::DirectSignatureOptions {
            embed_payload: false,
            ..Default::default()
        };

        match factory_inner.factory.create_direct_streaming_bytes(
            payload_arc,
            content_type_str,
            Some(options),
        ) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during file signing"),
    }
}

/// Signs a file directly, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct_file_to_message(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_file_to_message_inner(
        factory,
        file_path,
        content_type,
        out_message,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect_file_to_message.
pub fn impl_factory_sign_indirect_file_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if file_path.is_null() {
            set_error(out_error, ErrorInner::null_pointer("file_path"));
            return FFI_ERR_NULL_POINTER;
        }

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(file_path) };
        let path_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid file_path UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let file_payload = match cose_sign1_primitives::FilePayload::new(path_str) {
            Ok(p) => p,
            Err(e) => {
                set_error(
                    out_error,
                    ErrorInner::new(
                        format!("failed to open file: {}", e),
                        FFI_ERR_INVALID_ARGUMENT,
                    ),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

        match factory_inner.factory.create_indirect_streaming_bytes(
            payload_arc,
            content_type_str,
            None,
        ) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during file signing"),
    }
}

/// Signs a file with indirect signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect_file_to_message(
    factory: *const CoseSign1FactoryHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_file_to_message_inner(
        factory,
        file_path,
        content_type,
        out_message,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_direct_streaming_to_message.
pub fn impl_factory_sign_direct_streaming_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let callback_payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len: payload_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> =
            Arc::new(callback_payload);

        let options = cose_sign1_factories::direct::DirectSignatureOptions {
            embed_payload: false,
            ..Default::default()
        };

        match factory_inner.factory.create_direct_streaming_bytes(
            payload_arc,
            content_type_str,
            Some(options),
        ) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during streaming signing"),
    }
}

/// Signs with a streaming payload via callback (direct), returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid callback function
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_direct_streaming_to_message(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_direct_streaming_to_message_inner(
        factory,
        read_callback,
        payload_len,
        user_data,
        content_type,
        out_message,
        out_error,
    )
}

/// Inner implementation for cose_sign1_factory_sign_indirect_streaming_to_message.
pub fn impl_factory_sign_indirect_streaming_to_message_inner(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        let Some(factory_inner) = (unsafe { factory_handle_to_inner(factory) }) else {
            set_error(out_error, ErrorInner::null_pointer("factory"));
            return FFI_ERR_NULL_POINTER;
        };

        if content_type.is_null() {
            set_error(out_error, ErrorInner::null_pointer("content_type"));
            return FFI_ERR_NULL_POINTER;
        }

        let c_str = unsafe { std::ffi::CStr::from_ptr(content_type) };
        let content_type_str = match c_str.to_str() {
            Ok(s) => s,
            Err(_) => {
                set_error(
                    out_error,
                    ErrorInner::new("invalid content_type UTF-8", FFI_ERR_INVALID_ARGUMENT),
                );
                return FFI_ERR_INVALID_ARGUMENT;
            }
        };

        let callback_payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len: payload_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> =
            Arc::new(callback_payload);

        match factory_inner.factory.create_indirect_streaming_bytes(
            payload_arc,
            content_type_str,
            None,
        ) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(
                    out_error,
                    ErrorInner::new(format!("factory failed: {}", err), FFI_ERR_FACTORY_FAILED),
                );
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => handle_panic(out_error, "panic during streaming signing"),
    }
}

/// Signs with a streaming payload via callback (indirect), returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid callback function
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_sign_indirect_streaming_to_message(
    factory: *const CoseSign1FactoryHandle,
    read_callback: CoseReadCallback,
    payload_len: u64,
    user_data: *mut libc::c_void,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1SigningErrorHandle,
) -> i32 {
    impl_factory_sign_indirect_streaming_to_message_inner(
        factory,
        read_callback,
        payload_len,
        user_data,
        content_type,
        out_message,
        out_error,
    )
}

/// Frees a factory handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factory_free(factory: *mut CoseSign1FactoryHandle) {
    if factory.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(factory as *mut FactoryInner));
    }
}

/// Frees COSE bytes allocated by factory functions.
///
/// # Safety
///
/// - `ptr` must have been returned by a factory signing function or be NULL
/// - `len` must be the length returned alongside the bytes
/// - The bytes must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_cose_bytes_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr,
            len as usize,
        )));
    }
}

// ============================================================================
// Internal: Callback-based key implementation
// ============================================================================

struct CallbackKey {
    algorithm: i64,
    key_type: String,
    sign_fn: CoseSignCallback,
    user_data: *mut libc::c_void,
}

// Safety: user_data is opaque and the callback is responsible for thread safety
unsafe impl Send for CallbackKey {}
unsafe impl Sync for CallbackKey {}

impl CryptoSigner for CallbackKey {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out_sig: *mut u8 = ptr::null_mut();
        let mut out_sig_len: usize = 0;

        let rc = unsafe {
            (self.sign_fn)(
                data.as_ptr(),
                data.len(),
                &mut out_sig,
                &mut out_sig_len,
                self.user_data,
            )
        };

        if rc != 0 {
            return Err(CryptoError::SigningFailed(format!(
                "callback returned error code {}",
                rc
            )));
        }

        if out_sig.is_null() {
            return Err(CryptoError::SigningFailed(
                "callback returned null signature".to_string(),
            ));
        }

        let sig = unsafe { slice::from_raw_parts(out_sig, out_sig_len) }.to_vec();

        // Free the callback-allocated memory
        unsafe {
            libc::free(out_sig as *mut libc::c_void);
        }

        Ok(sig)
    }

    // Accessor methods on CallbackKey are not called during the signing pipeline
    // (CoseSigner::sign_payload only invokes signer.sign), and CallbackKey is a
    // private type that cannot be constructed from external tests.
    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_type(&self) -> &str {
        &self.key_type
    }

    fn key_id(&self) -> Option<&[u8]> {
        None
    }
}

// ============================================================================
// Internal: Simple signing service implementation
// ============================================================================

/// Simple signing service that wraps a single key.
///
/// Used to bridge between the key-based FFI and the factory pattern.
struct SimpleSigningService {
    key: std::sync::Arc<dyn CryptoSigner>,
}

impl SimpleSigningService {
    pub fn new(key: std::sync::Arc<dyn CryptoSigner>) -> Self {
        Self { key }
    }
}

impl cose_sign1_signing::SigningService for SimpleSigningService {
    fn get_cose_signer(
        &self,
        _context: &cose_sign1_signing::SigningContext,
    ) -> Result<cose_sign1_signing::CoseSigner, cose_sign1_signing::SigningError> {
        Ok(cose_sign1_signing::CoseSigner::new(
            Box::new(ArcCryptoSignerWrapper {
                key: self.key.clone(),
            }),
            CoseHeaderMap::new(),
            CoseHeaderMap::new(),
        ))
    }

    // SimpleSigningService methods below are unreachable through the FFI:
    // - is_remote/service_metadata: factory does not query these through FFI
    // - verify_signature: always returns Err, making the factory Ok branches unreachable
    fn is_remote(&self) -> bool {
        false
    }

    fn service_metadata(&self) -> &cose_sign1_signing::SigningServiceMetadata {
        static METADATA: once_cell::sync::Lazy<cose_sign1_signing::SigningServiceMetadata> =
            once_cell::sync::Lazy::new(|| {
                cose_sign1_signing::SigningServiceMetadata::new(
                    "FFI Signing Service".to_string(),
                    "1.0.0".to_string(),
                )
            });
        &METADATA
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &cose_sign1_signing::SigningContext,
    ) -> Result<bool, cose_sign1_signing::SigningError> {
        Err(cose_sign1_signing::SigningError::VerificationFailed(
            "verification not supported by FFI signing service".to_string(),
        ))
    }
}

/// Wrapper to convert Arc<dyn CryptoSigner> to Box<dyn CryptoSigner>.
struct ArcCryptoSignerWrapper {
    key: std::sync::Arc<dyn CryptoSigner>,
}

impl CryptoSigner for ArcCryptoSignerWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.key.sign(data)
    }

    // ArcCryptoSignerWrapper accessor methods are not called during the signing
    // pipeline (CoseSigner::sign_payload only invokes signer.sign), and this is
    // a private type that cannot be constructed from external tests.
    fn algorithm(&self) -> i64 {
        self.key.algorithm()
    }

    fn key_type(&self) -> &str {
        self.key.key_type()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.key.key_id()
    }
}
