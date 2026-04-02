// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI functions for CoseSign1Message parsing and verification.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use crate::provider::ffi_cbor_provider;
use cose_sign1_primitives::CoseSign1Message;

use crate::error::{
    set_error, CoseSign1ErrorHandle, ErrorInner, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PANIC, FFI_ERR_PARSE_FAILED, FFI_ERR_PAYLOAD_MISSING, FFI_ERR_VERIFY_FAILED, FFI_OK,
};
use crate::types::{
    key_handle_to_inner, message_handle_to_inner, message_inner_to_handle, CoseKeyHandle,
    CoseSign1MessageHandle, MessageInner,
};

/// Inner implementation for cose_sign1_message_parse (coverable by LLVM).
pub fn message_parse_inner(
    data: *const u8,
    data_len: usize,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_message.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_message"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_message = ptr::null_mut();
        }

        if data.is_null() {
            set_error(out_error, ErrorInner::null_pointer("data"));
            return FFI_ERR_NULL_POINTER;
        }

        let bytes = unsafe { slice::from_raw_parts(data, data_len) };

        let _provider = ffi_cbor_provider();
        match CoseSign1Message::parse(bytes) {
            Ok(message) => {
                let inner = MessageInner { message };
                unsafe {
                    *out_message = message_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_cose_error(&err));
                FFI_ERR_PARSE_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during message parsing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Parses a COSE_Sign1 message from CBOR bytes.
///
/// # Safety
///
/// - `data` must be valid for reads of `data_len` bytes
/// - `out_message` must be valid for writes
/// - Caller owns the returned message handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_parse(
    data: *const u8,
    data_len: usize,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    message_parse_inner(data, data_len, out_message, out_error)
}

/// Frees a message handle.
///
/// # Safety
///
/// - `message` must be a valid message handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_free(message: *mut CoseSign1MessageHandle) {
    if message.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(message as *mut MessageInner));
    }
}

/// Inner implementation for cose_sign1_message_protected_bytes.
pub fn message_protected_bytes_inner(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let bytes = inner.message.protected_header_bytes();
        unsafe {
            *out_bytes = bytes.as_ptr();
            *out_len = bytes.len();
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the raw protected header bytes from a message.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - The returned bytes pointer is valid only as long as the message handle is valid
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_protected_bytes(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    message_protected_bytes_inner(message, out_bytes, out_len)
}

/// Inner implementation for cose_sign1_message_signature.
pub fn message_signature_inner(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let bytes = inner.message.signature();
        unsafe {
            *out_bytes = bytes.as_ptr();
            *out_len = bytes.len();
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the signature bytes from a message.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - The returned bytes pointer is valid only as long as the message handle is valid
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_signature(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    message_signature_inner(message, out_bytes, out_len)
}

/// Inner implementation for cose_sign1_message_alg.
pub fn message_alg_inner(message: *const CoseSign1MessageHandle, out_alg: *mut i64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_alg.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        match inner.message.alg() {
            Some(alg) => {
                unsafe {
                    *out_alg = alg;
                }
                FFI_OK
            }
            None => FFI_ERR_INVALID_ARGUMENT,
        }
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the algorithm from the protected headers.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_alg` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_alg(
    message: *const CoseSign1MessageHandle,
    out_alg: *mut i64,
) -> i32 {
    message_alg_inner(message, out_alg)
}

/// Inner implementation for cose_sign1_message_is_detached.
pub fn message_is_detached_inner(message: *const CoseSign1MessageHandle) -> bool {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return false;
        };
        inner.message.is_detached()
    }));

    result.unwrap_or(false)
}

/// Checks if the message has a detached payload.
///
/// # Safety
///
/// - `message` must be a valid message handle
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_is_detached(
    message: *const CoseSign1MessageHandle,
) -> bool {
    message_is_detached_inner(message)
}

/// Inner implementation for cose_sign1_message_payload.
pub fn message_payload_inner(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        match inner.message.payload() {
            Some(payload) => {
                unsafe {
                    *out_bytes = payload.as_ptr();
                    *out_len = payload.len();
                }
                FFI_OK
            }
            None => {
                unsafe {
                    *out_bytes = ptr::null();
                    *out_len = 0;
                }
                FFI_ERR_PAYLOAD_MISSING
            }
        }
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the embedded payload from a message.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - The returned bytes pointer is valid only as long as the message handle is valid
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_payload(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    message_payload_inner(message, out_bytes, out_len)
}

// ============================================================================
// Verification functions - All include external_aad parameter
// ============================================================================

/// Inner implementation for cose_sign1_message_verify (coverable by LLVM).
pub fn message_verify_inner(
    message: *const CoseSign1MessageHandle,
    key: *const CoseKeyHandle,
    external_aad: *const u8,
    external_aad_len: usize,
    out_verified: *mut bool,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_verified.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_verified"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_verified = false;
        }

        let Some(msg_inner) = (unsafe { message_handle_to_inner(message) }) else {
            set_error(out_error, ErrorInner::null_pointer("message"));
            return FFI_ERR_NULL_POINTER;
        };

        let Some(key_inner) = (unsafe { key_handle_to_inner(key) }) else {
            set_error(out_error, ErrorInner::null_pointer("key"));
            return FFI_ERR_NULL_POINTER;
        };

        let aad: Option<&[u8]> = if external_aad.is_null() {
            None
        } else {
            Some(unsafe { slice::from_raw_parts(external_aad, external_aad_len) })
        };

        match msg_inner.message.verify(key_inner.key.as_ref(), aad) {
            Ok(verified) => {
                unsafe {
                    *out_verified = verified;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_cose_error(&err));
                FFI_ERR_VERIFY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during verification", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Verifies a CoseSign1 message with embedded payload.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `key` must be a valid key handle
/// - `external_aad` must be valid for reads of `external_aad_len` bytes if not NULL
/// - `out_verified` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_verify(
    message: *const CoseSign1MessageHandle,
    key: *const CoseKeyHandle,
    external_aad: *const u8,
    external_aad_len: usize,
    out_verified: *mut bool,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    message_verify_inner(
        message,
        key,
        external_aad,
        external_aad_len,
        out_verified,
        out_error,
    )
}

/// Inner implementation for cose_sign1_message_verify_detached (coverable by LLVM).
#[allow(clippy::too_many_arguments)]
pub fn message_verify_detached_inner(
    message: *const CoseSign1MessageHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    external_aad: *const u8,
    external_aad_len: usize,
    out_verified: *mut bool,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_verified.is_null() {
            set_error(out_error, ErrorInner::null_pointer("out_verified"));
            return FFI_ERR_NULL_POINTER;
        }

        unsafe {
            *out_verified = false;
        }

        let Some(msg_inner) = (unsafe { message_handle_to_inner(message) }) else {
            set_error(out_error, ErrorInner::null_pointer("message"));
            return FFI_ERR_NULL_POINTER;
        };

        let Some(key_inner) = (unsafe { key_handle_to_inner(key) }) else {
            set_error(out_error, ErrorInner::null_pointer("key"));
            return FFI_ERR_NULL_POINTER;
        };

        if payload.is_null() {
            set_error(out_error, ErrorInner::null_pointer("payload"));
            return FFI_ERR_NULL_POINTER;
        }

        let payload_bytes = unsafe { slice::from_raw_parts(payload, payload_len) };
        let aad: Option<&[u8]> = if external_aad.is_null() {
            None
        } else {
            Some(unsafe { slice::from_raw_parts(external_aad, external_aad_len) })
        };

        match msg_inner
            .message
            .verify_detached(key_inner.key.as_ref(), payload_bytes, aad)
        {
            Ok(verified) => {
                unsafe {
                    *out_verified = verified;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, ErrorInner::from_cose_error(&err));
                FFI_ERR_VERIFY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during verification", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Verifies a CoseSign1 message with detached payload.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `key` must be a valid key handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `external_aad` must be valid for reads of `external_aad_len` bytes if not NULL
/// - `out_verified` must be valid for writes
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_verify_detached(
    message: *const CoseSign1MessageHandle,
    key: *const CoseKeyHandle,
    payload: *const u8,
    payload_len: usize,
    external_aad: *const u8,
    external_aad_len: usize,
    out_verified: *mut bool,
    out_error: *mut *mut CoseSign1ErrorHandle,
) -> i32 {
    message_verify_detached_inner(
        message,
        key,
        payload,
        payload_len,
        external_aad,
        external_aad_len,
        out_verified,
        out_error,
    )
}

// ============================================================================
// Message byte accessor
// ============================================================================

/// Inner implementation for cose_sign1_message_as_bytes.
pub fn message_as_bytes_inner(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_bytes.is_null() || out_len.is_null() {
            return FFI_ERR_NULL_POINTER;
        }

        let Some(inner) = (unsafe { message_handle_to_inner(message) }) else {
            return FFI_ERR_NULL_POINTER;
        };

        let bytes = inner.message.as_bytes();
        unsafe {
            *out_bytes = bytes.as_ptr();
            *out_len = bytes.len();
        }
        FFI_OK
    }));

    result.unwrap_or(FFI_ERR_PANIC)
}

/// Gets the full COSE_Sign1 message bytes from a handle.
///
/// The returned pointer borrows from the handle's internal storage and is valid
/// only as long as the message handle is alive.
///
/// # Safety
///
/// - `message` must be a valid message handle
/// - `out_bytes` and `out_len` must be valid for writes
/// - The returned bytes pointer is valid only as long as the message handle is valid
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_message_as_bytes(
    message: *const CoseSign1MessageHandle,
    out_bytes: *mut *const u8,
    out_len: *mut usize,
) -> i32 {
    message_as_bytes_inner(message, out_bytes, out_len)
}
