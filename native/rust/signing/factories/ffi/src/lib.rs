// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C/C++ FFI for COSE_Sign1 message factories.
//!
//! This crate (`cose_sign1_factories_ffi`) provides FFI-safe wrappers for creating
//! COSE_Sign1 messages using the factory pattern. It supports both direct and indirect
//! signatures, with streaming and file-based payloads.
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
//! - `cose_sign1_factories_free` for factory handles
//! - `cose_sign1_factories_error_free` for error handles
//! - `cose_sign1_factories_string_free` for string pointers
//! - `cose_sign1_factories_bytes_free` for byte buffer pointers

pub mod error;
pub mod provider;
pub mod types;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Arc;

use cose_sign1_primitives::CryptoSigner;

use crate::error::{
    set_error, ErrorInner, FFI_ERR_FACTORY_FAILED, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PANIC, FFI_OK,
};
use crate::types::{
    factory_handle_to_inner, factory_inner_to_handle, message_inner_to_handle,
    signing_service_handle_to_inner, FactoryInner, MessageInner, SigningServiceInner,
};

// Re-export handle types for library users
pub use crate::types::{
    CoseSign1FactoriesHandle, CoseSign1FactoriesSigningServiceHandle,
    CoseSign1FactoriesTransparencyProviderHandle, CoseSign1MessageHandle,
};

// Re-export error types for library users
pub use crate::error::{
    CoseSign1FactoriesErrorHandle,
    FFI_ERR_FACTORY_FAILED as COSE_SIGN1_FACTORIES_ERR_FACTORY_FAILED,
    FFI_ERR_INVALID_ARGUMENT as COSE_SIGN1_FACTORIES_ERR_INVALID_ARGUMENT,
    FFI_ERR_NULL_POINTER as COSE_SIGN1_FACTORIES_ERR_NULL_POINTER,
    FFI_ERR_PANIC as COSE_SIGN1_FACTORIES_ERR_PANIC, FFI_OK as COSE_SIGN1_FACTORIES_OK,
};

pub use crate::error::{
    cose_sign1_factories_error_code, cose_sign1_factories_error_free,
    cose_sign1_factories_error_message, cose_sign1_factories_string_free,
};

/// ABI version for this library.
///
/// Increment when making breaking changes to the FFI interface.
pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_sign1_factories_abi_version() -> u32 {
    ABI_VERSION
}

// ============================================================================
// Inner implementation functions (testable from Rust)
// ============================================================================

/// Inner implementation for cose_sign1_factories_create_from_signing_service.
pub fn impl_create_from_signing_service_inner(
    service: &SigningServiceInner,
) -> Result<FactoryInner, ErrorInner> {
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(service.service.clone());
    Ok(FactoryInner { factory })
}

/// Inner implementation for cose_sign1_factories_create_from_crypto_signer.
pub fn impl_create_from_crypto_signer_inner(
    signer: Arc<dyn crypto_primitives::CryptoSigner>,
) -> Result<FactoryInner, ErrorInner> {
    let service = SimpleSigningService::new(signer);
    let factory = cose_sign1_factories::CoseSign1MessageFactory::new(Arc::new(service));
    Ok(FactoryInner { factory })
}

/// Inner implementation for cose_sign1_factories_create_with_transparency.
pub fn impl_create_with_transparency_inner(
    service: &SigningServiceInner,
    providers: Vec<Box<dyn cose_sign1_signing::transparency::TransparencyProvider>>,
) -> Result<FactoryInner, ErrorInner> {
    let factory = cose_sign1_factories::CoseSign1MessageFactory::with_transparency(
        service.service.clone(),
        providers,
    );
    Ok(FactoryInner { factory })
}

/// Inner implementation for cose_sign1_factories_sign_direct.
pub fn impl_sign_direct_inner(
    factory: &FactoryInner,
    payload: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    factory
        .factory
        .create_direct_bytes(payload, content_type, None)
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_direct_detached.
pub fn impl_sign_direct_detached_inner(
    factory: &FactoryInner,
    payload: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    let options = cose_sign1_factories::direct::DirectSignatureOptions {
        embed_payload: false,
        ..Default::default()
    };

    factory
        .factory
        .create_direct_bytes(payload, content_type, Some(options))
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_direct_file.
pub fn impl_sign_direct_file_inner(
    factory: &FactoryInner,
    file_path: &str,
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    // Create FilePayload
    let file_payload = cose_sign1_primitives::FilePayload::new(file_path).map_err(|e| {
        ErrorInner::new(
            format!("failed to open file: {}", e),
            FFI_ERR_INVALID_ARGUMENT,
        )
    })?;

    let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

    // Create options with detached=true for streaming
    let options = cose_sign1_factories::direct::DirectSignatureOptions {
        embed_payload: false, // Force detached for streaming
        ..Default::default()
    };

    factory
        .factory
        .create_direct_streaming_bytes(payload_arc, content_type, Some(options))
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_direct_streaming.
pub fn impl_sign_direct_streaming_inner(
    factory: &FactoryInner,
    payload: Arc<dyn cose_sign1_primitives::StreamingPayload>,
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    // Create options with detached=true
    let options = cose_sign1_factories::direct::DirectSignatureOptions {
        embed_payload: false,
        ..Default::default()
    };

    factory
        .factory
        .create_direct_streaming_bytes(payload, content_type, Some(options))
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_indirect.
pub fn impl_sign_indirect_inner(
    factory: &FactoryInner,
    payload: &[u8],
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    factory
        .factory
        .create_indirect_bytes(payload, content_type, None)
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_indirect_file.
pub fn impl_sign_indirect_file_inner(
    factory: &FactoryInner,
    file_path: &str,
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    // Create FilePayload
    let file_payload = cose_sign1_primitives::FilePayload::new(file_path).map_err(|e| {
        ErrorInner::new(
            format!("failed to open file: {}", e),
            FFI_ERR_INVALID_ARGUMENT,
        )
    })?;

    let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(file_payload);

    factory
        .factory
        .create_indirect_streaming_bytes(payload_arc, content_type, None)
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

/// Inner implementation for cose_sign1_factories_sign_indirect_streaming.
pub fn impl_sign_indirect_streaming_inner(
    factory: &FactoryInner,
    payload: Arc<dyn cose_sign1_primitives::StreamingPayload>,
    content_type: &str,
) -> Result<Vec<u8>, ErrorInner> {
    factory
        .factory
        .create_indirect_streaming_bytes(payload, content_type, None)
        .map_err(|err| ErrorInner::from_factory_error(&err))
}

// ============================================================================
// CryptoSigner handle type (imported from crypto layer)
// ============================================================================

/// Opaque handle to a CryptoSigner from crypto_primitives.
///
/// This type is defined in the crypto layer and is used to create factories.
#[repr(C)]
pub struct CryptoSignerHandle {
    _private: [u8; 0],
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
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
) -> i32 {
    let _provider = crate::provider::get_provider();
    match cose_sign1_primitives::CoseSign1Message::parse(&bytes) {
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
                    FFI_ERR_FACTORY_FAILED,
                ),
            );
            FFI_ERR_FACTORY_FAILED
        }
    }
}

// ============================================================================
// Factory creation functions
// ============================================================================

/// Creates a factory from a signing service handle.
///
/// # Safety
///
/// - `service` must be a valid signing service handle
/// - `out_factory` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_factories_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_create_from_signing_service(
    service: *const CoseSign1FactoriesSigningServiceHandle,
    out_factory: *mut *mut CoseSign1FactoriesHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_create_from_signing_service_inner(service_inner) {
            Ok(inner) => {
                unsafe {
                    *out_factory = factory_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during factory creation", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Creates a factory from a CryptoSigner handle in a single call.
///
/// This is a convenience function that wraps the signer in a SimpleSigningService
/// and creates a factory. Ownership of the signer handle is transferred to the factory.
///
/// # Safety
///
/// - `signer_handle` must be a valid CryptoSigner handle (from crypto layer)
/// - `out_factory` must be valid for writes
/// - `signer_handle` must not be used after this call (ownership transferred)
/// - Caller owns the returned handle and must free it with `cose_sign1_factories_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_create_from_crypto_signer(
    signer_handle: *mut CryptoSignerHandle,
    out_factory: *mut *mut CoseSign1FactoriesHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_create_from_crypto_signer_inner(signer_arc) {
            Ok(inner) => {
                unsafe {
                    *out_factory = factory_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new(
                    "panic during factory creation from crypto signer",
                    FFI_ERR_PANIC,
                ),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Creates a factory with transparency providers.
///
/// # Safety
///
/// - `service` must be a valid signing service handle
/// - `providers` must be valid for reads of `providers_len` elements
/// - `out_factory` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_factories_free`
/// - Ownership of provider handles is transferred (caller must not free them)
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_create_with_transparency(
    service: *const CoseSign1FactoriesSigningServiceHandle,
    providers: *const *mut CoseSign1FactoriesTransparencyProviderHandle,
    providers_len: usize,
    out_factory: *mut *mut CoseSign1FactoriesHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        if providers.is_null() && providers_len > 0 {
            set_error(out_error, ErrorInner::null_pointer("providers"));
            return FFI_ERR_NULL_POINTER;
        }

        // Convert provider handles to Vec<Box<dyn TransparencyProvider>>
        let mut provider_vec = Vec::new();
        if !providers.is_null() {
            let providers_slice = unsafe { slice::from_raw_parts(providers, providers_len) };
            for &provider_handle in providers_slice {
                if provider_handle.is_null() {
                    set_error(
                        out_error,
                        ErrorInner::new("provider handle must not be null", FFI_ERR_NULL_POINTER),
                    );
                    return FFI_ERR_NULL_POINTER;
                }
                // Take ownership of the provider
                let provider_inner = unsafe {
                    Box::from_raw(provider_handle as *mut crate::types::TransparencyProviderInner)
                };
                provider_vec.push(provider_inner.provider);
            }
        }

        match impl_create_with_transparency_inner(service_inner, provider_vec) {
            Ok(inner) => {
                unsafe {
                    *out_factory = factory_inner_to_handle(inner);
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new(
                    "panic during factory creation with transparency",
                    FFI_ERR_PANIC,
                ),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Frees a factory handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle or NULL
/// - The handle must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_free(factory: *mut CoseSign1FactoriesHandle) {
    if factory.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(factory as *mut FactoryInner));
    }
}

// ============================================================================
// Direct signature functions
// ============================================================================

/// Signs payload with direct signature (embedded payload).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during direct signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs payload with direct signature in detached mode (payload not embedded).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_detached(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_detached_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during detached direct signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs a file directly without loading it into memory (direct signature, detached).
///
/// Creates a detached COSE_Sign1 signature over the file content.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_file(
    factory: *const CoseSign1FactoriesHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_file_inner(factory_inner, path_str, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during file signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

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
pub struct CallbackStreamingPayload {
    pub callback: CoseReadCallback,
    pub user_data: *mut libc::c_void,
    pub total_len: u64,
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
pub struct CallbackReader {
    pub callback: CoseReadCallback,
    pub user_data: *mut libc::c_void,
    pub total_len: u64,
    pub bytes_read: u64,
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

/// Signs a streaming payload with direct signature (detached).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid function pointer
/// - `user_data` will be passed to the callback (can be NULL)
/// - `total_len` must be the total size of the payload
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_streaming(
    factory: *const CoseSign1FactoriesHandle,
    read_callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        let payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(payload);

        match impl_sign_direct_streaming_inner(factory_inner, payload_arc, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during streaming signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

// ============================================================================
// Indirect signature functions
// ============================================================================

/// Signs payload with indirect signature (hash envelope).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_indirect_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs a file with indirect signature (hash envelope) without loading it into memory.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `file_path` must be a valid null-terminated UTF-8 string
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect_file(
    factory: *const CoseSign1FactoriesHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_indirect_file_inner(factory_inner, path_str, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect file signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs a streaming payload with indirect signature (hash envelope).
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid function pointer
/// - `user_data` will be passed to the callback (can be NULL)
/// - `total_len` must be the total size of the payload
/// - `content_type` must be a valid null-terminated C string
/// - `out_cose_bytes` and `out_cose_len` must be valid for writes
/// - Caller must free the returned bytes with `cose_sign1_factories_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect_streaming(
    factory: *const CoseSign1FactoriesHandle,
    read_callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
    content_type: *const libc::c_char,
    out_cose_bytes: *mut *mut u8,
    out_cose_len: *mut u32,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        let payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(payload);

        match impl_sign_indirect_streaming_inner(factory_inner, payload_arc, content_type_str) {
            Ok(bytes) => {
                let len = bytes.len();
                let boxed = bytes.into_boxed_slice();
                let raw = Box::into_raw(boxed);
                unsafe {
                    *out_cose_bytes = raw as *mut u8;
                    *out_cose_len = len as u32;
                }
                FFI_OK
            }
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect streaming signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

// ============================================================================
// Factory _to_message variants — return CoseSign1MessageHandle
// ============================================================================

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
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_to_message(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during direct signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs payload with direct detached signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `payload` must be valid for reads of `payload_len` bytes
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_detached_to_message(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_detached_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during detached direct signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
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
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_file_to_message(
    factory: *const CoseSign1FactoriesHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_direct_file_inner(factory_inner, path_str, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during file signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs a streaming payload with direct signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid function pointer
/// - `user_data` will be passed to the callback (can be NULL)
/// - `total_len` must be the total size of the payload
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factories_sign_direct_streaming_to_message(
    factory: *const CoseSign1FactoriesHandle,
    read_callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        let payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(payload);

        match impl_sign_direct_streaming_inner(factory_inner, payload_arc, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during streaming signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
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
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect_to_message(
    factory: *const CoseSign1FactoriesHandle,
    payload: *const u8,
    payload_len: u32,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_indirect_inner(factory_inner, payload_bytes, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
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
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect_file_to_message(
    factory: *const CoseSign1FactoriesHandle,
    file_path: *const libc::c_char,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        match impl_sign_indirect_file_inner(factory_inner, path_str, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect file signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

/// Signs a streaming payload with indirect signature, returning an opaque message handle.
///
/// # Safety
///
/// - `factory` must be a valid factory handle
/// - `read_callback` must be a valid function pointer
/// - `user_data` will be passed to the callback (can be NULL)
/// - `total_len` must be the total size of the payload
/// - `content_type` must be a valid null-terminated C string
/// - `out_message` must be valid for writes
/// - Caller owns the returned handle and must free it with `cose_sign1_message_free`
#[no_mangle]
pub unsafe extern "C" fn cose_sign1_factories_sign_indirect_streaming_to_message(
    factory: *const CoseSign1FactoriesHandle,
    read_callback: CoseReadCallback,
    user_data: *mut libc::c_void,
    total_len: u64,
    content_type: *const libc::c_char,
    out_message: *mut *mut CoseSign1MessageHandle,
    out_error: *mut *mut CoseSign1FactoriesErrorHandle,
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

        let payload = CallbackStreamingPayload {
            callback: read_callback,
            user_data,
            total_len,
        };

        let payload_arc: Arc<dyn cose_sign1_primitives::StreamingPayload> = Arc::new(payload);

        match impl_sign_indirect_streaming_inner(factory_inner, payload_arc, content_type_str) {
            Ok(bytes) => unsafe { write_signed_message(bytes, out_message, out_error) },
            Err(err) => {
                set_error(out_error, err);
                FFI_ERR_FACTORY_FAILED
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_error(
                out_error,
                ErrorInner::new("panic during indirect streaming signing", FFI_ERR_PANIC),
            );
            FFI_ERR_PANIC
        }
    }
}

// ============================================================================
// Memory management functions
// ============================================================================

/// Frees COSE bytes allocated by factory functions.
///
/// # Safety
///
/// - `ptr` must have been returned by a factory signing function or be NULL
/// - `len` must be the length returned alongside the bytes
/// - The bytes must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_sign1_factories_bytes_free(ptr: *mut u8, len: u32) {
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
// Internal: Simple signing service implementation
// ============================================================================

/// Simple signing service that wraps a single key.
///
/// Used to bridge between the key-based FFI and the factory pattern.
pub struct SimpleSigningService {
    key: std::sync::Arc<dyn CryptoSigner>,
    metadata: cose_sign1_signing::SigningServiceMetadata,
}

impl SimpleSigningService {
    pub fn new(key: std::sync::Arc<dyn CryptoSigner>) -> Self {
        let metadata = cose_sign1_signing::SigningServiceMetadata::new(
            "Simple Signing Service".to_string(),
            "FFI-based signing service wrapping a CryptoSigner".to_string(),
        );
        Self { key, metadata }
    }
}

impl cose_sign1_signing::SigningService for SimpleSigningService {
    fn get_cose_signer(
        &self,
        _context: &cose_sign1_signing::SigningContext,
    ) -> Result<cose_sign1_signing::CoseSigner, cose_sign1_signing::SigningError> {
        use cose_sign1_primitives::CoseHeaderMap;

        // Convert Arc to Box for the signer
        let key_box: Box<dyn CryptoSigner> = Box::new(SimpleKeyWrapper {
            key: self.key.clone(),
        });

        // Create a CoseSigner with empty header maps
        let signer = cose_sign1_signing::CoseSigner::new(
            key_box,
            CoseHeaderMap::new(),
            CoseHeaderMap::new(),
        );
        Ok(signer)
    }

    fn is_remote(&self) -> bool {
        false
    }

    fn service_metadata(&self) -> &cose_sign1_signing::SigningServiceMetadata {
        &self.metadata
    }

    fn verify_signature(
        &self,
        _message_bytes: &[u8],
        _context: &cose_sign1_signing::SigningContext,
    ) -> Result<bool, cose_sign1_signing::SigningError> {
        // Simple service doesn't support verification
        Ok(true)
    }
}

/// Wrapper to convert Arc<dyn CryptoSigner> to Box<dyn CryptoSigner>.
pub struct SimpleKeyWrapper {
    pub key: std::sync::Arc<dyn CryptoSigner>,
}

impl CryptoSigner for SimpleKeyWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, cose_sign1_primitives::CryptoError> {
        self.key.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.key.algorithm()
    }

    fn key_type(&self) -> &str {
        self.key.key_type()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.key.key_id()
    }

    fn supports_streaming(&self) -> bool {
        self.key.supports_streaming()
    }

    fn sign_init(
        &self,
    ) -> Result<Box<dyn crypto_primitives::SigningContext>, cose_sign1_primitives::CryptoError>
    {
        self.key.sign_init()
    }
}
