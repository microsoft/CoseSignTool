// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! C-ABI projection for `cose_sign1_crypto_openssl`.
//!
//! This crate provides C-compatible FFI exports for the OpenSSL crypto provider,
//! allowing C and C++ code to create cryptographic signers and verifiers backed by
//! OpenSSL. It supports DER- and PEM-encoded keys, JWK-based EC and RSA verifiers,
//! and provides the core signing and verification primitives used by the COSE_Sign1
//! signing pipeline.
//!
//! # ABI Stability
//!
//! All exported functions use `extern "C"` calling convention.
//! Opaque handle types are passed as `*mut` (owned) or `*const` (borrowed).
//! The ABI version is available via `cose_crypto_openssl_abi_version()`.
//!
//! # Panic Safety
//!
//! All exported functions are wrapped in `catch_unwind` to prevent
//! Rust panics from crossing the FFI boundary.
//!
//! # Error Handling
//!
//! Functions return `cose_status_t` (0 = OK, non-zero = error).
//! Thread-local error storage: retrieve via `cose_last_error_message_utf8()`.
//! Call `cose_last_error_clear()` to reset error state.
//! Output parameters are only valid if the return value is `COSE_OK`.
//!
//! # Memory Ownership
//!
//! - `*mut T` parameters transfer ownership TO this function (consumed)
//! - `*const T` parameters are borrowed (caller retains ownership)
//! - `*mut *mut T` out-parameters transfer ownership FROM this function (caller must free)
//! - Every handle type has a corresponding `*_free()` function:
//!   - `cose_crypto_openssl_provider_free` for provider handles
//!   - `cose_crypto_signer_free` for signer handles
//!   - `cose_crypto_verifier_free` for verifier handles
//!   - `cose_crypto_bytes_free` for byte buffers
//!   - `cose_string_free` for error message strings
//!
//! # Thread Safety
//!
//! All functions are thread-safe. Error state is thread-local.
//!
//! # Example (C)
//!
//! ```c
//! #include "cose_crypto_openssl_ffi.h"
//!
//! // Create provider
//! cose_crypto_provider_t* provider = NULL;
//! cose_crypto_openssl_provider_new(&provider);
//!
//! // Create signer from DER-encoded private key
//! cose_crypto_signer_t* signer = NULL;
//! cose_crypto_openssl_signer_from_der(provider, key_der, key_len, &signer);
//!
//! // Sign data
//! uint8_t* signature = NULL;
//! size_t sig_len = 0;
//! cose_crypto_signer_sign(signer, data, data_len, &signature, &sig_len);
//!
//! // Clean up
//! cose_crypto_bytes_free(signature, sig_len);
//! cose_crypto_signer_free(signer);
//! cose_crypto_openssl_provider_free(provider);
//! ```

use std::cell::RefCell;
use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use cose_sign1_crypto_openssl::jwk_verifier::OpenSslJwkVerifierFactory;
use cose_sign1_crypto_openssl::OpenSslCryptoProvider;
use crypto_primitives::{
    CryptoProvider, CryptoSigner, CryptoVerifier, EcJwk, JwkVerifierFactory, RsaJwk,
};

// ============================================================================
// Error handling
// ============================================================================

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub fn set_last_error(message: impl Into<String>) {
    let s = message.into();
    let c =
        CString::new(s).unwrap_or_else(|_| CString::new("error message contained NUL").unwrap());
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(c);
    });
}

pub fn clear_last_error() {
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = None;
    });
}

fn take_last_error_ptr() -> *mut c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow_mut()
            .take()
            .map(|c| c.into_raw())
            .unwrap_or(ptr::null_mut())
    })
}

#[inline(never)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn with_catch_unwind<F: FnOnce() -> Result<cose_status_t, anyhow::Error>>(
    f: F,
) -> cose_status_t {
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(status)) => status,
        Ok(Err(err)) => {
            set_last_error(format!("{:#}", err));
            cose_status_t::COSE_ERR
        }
        Err(_) => {
            set_last_error("panic across FFI boundary");
            cose_status_t::COSE_PANIC
        }
    }
}

// ============================================================================
// Status codes
// ============================================================================

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum cose_status_t {
    COSE_OK = 0,
    COSE_ERR = 1,
    COSE_PANIC = 2,
    COSE_INVALID_ARG = 3,
}

pub use cose_status_t::*;

// ============================================================================
// Opaque handle types
// ============================================================================

/// Opaque handle for the OpenSSL crypto provider.
/// Freed with `cose_crypto_openssl_provider_free()`.
#[repr(C)]
pub struct cose_crypto_provider_t {
    _private: [u8; 0],
}

/// Opaque handle for a crypto signer.
/// Freed with `cose_crypto_signer_free()`.
#[repr(C)]
pub struct cose_crypto_signer_t {
    _private: [u8; 0],
}

/// Opaque handle for a crypto verifier.
/// Freed with `cose_crypto_verifier_free()`.
#[repr(C)]
pub struct cose_crypto_verifier_t {
    _private: [u8; 0],
}

// ============================================================================
// ABI version
// ============================================================================

pub const ABI_VERSION: u32 = 1;

/// Returns the ABI version for this library.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_crypto_openssl_abi_version() -> u32 {
    ABI_VERSION
}

// ============================================================================
// Error message retrieval
// ============================================================================

/// Returns a newly-allocated UTF-8 string containing the last error message for the current thread.
///
/// Ownership: caller must free via `cose_string_free`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_last_error_message_utf8() -> *mut c_char {
    take_last_error_ptr()
}

/// Clears the last error message for the current thread.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub extern "C" fn cose_last_error_clear() {
    clear_last_error();
}

/// Frees a string previously returned by this library.
///
/// # Safety
///
/// - `s` must be a string allocated by this library or null
/// - The string must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

// ============================================================================
// Provider functions
// ============================================================================

/// Creates a new OpenSSL crypto provider instance.
///
/// # Safety
///
/// - `out` must be a valid, non-null, aligned pointer
/// - Caller owns the returned handle and must free it with `cose_crypto_openssl_provider_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_provider_new(
    out: *mut *mut cose_crypto_provider_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out pointer must not be null");
        }

        let provider = Box::new(OpenSslCryptoProvider);
        unsafe {
            *out = Box::into_raw(provider) as *mut cose_crypto_provider_t;
        }

        Ok(COSE_OK)
    })
}

/// Frees an OpenSSL crypto provider instance.
///
/// # Safety
///
/// - `provider` must be a provider allocated by this library or null
/// - The provider must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_provider_free(provider: *mut cose_crypto_provider_t) {
    if provider.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(provider as *mut OpenSslCryptoProvider));
    }
}

// ============================================================================
// Signer functions
// ============================================================================

/// Creates a signer from a DER-encoded private key.
///
/// # Safety
///
/// - `provider` must be a valid provider handle
/// - `private_key_der` must be a valid pointer to `len` bytes
/// - `out_signer` must be a valid, non-null, aligned pointer
/// - Caller owns the returned signer and must free it with `cose_crypto_signer_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_signer_from_der(
    provider: *const cose_crypto_provider_t,
    private_key_der: *const u8,
    len: usize,
    out_signer: *mut *mut cose_crypto_signer_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if provider.is_null() {
            anyhow::bail!("provider must not be null");
        }
        if private_key_der.is_null() {
            anyhow::bail!("private_key_der must not be null");
        }
        if out_signer.is_null() {
            anyhow::bail!("out_signer must not be null");
        }

        let provider_ref = unsafe { &*(provider as *const OpenSslCryptoProvider) };
        let key_bytes = unsafe { slice::from_raw_parts(private_key_der, len) };

        let signer = provider_ref
            .signer_from_der(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create signer: {}", e))?;

        unsafe {
            *out_signer = Box::into_raw(signer) as *mut cose_crypto_signer_t;
        }

        Ok(COSE_OK)
    })
}

/// Create a signer from PEM-encoded private key bytes.
///
/// # Safety
///
/// - `provider` must be a valid provider handle
/// - `private_key_pem` must be a valid pointer to `len` bytes of PEM data
/// - `out_signer` must be a valid, non-null, aligned pointer
/// - Caller owns the returned signer and must free it with `cose_crypto_signer_free`
#[no_mangle]
pub unsafe extern "C" fn cose_crypto_openssl_signer_from_pem(
    provider: *const cose_crypto_provider_t,
    private_key_pem: *const u8,
    len: usize,
    out_signer: *mut *mut cose_crypto_signer_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if provider.is_null() {
            anyhow::bail!("provider must not be null");
        }
        if private_key_pem.is_null() {
            anyhow::bail!("private_key_pem must not be null");
        }
        if out_signer.is_null() {
            anyhow::bail!("out_signer must not be null");
        }

        let provider_ref = unsafe { &*(provider as *const OpenSslCryptoProvider) };
        let key_bytes = unsafe { slice::from_raw_parts(private_key_pem, len) };

        let signer = provider_ref
            .signer_from_pem(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create signer from PEM: {}", e))?;

        unsafe {
            *out_signer = Box::into_raw(signer) as *mut cose_crypto_signer_t;
        }

        Ok(COSE_OK)
    })
}

/// Create a verifier from PEM-encoded public key bytes.
///
/// # Safety
///
/// - `provider` must be a valid provider handle
/// - `public_key_pem` must be a valid pointer to `len` bytes of PEM data
/// - `out_verifier` must be a valid, non-null, aligned pointer
/// - Caller owns the returned verifier and must free it with `cose_crypto_verifier_free`
#[no_mangle]
pub unsafe extern "C" fn cose_crypto_openssl_verifier_from_pem(
    provider: *const cose_crypto_provider_t,
    public_key_pem: *const u8,
    len: usize,
    out_verifier: *mut *mut cose_crypto_verifier_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if provider.is_null() {
            anyhow::bail!("provider must not be null");
        }
        if public_key_pem.is_null() {
            anyhow::bail!("public_key_pem must not be null");
        }
        if out_verifier.is_null() {
            anyhow::bail!("out_verifier must not be null");
        }

        let provider_ref = unsafe { &*(provider as *const OpenSslCryptoProvider) };
        let key_bytes = unsafe { slice::from_raw_parts(public_key_pem, len) };

        let verifier = provider_ref
            .verifier_from_pem(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create verifier from PEM: {}", e))?;

        unsafe {
            *out_verifier = Box::into_raw(verifier) as *mut cose_crypto_verifier_t;
        }

        Ok(COSE_OK)
    })
}
///
/// # Safety
///
/// - `signer` must be a valid signer handle
/// - `data` must be a valid pointer to `data_len` bytes
/// - `out_sig` must be a valid, non-null, aligned pointer
/// - `out_sig_len` must be a valid, non-null, aligned pointer
/// - Caller owns the returned signature buffer and must free it with `cose_crypto_bytes_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_signer_sign(
    signer: *const cose_crypto_signer_t,
    data: *const u8,
    data_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if signer.is_null() {
            anyhow::bail!("signer must not be null");
        }
        if data.is_null() {
            anyhow::bail!("data must not be null");
        }
        if out_sig.is_null() {
            anyhow::bail!("out_sig must not be null");
        }
        if out_sig_len.is_null() {
            anyhow::bail!("out_sig_len must not be null");
        }

        let signer_ref = unsafe { &*(signer as *const Box<dyn CryptoSigner>) };
        let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };

        let signature = signer_ref
            .sign(data_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to sign: {}", e))?;

        let sig_len = signature.len();
        let sig_ptr = signature.into_boxed_slice();
        let sig_raw = Box::into_raw(sig_ptr) as *mut u8;

        unsafe {
            *out_sig = sig_raw;
            *out_sig_len = sig_len;
        }

        Ok(COSE_OK)
    })
}

/// Get the COSE algorithm identifier for the signer.
///
/// # Safety
///
/// - `signer` must be a valid signer handle
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_signer_algorithm(signer: *const cose_crypto_signer_t) -> i64 {
    if signer.is_null() {
        return 0;
    }
    let signer_ref = unsafe { &*(signer as *const Box<dyn CryptoSigner>) };
    signer_ref.algorithm()
}

/// Frees a signer instance.
///
/// # Safety
///
/// - `signer` must be a signer allocated by this library or null
/// - The signer must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_signer_free(signer: *mut cose_crypto_signer_t) {
    if signer.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(signer as *mut Box<dyn CryptoSigner>));
    }
}

// ============================================================================
// Verifier functions
// ============================================================================

/// Creates a verifier from a DER-encoded public key.
///
/// # Safety
///
/// - `provider` must be a valid provider handle
/// - `public_key_der` must be a valid pointer to `len` bytes
/// - `out_verifier` must be a valid, non-null, aligned pointer
/// - Caller owns the returned verifier and must free it with `cose_crypto_verifier_free`
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_verifier_from_der(
    provider: *const cose_crypto_provider_t,
    public_key_der: *const u8,
    len: usize,
    out_verifier: *mut *mut cose_crypto_verifier_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if provider.is_null() {
            anyhow::bail!("provider must not be null");
        }
        if public_key_der.is_null() {
            anyhow::bail!("public_key_der must not be null");
        }
        if out_verifier.is_null() {
            anyhow::bail!("out_verifier must not be null");
        }

        let provider_ref = unsafe { &*(provider as *const OpenSslCryptoProvider) };
        let key_bytes = unsafe { slice::from_raw_parts(public_key_der, len) };

        let verifier = provider_ref
            .verifier_from_der(key_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to create verifier: {}", e))?;

        unsafe {
            *out_verifier = Box::into_raw(verifier) as *mut cose_crypto_verifier_t;
        }

        Ok(COSE_OK)
    })
}

/// Verify a signature using the given verifier.
///
/// # Safety
///
/// - `verifier` must be a valid verifier handle
/// - `data` must be a valid pointer to `data_len` bytes
/// - `sig` must be a valid pointer to `sig_len` bytes
/// - `out_valid` must be a valid, non-null, aligned pointer
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_verifier_verify(
    verifier: *const cose_crypto_verifier_t,
    data: *const u8,
    data_len: usize,
    sig: *const u8,
    sig_len: usize,
    out_valid: *mut bool,
) -> cose_status_t {
    with_catch_unwind(|| {
        if verifier.is_null() {
            anyhow::bail!("verifier must not be null");
        }
        if data.is_null() {
            anyhow::bail!("data must not be null");
        }
        if sig.is_null() {
            anyhow::bail!("sig must not be null");
        }
        if out_valid.is_null() {
            anyhow::bail!("out_valid must not be null");
        }

        let verifier_ref = unsafe { &*(verifier as *const Box<dyn CryptoVerifier>) };
        let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
        let sig_bytes = unsafe { slice::from_raw_parts(sig, sig_len) };

        let valid = verifier_ref
            .verify(data_bytes, sig_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to verify: {}", e))?;

        unsafe {
            *out_valid = valid;
        }

        Ok(COSE_OK)
    })
}

/// Frees a verifier instance.
///
/// # Safety
///
/// - `verifier` must be a verifier allocated by this library or null
/// - The verifier must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_verifier_free(verifier: *mut cose_crypto_verifier_t) {
    if verifier.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(verifier as *mut Box<dyn CryptoVerifier>));
    }
}

// ============================================================================
// JWK verifier factory functions
// ============================================================================

/// Helper: reads a non-null C string into a Rust String. Returns Err on null or invalid UTF-8.
fn cstr_to_string(ptr: *const c_char, name: &str) -> Result<String, anyhow::Error> {
    if ptr.is_null() {
        anyhow::bail!("{name} must not be null");
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    cstr.to_str()
        .map(|s| s.to_string())
        .map_err(|_| anyhow::anyhow!("{name} is not valid UTF-8"))
}

/// Creates a crypto verifier from EC JWK public key fields.
///
/// The caller supplies base64url-encoded x/y coordinates, curve name, and COSE algorithm.
///
/// # Safety
///
/// - `crv`, `x`, `y` must be valid, non-null, NUL-terminated UTF-8 C strings.
/// - `kid` may be null (no key ID). If non-null it must be a valid C string.
/// - `out_verifier` must be a valid, non-null, aligned pointer.
/// - Caller owns the returned verifier and must free it with `cose_crypto_verifier_free`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_jwk_verifier_from_ec(
    crv: *const c_char,
    x: *const c_char,
    y: *const c_char,
    kid: *const c_char,
    cose_algorithm: i64,
    out_verifier: *mut *mut cose_crypto_verifier_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_verifier.is_null() {
            anyhow::bail!("out_verifier must not be null");
        }

        let ec_jwk = EcJwk {
            kty: "EC".into(),
            crv: cstr_to_string(crv, "crv")?.into(),
            x: cstr_to_string(x, "x")?.into(),
            y: cstr_to_string(y, "y")?.into(),
            kid: if kid.is_null() {
                None
            } else {
                Some(cstr_to_string(kid, "kid")?.into())
            },
        };

        let factory = OpenSslJwkVerifierFactory;
        let verifier = factory
            .verifier_from_ec_jwk(&ec_jwk, cose_algorithm)
            .map_err(|e| anyhow::anyhow!("EC JWK verifier: {}", e))?;

        unsafe { *out_verifier = Box::into_raw(verifier) as *mut cose_crypto_verifier_t };
        Ok(COSE_OK)
    })
}

/// Creates a crypto verifier from RSA JWK public key fields.
///
/// The caller supplies base64url-encoded modulus (n) and exponent (e), plus a COSE algorithm.
///
/// # Safety
///
/// - `n`, `e` must be valid, non-null, NUL-terminated UTF-8 C strings.
/// - `kid` may be null. If non-null it must be a valid C string.
/// - `out_verifier` must be a valid, non-null, aligned pointer.
/// - Caller owns the returned verifier and must free it with `cose_crypto_verifier_free`.
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_openssl_jwk_verifier_from_rsa(
    n: *const c_char,
    e: *const c_char,
    kid: *const c_char,
    cose_algorithm: i64,
    out_verifier: *mut *mut cose_crypto_verifier_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_verifier.is_null() {
            anyhow::bail!("out_verifier must not be null");
        }

        let rsa_jwk = RsaJwk {
            kty: "RSA".to_string(),
            n: cstr_to_string(n, "n")?,
            e: cstr_to_string(e, "e")?,
            kid: if kid.is_null() {
                None
            } else {
                Some(cstr_to_string(kid, "kid")?)
            },
        };

        let factory = OpenSslJwkVerifierFactory;
        let verifier = factory
            .verifier_from_rsa_jwk(&rsa_jwk, cose_algorithm)
            .map_err(|e| anyhow::anyhow!("RSA JWK verifier: {}", e))?;

        unsafe { *out_verifier = Box::into_raw(verifier) as *mut cose_crypto_verifier_t };
        Ok(COSE_OK)
    })
}

// ============================================================================
// Memory management
// ============================================================================

/// Frees a byte buffer previously returned by this library.
///
/// # Safety
///
/// - `ptr` must be a byte buffer allocated by this library or null
/// - `len` must match the original buffer length
/// - The buffer must not be used after this call
#[no_mangle]
#[cfg_attr(coverage_nightly, coverage(off))]
pub unsafe extern "C" fn cose_crypto_bytes_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}
