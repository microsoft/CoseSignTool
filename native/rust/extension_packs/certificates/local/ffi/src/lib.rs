// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! FFI bindings for local certificate creation and loading.
//!
//! This crate provides C-compatible FFI exports for the `cose_sign1_certificates_local` crate,
//! enabling certificate creation, chain building, and certificate loading from C/C++ code.

use cose_sign1_certificates_local::{
    CertificateChainFactory, CertificateChainOptions, CertificateFactory, CertificateOptions,
    EphemeralCertificateFactory, KeyAlgorithm, SoftwareKeyProvider,
};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

static ABI_VERSION: u32 = 1;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

pub fn set_last_error(message: impl Into<String>) {
    let s = message.into();
    let c = CString::new(s).unwrap_or_else(|_| CString::new("error message contained NUL").unwrap());
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

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum cose_status_t {
    COSE_OK = 0,
    COSE_ERR = 1,
    COSE_PANIC = 2,
    COSE_INVALID_ARG = 3,
}

#[inline(never)]
pub fn with_catch_unwind<F: FnOnce() -> Result<cose_status_t, anyhow::Error>>(f: F) -> cose_status_t {
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

/// Opaque handle for the ephemeral certificate factory.
#[repr(C)]
pub struct cose_cert_local_factory_t {
    factory: EphemeralCertificateFactory,
}

/// Opaque handle for the certificate chain factory.
#[repr(C)]
pub struct cose_cert_local_chain_t {
    factory: CertificateChainFactory,
}

/// Returns the ABI version for this library.
#[no_mangle]
pub extern "C" fn cose_cert_local_ffi_abi_version() -> u32 {
    ABI_VERSION
}

/// Returns a newly-allocated UTF-8 string containing the last error message for the current thread.
///
/// Ownership: caller must free via `cose_string_free`.
#[no_mangle]
pub extern "C" fn cose_cert_local_last_error_message_utf8() -> *mut c_char {
    take_last_error_ptr()
}

/// Clears the last error for the current thread.
#[no_mangle]
pub extern "C" fn cose_cert_local_last_error_clear() {
    clear_last_error();
}

/// Frees a string previously returned by this library.
///
/// # Safety
///
/// - `s` must be a string allocated by this library or null
/// - The string must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_cert_local_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}

/// Creates a new ephemeral certificate factory.
///
/// # Safety
///
/// - `out` must be a valid, non-null pointer
/// - Caller must free the result with `cose_cert_local_factory_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_factory_new(out: *mut *mut cose_cert_local_factory_t) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }

        let key_provider = Box::new(SoftwareKeyProvider::new());
        let factory = EphemeralCertificateFactory::new(key_provider);
        let handle = cose_cert_local_factory_t { factory };
        let boxed = Box::new(handle);
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Frees an ephemeral certificate factory.
///
/// # Safety
///
/// - `factory` must be a valid handle returned by `cose_cert_local_factory_new` or null
#[no_mangle]
pub extern "C" fn cose_cert_local_factory_free(factory: *mut cose_cert_local_factory_t) {
    if factory.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(factory));
    }
}

fn string_from_ptr(arg_name: &'static str, s: *const c_char) -> Result<String, anyhow::Error> {
    if s.is_null() {
        anyhow::bail!("{arg_name} must not be null");
    }
    let s = unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("{arg_name} must be valid UTF-8"))?;
    Ok(s.to_string())
}

/// Creates a certificate with custom options.
///
/// # Safety
///
/// - `factory` must be a valid handle
/// - `subject` must be a valid UTF-8 null-terminated string
/// - `out_cert_der`, `out_cert_len`, `out_key_der`, `out_key_len` must be valid, non-null pointers
/// - Caller must free the certificate and key bytes with `cose_cert_local_bytes_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_factory_create_cert(
    factory: *const cose_cert_local_factory_t,
    subject: *const c_char,
    algorithm: u32,
    key_size: u32,
    validity_secs: u64,
    out_cert_der: *mut *mut u8,
    out_cert_len: *mut usize,
    out_key_der: *mut *mut u8,
    out_key_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_cert_der.is_null() || out_cert_len.is_null() || out_key_der.is_null() || out_key_len.is_null() {
            anyhow::bail!("output pointers must not be null");
        }

        let factory = unsafe { factory.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("factory must not be null"))?;
        
        let subject_str = string_from_ptr("subject", subject)?;
        
        let key_alg = match algorithm {
            0 => KeyAlgorithm::Rsa,
            1 => KeyAlgorithm::Ecdsa,
            #[cfg(feature = "pqc")]
            2 => KeyAlgorithm::MlDsa,
            _ => anyhow::bail!("invalid algorithm value: {}", algorithm),
        };

        let opts = CertificateOptions::new()
            .with_subject_name(&subject_str)
            .with_key_algorithm(key_alg)
            .with_key_size(key_size)
            .with_validity(std::time::Duration::from_secs(validity_secs));

        let cert = factory.factory.create_certificate(opts)
            .map_err(|e| anyhow::anyhow!("certificate creation failed: {}", e))?;

        let cert_der = cert.cert_der.clone();
        let key_der = cert.private_key_der.clone()
            .ok_or_else(|| anyhow::anyhow!("certificate does not have a private key"))?;

        // Get lengths before boxing
        let cert_len = cert_der.len();
        let key_len = key_der.len();

        // Allocate and transfer ownership to caller
        let cert_boxed = cert_der.into_boxed_slice();
        let cert_ptr = Box::into_raw(cert_boxed);

        let key_boxed = key_der.into_boxed_slice();
        let key_ptr = Box::into_raw(key_boxed);

        unsafe {
            *out_cert_der = (*cert_ptr).as_mut_ptr();
            *out_cert_len = cert_len;
            *out_key_der = (*key_ptr).as_mut_ptr();
            *out_key_len = key_len;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Creates a self-signed certificate with default options.
///
/// # Safety
///
/// - `factory` must be a valid handle
/// - `out_cert_der`, `out_cert_len`, `out_key_der`, `out_key_len` must be valid, non-null pointers
/// - Caller must free the certificate and key bytes with `cose_cert_local_bytes_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_factory_create_self_signed(
    factory: *const cose_cert_local_factory_t,
    out_cert_der: *mut *mut u8,
    out_cert_len: *mut usize,
    out_key_der: *mut *mut u8,
    out_key_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_cert_der.is_null() || out_cert_len.is_null() || out_key_der.is_null() || out_key_len.is_null() {
            anyhow::bail!("output pointers must not be null");
        }

        let factory = unsafe { factory.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("factory must not be null"))?;

        let cert = factory.factory.create_certificate_default()
            .map_err(|e| anyhow::anyhow!("certificate creation failed: {}", e))?;

        let cert_der = cert.cert_der.clone();
        let key_der = cert.private_key_der.clone()
            .ok_or_else(|| anyhow::anyhow!("certificate does not have a private key"))?;

        // Get lengths before boxing
        let cert_len = cert_der.len();
        let key_len = key_der.len();

        // Allocate and transfer ownership to caller
        let cert_boxed = cert_der.into_boxed_slice();
        let cert_ptr = Box::into_raw(cert_boxed);

        let key_boxed = key_der.into_boxed_slice();
        let key_ptr = Box::into_raw(key_boxed);

        unsafe {
            *out_cert_der = (*cert_ptr).as_mut_ptr();
            *out_cert_len = cert_len;
            *out_key_der = (*key_ptr).as_mut_ptr();
            *out_key_len = key_len;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Creates a new certificate chain factory.
///
/// # Safety
///
/// - `out` must be a valid, non-null pointer
/// - Caller must free the result with `cose_cert_local_chain_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_chain_new(out: *mut *mut cose_cert_local_chain_t) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }

        let key_provider = Box::new(SoftwareKeyProvider::new());
        let cert_factory = EphemeralCertificateFactory::new(key_provider);
        let chain_factory = CertificateChainFactory::new(cert_factory);
        let handle = cose_cert_local_chain_t { factory: chain_factory };
        let boxed = Box::new(handle);
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Frees a certificate chain factory.
///
/// # Safety
///
/// - `chain_factory` must be a valid handle returned by `cose_cert_local_chain_new` or null
#[no_mangle]
pub extern "C" fn cose_cert_local_chain_free(chain_factory: *mut cose_cert_local_chain_t) {
    if chain_factory.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(chain_factory));
    }
}

/// Creates a certificate chain.
///
/// # Safety
///
/// - `chain_factory` must be a valid handle
/// - `out_certs_data`, `out_certs_lengths`, `out_certs_count` must be valid, non-null pointers
/// - `out_keys_data`, `out_keys_lengths`, `out_keys_count` must be valid, non-null pointers
/// - Caller must free each certificate and key with `cose_cert_local_bytes_free`
/// - Caller must free the arrays themselves with `cose_cert_local_array_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_chain_create(
    chain_factory: *const cose_cert_local_chain_t,
    algorithm: u32,
    include_intermediate: bool,
    out_certs_data: *mut *mut *mut u8,
    out_certs_lengths: *mut *mut usize,
    out_certs_count: *mut usize,
    out_keys_data: *mut *mut *mut u8,
    out_keys_lengths: *mut *mut usize,
    out_keys_count: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_certs_data.is_null() || out_certs_lengths.is_null() || out_certs_count.is_null() {
            anyhow::bail!("certificate output pointers must not be null");
        }
        if out_keys_data.is_null() || out_keys_lengths.is_null() || out_keys_count.is_null() {
            anyhow::bail!("key output pointers must not be null");
        }

        let chain_factory = unsafe { chain_factory.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("chain_factory must not be null"))?;

        let key_alg = match algorithm {
            0 => KeyAlgorithm::Rsa,
            1 => KeyAlgorithm::Ecdsa,
            #[cfg(feature = "pqc")]
            2 => KeyAlgorithm::MlDsa,
            _ => anyhow::bail!("invalid algorithm value: {}", algorithm),
        };

        let opts = CertificateChainOptions::new()
            .with_key_algorithm(key_alg)
            .with_intermediate_name(if include_intermediate {
                Some("CN=Ephemeral Intermediate CA")
            } else {
                None
            });

        let chain = chain_factory.factory.create_chain_with_options(opts)
            .map_err(|e| anyhow::anyhow!("chain creation failed: {}", e))?;

        let count = chain.len();
        
        // Allocate arrays for certificate data pointers and lengths
        let mut cert_ptrs = Vec::with_capacity(count);
        let mut cert_lens = Vec::with_capacity(count);
        let mut key_ptrs = Vec::with_capacity(count);
        let mut key_lens = Vec::with_capacity(count);

        for cert in chain {
            // Certificate DER
            let cert_der_vec = cert.cert_der;
            let cert_len = cert_der_vec.len();
            let cert_boxed = cert_der_vec.into_boxed_slice();
            let cert_box_ptr = Box::into_raw(cert_boxed);
            cert_ptrs.push(unsafe { (*cert_box_ptr).as_mut_ptr() });
            cert_lens.push(cert_len);

            // Private key DER (may be None)
            if let Some(key_der) = cert.private_key_der {
                let key_len = key_der.len();
                let key_boxed = key_der.into_boxed_slice();
                let key_box_ptr = Box::into_raw(key_boxed);
                key_ptrs.push(unsafe { (*key_box_ptr).as_mut_ptr() });
                key_lens.push(key_len);
            } else {
                key_ptrs.push(ptr::null_mut());
                key_lens.push(0);
            }
        }

        // Transfer arrays to caller
        let certs_data_boxed = cert_ptrs.into_boxed_slice();
        let certs_lengths_boxed = cert_lens.into_boxed_slice();
        let keys_data_boxed = key_ptrs.into_boxed_slice();
        let keys_lengths_boxed = key_lens.into_boxed_slice();

        unsafe {
            *out_certs_data = Box::into_raw(certs_data_boxed) as *mut *mut u8;
            *out_certs_lengths = Box::into_raw(certs_lengths_boxed) as *mut usize;
            *out_certs_count = count;
            *out_keys_data = Box::into_raw(keys_data_boxed) as *mut *mut u8;
            *out_keys_lengths = Box::into_raw(keys_lengths_boxed) as *mut usize;
            *out_keys_count = count;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Loads a certificate from PEM-encoded data.
///
/// # Safety
///
/// - `pem_data` must be a valid pointer to `pem_len` bytes
/// - `out_cert_der`, `out_cert_len`, `out_key_der`, `out_key_len` must be valid, non-null pointers
/// - Caller must free the certificate and key bytes with `cose_cert_local_bytes_free`
/// - If no private key is present, `*out_key_der` will be null and `*out_key_len` will be 0
#[no_mangle]
pub extern "C" fn cose_cert_local_load_pem(
    pem_data: *const u8,
    pem_len: usize,
    out_cert_der: *mut *mut u8,
    out_cert_len: *mut usize,
    out_key_der: *mut *mut u8,
    out_key_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if pem_data.is_null() {
            anyhow::bail!("pem_data must not be null");
        }
        if out_cert_der.is_null() || out_cert_len.is_null() || out_key_der.is_null() || out_key_len.is_null() {
            anyhow::bail!("output pointers must not be null");
        }

        let pem_bytes = unsafe { std::slice::from_raw_parts(pem_data, pem_len) };
        
        let cert = cose_sign1_certificates_local::loaders::pem::load_cert_from_pem_bytes(pem_bytes)
            .map_err(|e| anyhow::anyhow!("PEM load failed: {}", e))?;

        let cert_der = cert.cert_der.clone();
        let cert_len = cert_der.len();
        let cert_boxed = cert_der.into_boxed_slice();
        let cert_ptr = Box::into_raw(cert_boxed);

        unsafe {
            *out_cert_der = (*cert_ptr).as_mut_ptr();
            *out_cert_len = cert_len;
        }

        if let Some(key_der) = cert.private_key_der {
            let key_len = key_der.len();
            let key_boxed = key_der.into_boxed_slice();
            let key_ptr = Box::into_raw(key_boxed);
            unsafe {
                *out_key_der = (*key_ptr).as_mut_ptr();
                *out_key_len = key_len;
            }
        } else {
            unsafe {
                *out_key_der = ptr::null_mut();
                *out_key_len = 0;
            }
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Loads a certificate from DER-encoded data.
///
/// # Safety
///
/// - `cert_data` must be a valid pointer to `cert_len` bytes
/// - `out_cert_der`, `out_cert_len` must be valid, non-null pointers
/// - Caller must free the certificate bytes with `cose_cert_local_bytes_free`
#[no_mangle]
pub extern "C" fn cose_cert_local_load_der(
    cert_data: *const u8,
    cert_len: usize,
    out_cert_der: *mut *mut u8,
    out_cert_len: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if cert_data.is_null() {
            anyhow::bail!("cert_data must not be null");
        }
        if out_cert_der.is_null() || out_cert_len.is_null() {
            anyhow::bail!("output pointers must not be null");
        }

        let cert_bytes = unsafe { std::slice::from_raw_parts(cert_data, cert_len) };
        
        let cert = cose_sign1_certificates_local::loaders::der::load_cert_from_der_bytes(cert_bytes)
            .map_err(|e| anyhow::anyhow!("DER load failed: {}", e))?;

        let cert_der = cert.cert_der.clone();
        let cert_len_out = cert_der.len();
        let cert_boxed = cert_der.into_boxed_slice();
        let cert_ptr = Box::into_raw(cert_boxed);

        unsafe {
            *out_cert_der = (*cert_ptr).as_mut_ptr();
            *out_cert_len = cert_len_out;
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Frees bytes allocated by this library.
///
/// # Safety
///
/// - `ptr` must be a pointer allocated by this library or null
/// - `len` must be the length originally returned
/// - The bytes must not be used after this call
#[no_mangle]
pub unsafe extern "C" fn cose_cert_local_bytes_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice as *mut [u8]));
    }
}

/// Frees arrays of pointers allocated by chain functions.
///
/// # Safety
///
/// - `ptr` must be a pointer allocated by this library or null
/// - `len` must be the length originally returned
#[no_mangle]
pub unsafe extern "C" fn cose_cert_local_array_free(ptr: *mut *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice as *mut [*mut u8]));
    }
}

/// Frees arrays of size_t values allocated by chain functions.
///
/// # Safety
///
/// - `ptr` must be a pointer allocated by this library or null
/// - `len` must be the length originally returned
#[no_mangle]
pub unsafe extern "C" fn cose_cert_local_lengths_array_free(ptr: *mut usize, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice as *mut [usize]));
    }
}
