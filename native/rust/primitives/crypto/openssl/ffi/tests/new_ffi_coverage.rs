// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI coverage tests: null safety for all FFI functions,
//! provider lifecycle, and key creation error paths.

use cose_sign1_crypto_openssl_ffi::*;
use std::ffi::CStr;
use std::ptr;

/// Helper to retrieve and consume the last error message.
fn last_error() -> Option<String> {
    let p = cose_last_error_message_utf8();
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
    unsafe { cose_string_free(p) };
    Some(s)
}

#[test]
fn ffi_abi_version_check() {
    assert_eq!(cose_crypto_openssl_abi_version(), ABI_VERSION);
}

#[test]
fn ffi_provider_lifecycle() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);
    assert!(!provider.is_null());
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_signer_from_der_null_provider() {
    let key = vec![0u8; 4];
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(ptr::null(), key.as_ptr(), key.len(), &mut signer)
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("provider must not be null"));
}

#[test]
fn ffi_signer_from_der_null_key() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();

    let rc = unsafe { cose_crypto_openssl_signer_from_der(provider, ptr::null(), 10, &mut signer) };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error()
        .unwrap()
        .contains("private_key_der must not be null"));
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_signer_from_der_null_out() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let key = vec![0u8; 4];

    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(provider, key.as_ptr(), key.len(), ptr::null_mut())
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error()
        .unwrap()
        .contains("out_signer must not be null"));
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_signer_from_invalid_der() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let bad_key = vec![0xFF, 0xFE, 0xFD];

    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(provider, bad_key.as_ptr(), bad_key.len(), &mut signer)
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().is_some());
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_sign_null_signer() {
    let data = b"test";
    let mut out_sig: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = unsafe {
        cose_crypto_signer_sign(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            &mut out_sig,
            &mut out_len,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("signer must not be null"));
}

#[test]
fn ffi_verify_null_verifier() {
    let data = b"test";
    let sig = b"fake";
    let mut valid = false;
    let rc = unsafe {
        cose_crypto_verifier_verify(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            sig.as_ptr(),
            sig.len(),
            &mut valid,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("verifier must not be null"));
}

#[test]
fn ffi_verifier_from_der_null_provider() {
    let key = vec![0u8; 4];
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(ptr::null(), key.as_ptr(), key.len(), &mut verifier)
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("provider must not be null"));
}

#[test]
fn ffi_verifier_from_invalid_der() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let bad_key = vec![0xAB, 0xCD];

    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            provider,
            bad_key.as_ptr(),
            bad_key.len(),
            &mut verifier,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().is_some());
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_verifier_from_der_null_key() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();

    let rc =
        unsafe { cose_crypto_openssl_verifier_from_der(provider, ptr::null(), 10, &mut verifier) };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error()
        .unwrap()
        .contains("public_key_der must not be null"));
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_verifier_from_der_null_out() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let key = vec![0u8; 4];

    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(provider, key.as_ptr(), key.len(), ptr::null_mut())
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error()
        .unwrap()
        .contains("out_verifier must not be null"));
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_verify_null_data() {
    let data = b"test";
    let mut valid = false;
    let rc = unsafe {
        cose_crypto_verifier_verify(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            ptr::null(),
            0,
            &mut valid,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("verifier must not be null"));
}

#[test]
fn ffi_verify_null_out_valid() {
    let data = b"test";
    let sig = b"fake";
    let rc = unsafe {
        cose_crypto_verifier_verify(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            sig.as_ptr(),
            sig.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, COSE_ERR);
    // Verifier null check fires first
    assert!(last_error().unwrap().contains("verifier must not be null"));
}

#[test]
fn ffi_sign_null_data() {
    let mut out_sig: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let rc =
        unsafe { cose_crypto_signer_sign(ptr::null(), ptr::null(), 0, &mut out_sig, &mut out_len) };
    assert_eq!(rc, COSE_ERR);
    // Signer null check fires first
    assert!(last_error().unwrap().contains("signer must not be null"));
}

#[test]
fn ffi_sign_null_out_sig() {
    let data = b"test";
    let mut out_len: usize = 0;
    let rc = unsafe {
        cose_crypto_signer_sign(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            ptr::null_mut(),
            &mut out_len,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("signer must not be null"));
}

#[test]
fn ffi_sign_null_out_len() {
    let data = b"test";
    let mut out_sig: *mut u8 = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_signer_sign(
            ptr::null(),
            data.as_ptr(),
            data.len(),
            &mut out_sig,
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().unwrap().contains("signer must not be null"));
}

#[test]
fn ffi_null_free_is_safe() {
    unsafe {
        cose_crypto_openssl_provider_free(ptr::null_mut());
        cose_crypto_signer_free(ptr::null_mut());
        cose_crypto_verifier_free(ptr::null_mut());
        cose_crypto_bytes_free(ptr::null_mut(), 0);
        cose_string_free(ptr::null_mut());
    }
}

#[test]
fn ffi_provider_new_null_out() {
    let rc = unsafe { cose_crypto_openssl_provider_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error()
        .unwrap()
        .contains("out pointer must not be null"));
}

#[test]
fn ffi_error_clear_and_no_error() {
    cose_last_error_clear();
    let p = cose_last_error_message_utf8();
    assert!(p.is_null(), "no error should be set after clear");
}
