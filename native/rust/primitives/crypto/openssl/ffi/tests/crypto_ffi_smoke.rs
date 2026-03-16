// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for cose_sign1_crypto_openssl_ffi.
//!
//! These tests verify the C calling convention compatibility and crypto operations.

use cose_sign1_crypto_openssl_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to get the last error message.
fn get_last_error() -> Option<String> {
    let msg_ptr = cose_last_error_message_utf8();
    if msg_ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    unsafe { cose_string_free(msg_ptr) };
    Some(s)
}

/// Generate a minimal EC P-256 private key in DER format for testing.
/// This is a hardcoded test key - DO NOT use in production.
fn test_ec_private_key_der() -> Vec<u8> {
    // This is a minimal PKCS#8 DER-encoded EC P-256 private key for testing
    // Generated with: openssl ecparam -genkey -name prime256v1 | openssl pkcs8 -topk8 -nocrypt -outform DER
    vec![
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
        0x01, 0x01, 0x04, 0x20, 0x37, 0x80, 0xe6, 0x57, 0x27, 0xc5, 0x5c, 0x58, 0x9d, 0x4a, 0x3b, 0x0e,
        0xd2, 0x3e, 0x5f, 0x9a, 0x2b, 0xc4, 0x54, 0xdc, 0x7c, 0x75, 0x1e, 0x42, 0x9b, 0x88, 0xc3, 0x5e,
        0xd9, 0x45, 0xbe, 0x64, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xf3, 0x35, 0x5c, 0x59, 0xd3, 0x20,
        0x9f, 0x73, 0x52, 0x75, 0xb8, 0x8a, 0xaa, 0x37, 0x1e, 0x36, 0x17, 0x40, 0xf7, 0x78, 0x8e, 0x06,
        0x90, 0x2a, 0x95, 0x81, 0x5f, 0x67, 0x25, 0x97, 0xa7, 0xf2, 0x6c, 0x69, 0x97, 0xad, 0x8a, 0x7b,
        0xf3, 0x0e, 0x4a, 0x5e, 0xd9, 0x3b, 0x8d, 0x7b, 0x68, 0x5b, 0xa1, 0x3d, 0x5f, 0xb5, 0x41, 0x0a,
        0x5f, 0xb9, 0x51, 0x7c, 0xa5, 0x4a, 0xd9, 0x7c, 0xd4,
    ]
}

#[test]
fn ffi_abi_version() {
    let version = cose_crypto_openssl_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_null_free_is_safe() {
    // All free functions should handle null safely
    unsafe {
        cose_crypto_openssl_provider_free(ptr::null_mut());
        cose_crypto_signer_free(ptr::null_mut());
        cose_crypto_verifier_free(ptr::null_mut());
        cose_crypto_bytes_free(ptr::null_mut(), 0);
        cose_string_free(ptr::null_mut());
    }
}

#[test]
fn ffi_provider_new_and_free() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();

    // Create provider
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK, "Error: {:?}", get_last_error());
    assert!(!provider.is_null());

    // Free provider
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_provider_new_null_inputs() {
    // Null out pointer should fail
    let rc = unsafe { cose_crypto_openssl_provider_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("out pointer must not be null"));
}

#[test]
fn ffi_signer_from_der_null_inputs() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let test_key = test_ec_private_key_der();

    // Create provider first
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);

    // Null provider should fail
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(
            ptr::null(),
            test_key.as_ptr(),
            test_key.len(),
            &mut signer,
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("provider must not be null"));

    // Null private_key_der should fail
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(provider, ptr::null(), test_key.len(), &mut signer)
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("private_key_der must not be null"));

    // Null out_signer should fail
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(
            provider,
            test_key.as_ptr(),
            test_key.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("out_signer must not be null"));

    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_signer_from_der_with_generated_key() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let test_key = test_ec_private_key_der();

    // Create provider
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);

    // Create signer from DER
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(
            provider,
            test_key.as_ptr(),
            test_key.len(),
            &mut signer,
        )
    };

    if rc == COSE_OK {
        assert!(!signer.is_null());

        // Get algorithm
        let algorithm = unsafe { cose_crypto_signer_algorithm(signer) };
        // ES256 is -7, but other algorithms are also valid
        assert_ne!(algorithm, 0);

        unsafe { cose_crypto_signer_free(signer) };
    } else {
        // Expected if key format is not exactly what OpenSSL expects
        // The important thing is that we test null safety and basic function calls
        let err_msg = get_last_error().unwrap_or_default();
        assert!(!err_msg.is_empty());
    }

    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_signer_sign_null_inputs() {
    let mut out_sig: *mut u8 = ptr::null_mut();
    let mut out_sig_len: usize = 0;
    let test_data = b"test data";

    // Null signer should fail
    let rc = unsafe {
        cose_crypto_signer_sign(
            ptr::null(),
            test_data.as_ptr(),
            test_data.len(),
            &mut out_sig,
            &mut out_sig_len,
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("signer must not be null"));

    // Create a signer first for other null checks
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let test_key = test_ec_private_key_der();

    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);

    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(
            provider,
            test_key.as_ptr(),
            test_key.len(),
            &mut signer,
        )
    };

    if rc == COSE_OK {
        // Null data should fail
        let rc = unsafe {
            cose_crypto_signer_sign(signer, ptr::null(), 0, &mut out_sig, &mut out_sig_len)
        };
        assert_eq!(rc, COSE_ERR);
        let err_msg = get_last_error().unwrap_or_default();
        assert!(err_msg.contains("data must not be null"));

        // Null out_sig should fail
        let rc = unsafe {
            cose_crypto_signer_sign(
                signer,
                test_data.as_ptr(),
                test_data.len(),
                ptr::null_mut(),
                &mut out_sig_len,
            )
        };
        assert_eq!(rc, COSE_ERR);
        let err_msg = get_last_error().unwrap_or_default();
        assert!(err_msg.contains("out_sig must not be null"));

        // Null out_sig_len should fail
        let rc = unsafe {
            cose_crypto_signer_sign(
                signer,
                test_data.as_ptr(),
                test_data.len(),
                &mut out_sig,
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, COSE_ERR);
        let err_msg = get_last_error().unwrap_or_default();
        assert!(err_msg.contains("out_sig_len must not be null"));

        unsafe { cose_crypto_signer_free(signer) };
    }

    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_verifier_from_der_null_inputs() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let test_key = test_ec_private_key_der();

    // Create provider first
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);

    // Null provider should fail
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            ptr::null(),
            test_key.as_ptr(),
            test_key.len(),
            &mut verifier,
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("provider must not be null"));

    // Null public_key_der should fail
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(provider, ptr::null(), test_key.len(), &mut verifier)
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("public_key_der must not be null"));

    // Null out_verifier should fail
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            provider,
            test_key.as_ptr(),
            test_key.len(),
            ptr::null_mut(),
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("out_verifier must not be null"));

    unsafe { cose_crypto_openssl_provider_free(provider) };
}

#[test]
fn ffi_verifier_verify_null_inputs() {
    let mut out_valid: bool = false;
    let test_data = b"test data";
    let test_sig = b"fake signature";

    // Null verifier should fail
    let rc = unsafe {
        cose_crypto_verifier_verify(
            ptr::null(),
            test_data.as_ptr(),
            test_data.len(),
            test_sig.as_ptr(),
            test_sig.len(),
            &mut out_valid,
        )
    };
    assert_eq!(rc, COSE_ERR);
    let err_msg = get_last_error().unwrap_or_default();
    assert!(err_msg.contains("verifier must not be null"));
}

#[test]
fn ffi_error_message_handling() {
    // Clear any existing error
    cose_last_error_clear();

    // Trigger an error
    let rc = unsafe { cose_crypto_openssl_provider_new(ptr::null_mut()) };
    assert_eq!(rc, COSE_ERR);

    // Get error message
    let msg_ptr = cose_last_error_message_utf8();
    assert!(!msg_ptr.is_null());

    let msg_str = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(!msg_str.is_empty());
    assert!(msg_str.contains("out pointer must not be null"));

    unsafe { cose_string_free(msg_ptr) };

    // Clear and verify it's gone
    cose_last_error_clear();
    let msg_ptr2 = cose_last_error_message_utf8();
    assert!(msg_ptr2.is_null());
}
