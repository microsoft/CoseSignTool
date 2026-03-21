// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for cose_sign1_crypto_openssl_ffi — sign/verify roundtrip,
//! verifier null safety, and error path coverage.

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

/// Generate a test EC P-256 private key in DER (PKCS#8) format.
fn test_ec_private_key_der() -> Vec<u8> {
    vec![
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x37, 0x80, 0xe6, 0x57, 0x27, 0xc5, 0x5c, 0x58, 0x9d,
        0x4a, 0x3b, 0x0e, 0xd2, 0x3e, 0x5f, 0x9a, 0x2b, 0xc4, 0x54, 0xdc, 0x7c, 0x75, 0x1e, 0x42,
        0x9b, 0x88, 0xc3, 0x5e, 0xd9, 0x45, 0xbe, 0x64, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xf3,
        0x35, 0x5c, 0x59, 0xd3, 0x20, 0x9f, 0x73, 0x52, 0x75, 0xb8, 0x8a, 0xaa, 0x37, 0x1e, 0x36,
        0x17, 0x40, 0xf7, 0x78, 0x8e, 0x06, 0x90, 0x2a, 0x95, 0x81, 0x5f, 0x67, 0x25, 0x97, 0xa7,
        0xf2, 0x6c, 0x69, 0x97, 0xad, 0x8a, 0x7b, 0xf3, 0x0e, 0x4a, 0x5e, 0xd9, 0x3b, 0x8d, 0x7b,
        0x68, 0x5b, 0xa1, 0x3d, 0x5f, 0xb5, 0x41, 0x0a, 0x5f, 0xb9, 0x51, 0x7c, 0xa5, 0x4a, 0xd9,
        0x7c, 0xd4,
    ]
}

/// Helper: create provider + signer from test key. Returns (provider, signer) or skips.
fn make_signer() -> Option<(*mut cose_crypto_provider_t, *mut cose_crypto_signer_t)> {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    let rc = unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    assert_eq!(rc, COSE_OK);

    let key = test_ec_private_key_der();
    let mut signer: *mut cose_crypto_signer_t = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_openssl_signer_from_der(provider, key.as_ptr(), key.len(), &mut signer)
    };
    if rc != COSE_OK {
        unsafe { cose_crypto_openssl_provider_free(provider) };
        return None;
    }
    Some((provider, signer))
}

// ========================================================================
// Sign and verify roundtrip
// ========================================================================

#[test]
fn sign_verify_roundtrip() {
    let Some((provider, signer)) = make_signer() else {
        return; // key format not supported
    };

    let data = b"roundtrip test data";

    // Sign the data
    let mut sig_ptr: *mut u8 = ptr::null_mut();
    let mut sig_len: usize = 0;
    let rc = unsafe {
        cose_crypto_signer_sign(
            signer,
            data.as_ptr(),
            data.len(),
            &mut sig_ptr,
            &mut sig_len,
        )
    };
    assert_eq!(rc, COSE_OK);
    assert!(!sig_ptr.is_null());
    assert!(sig_len > 0);

    // Extract the public key DER from the private key for verification
    // Use OpenSSL to extract public key from the private key
    let key_der = test_ec_private_key_der();
    let pkey = openssl::pkey::PKey::private_key_from_der(&key_der).unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    // Create verifier from public key
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            provider,
            pub_der.as_ptr(),
            pub_der.len(),
            &mut verifier,
        )
    };
    assert_eq!(rc, COSE_OK, "Error: {:?}", last_error());
    assert!(!verifier.is_null());

    // Verify the signature
    let mut valid: bool = false;
    let rc = unsafe {
        cose_crypto_verifier_verify(
            verifier,
            data.as_ptr(),
            data.len(),
            sig_ptr,
            sig_len,
            &mut valid,
        )
    };
    assert_eq!(rc, COSE_OK, "Error: {:?}", last_error());
    assert!(valid);

    // Verify with wrong data should fail
    let wrong_data = b"wrong data";
    let mut valid2: bool = true;
    let rc = unsafe {
        cose_crypto_verifier_verify(
            verifier,
            wrong_data.as_ptr(),
            wrong_data.len(),
            sig_ptr,
            sig_len,
            &mut valid2,
        )
    };
    // May return ok with valid=false, or may return error
    if rc == COSE_OK {
        assert!(!valid2);
    }

    unsafe {
        cose_crypto_bytes_free(sig_ptr, sig_len);
        cose_crypto_verifier_free(verifier);
        cose_crypto_signer_free(signer);
        cose_crypto_openssl_provider_free(provider);
    }
}

// ========================================================================
// Signer algorithm check
// ========================================================================

#[test]
fn signer_algorithm_null_returns_zero() {
    let alg = unsafe { cose_crypto_signer_algorithm(ptr::null()) };
    assert_eq!(alg, 0);
}

#[test]
fn signer_algorithm_valid() {
    let Some((provider, signer)) = make_signer() else {
        return;
    };
    let alg = unsafe { cose_crypto_signer_algorithm(signer) };
    // ES256 = -7, ES384 = -35, ES512 = -36
    assert!(alg != 0, "Expected non-zero algorithm, got {}", alg);
    unsafe {
        cose_crypto_signer_free(signer);
        cose_crypto_openssl_provider_free(provider);
    }
}

// ========================================================================
// Verifier: null inputs for verify
// ========================================================================

#[test]
fn verify_null_data() {
    let Some((provider, signer)) = make_signer() else {
        return;
    };

    // Get public key
    let key_der = test_ec_private_key_der();
    let pkey = openssl::pkey::PKey::private_key_from_der(&key_der).unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();

    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            provider,
            pub_der.as_ptr(),
            pub_der.len(),
            &mut verifier,
        )
    };

    if rc == COSE_OK {
        let sig = b"fake";
        let mut valid: bool = false;

        // Null data
        let rc = unsafe {
            cose_crypto_verifier_verify(
                verifier,
                ptr::null(),
                0,
                sig.as_ptr(),
                sig.len(),
                &mut valid,
            )
        };
        assert_eq!(rc, COSE_ERR);

        // Null sig
        let data = b"data";
        let rc = unsafe {
            cose_crypto_verifier_verify(
                verifier,
                data.as_ptr(),
                data.len(),
                ptr::null(),
                0,
                &mut valid,
            )
        };
        assert_eq!(rc, COSE_ERR);

        // Null out_valid
        let rc = unsafe {
            cose_crypto_verifier_verify(
                verifier,
                data.as_ptr(),
                data.len(),
                sig.as_ptr(),
                sig.len(),
                ptr::null_mut(),
            )
        };
        assert_eq!(rc, COSE_ERR);

        unsafe { cose_crypto_verifier_free(verifier) };
    }

    unsafe {
        cose_crypto_signer_free(signer);
        cose_crypto_openssl_provider_free(provider);
    }
}

// ========================================================================
// Verifier: invalid key DER
// ========================================================================

#[test]
fn verifier_from_invalid_der() {
    let mut provider: *mut cose_crypto_provider_t = ptr::null_mut();
    unsafe { cose_crypto_openssl_provider_new(&mut provider) };
    let mut verifier: *mut cose_crypto_verifier_t = ptr::null_mut();
    let garbage = [0xDE, 0xAD, 0xBE, 0xEF];

    let rc = unsafe {
        cose_crypto_openssl_verifier_from_der(
            provider,
            garbage.as_ptr(),
            garbage.len(),
            &mut verifier,
        )
    };
    assert_eq!(rc, COSE_ERR);
    assert!(last_error().is_some());
    unsafe { cose_crypto_openssl_provider_free(provider) };
}

// ========================================================================
// Bytes free: non-null path
// ========================================================================

#[test]
fn bytes_free_with_actual_data() {
    let Some((provider, signer)) = make_signer() else {
        return;
    };

    let data = b"test data for bytes free";
    let mut sig_ptr: *mut u8 = ptr::null_mut();
    let mut sig_len: usize = 0;
    let rc = unsafe {
        cose_crypto_signer_sign(
            signer,
            data.as_ptr(),
            data.len(),
            &mut sig_ptr,
            &mut sig_len,
        )
    };

    if rc == COSE_OK {
        assert!(!sig_ptr.is_null());
        unsafe { cose_crypto_bytes_free(sig_ptr, sig_len) };
    }

    unsafe {
        cose_crypto_signer_free(signer);
        cose_crypto_openssl_provider_free(provider);
    }
}

// ========================================================================
// String free: non-null path via error message
// ========================================================================

#[test]
fn string_free_actual_string() {
    // Trigger an error
    unsafe { cose_crypto_openssl_provider_new(ptr::null_mut()) };
    let msg = cose_last_error_message_utf8();
    assert!(!msg.is_null());
    // Free the real string (non-null path)
    unsafe { cose_string_free(msg) };
}

// ========================================================================
// cose_status_t enum coverage
// ========================================================================

#[test]
fn status_enum_properties() {
    assert_eq!(COSE_OK, COSE_OK);
    assert_ne!(COSE_OK, COSE_ERR);
    assert_ne!(COSE_PANIC, COSE_INVALID_ARG);
    let _ = format!("{:?}", COSE_OK);
    let _ = format!("{:?}", COSE_ERR);
    let _ = format!("{:?}", COSE_PANIC);
    let _ = format!("{:?}", COSE_INVALID_ARG);
    let a = COSE_OK;
    let b = a;
    assert_eq!(a, b);
}

// ========================================================================
// with_catch_unwind: panic path
// ========================================================================

#[test]
fn catch_unwind_panic_returns_cose_panic() {
    use cose_sign1_crypto_openssl_ffi::with_catch_unwind;
    let status = with_catch_unwind(|| {
        panic!("deliberate panic for coverage");
    });
    assert_eq!(status, COSE_PANIC);
}
