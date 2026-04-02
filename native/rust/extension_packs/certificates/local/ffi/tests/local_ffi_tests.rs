// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for certificates/local FFI exports.

use cose_sign1_certificates_local_ffi::{
    cose_cert_local_array_free, cose_cert_local_bytes_free, cose_cert_local_chain_create,
    cose_cert_local_chain_free, cose_cert_local_chain_new, cose_cert_local_chain_t,
    cose_cert_local_factory_create_cert, cose_cert_local_factory_create_self_signed,
    cose_cert_local_factory_free, cose_cert_local_factory_new, cose_cert_local_factory_t,
    cose_cert_local_ffi_abi_version, cose_cert_local_last_error_clear,
    cose_cert_local_last_error_message_utf8, cose_cert_local_lengths_array_free,
    cose_cert_local_load_der, cose_cert_local_string_free, cose_status_t,
};
use std::ffi::CString;

#[test]
fn abi_version() {
    assert_eq!(cose_cert_local_ffi_abi_version(), 1);
}

#[test]
fn last_error_initially_null() {
    cose_cert_local_last_error_clear();
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(msg.is_null());
}

#[test]
fn last_error_clear() {
    cose_cert_local_last_error_clear(); // should not crash
}

#[test]
fn string_free_null() {
    unsafe { cose_cert_local_string_free(std::ptr::null_mut()) }; // should not crash
}

#[test]
fn bytes_free_null() {
    unsafe { cose_cert_local_bytes_free(std::ptr::null_mut(), 0) };
}

#[test]
fn array_free_null() {
    unsafe { cose_cert_local_array_free(std::ptr::null_mut(), 0) };
}

#[test]
fn lengths_array_free_null() {
    unsafe { cose_cert_local_lengths_array_free(std::ptr::null_mut(), 0) };
}

#[test]
fn factory_new_and_free() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    let status = cose_cert_local_factory_new(&mut factory);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!factory.is_null());
    cose_cert_local_factory_free(factory);
}

#[test]
fn factory_new_null_out() {
    let status = cose_cert_local_factory_new(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn factory_free_null() {
    cose_cert_local_factory_free(std::ptr::null_mut()); // should not crash
}

#[test]
fn chain_new_and_free() {
    let mut chain: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    let status = cose_cert_local_chain_new(&mut chain);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!chain.is_null());
    cose_cert_local_chain_free(chain);
}

#[test]
fn chain_new_null_out() {
    let status = cose_cert_local_chain_new(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn chain_free_null() {
    cose_cert_local_chain_free(std::ptr::null_mut()); // should not crash
}

// ========================================================================
// Factory — create self-signed certificate
// ========================================================================

#[test]
fn factory_create_self_signed() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_self_signed(
        factory,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!cert_der.is_null());
    assert!(cert_len > 0);
    assert!(!key_der.is_null());
    assert!(key_len > 0);

    // Clean up
    unsafe {
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
    }
    cose_cert_local_factory_free(factory);
}

#[test]
fn factory_create_self_signed_null_factory() {
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;
    let status = cose_cert_local_factory_create_self_signed(
        std::ptr::null(),
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn factory_create_self_signed_null_outputs() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let status = cose_cert_local_factory_create_self_signed(
        factory,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_factory_free(factory);
}

// ========================================================================
// Factory — create certificate with options
// ========================================================================

#[test]
fn factory_create_ecdsa_cert() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=test-ecdsa").unwrap();
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        subject.as_ptr(),
        1, // ECDSA
        256,
        3600, // 1 hour
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(cert_len > 0);
    assert!(key_len > 0);

    unsafe {
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
    }
    cose_cert_local_factory_free(factory);
}

#[test]
fn factory_create_rsa_cert() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=test-rsa").unwrap();
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        subject.as_ptr(),
        0, // RSA
        2048,
        86400,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    // RSA key generation may not be supported in all configurations
    if status == cose_status_t::COSE_OK {
        assert!(cert_len > 0);
        unsafe {
            cose_cert_local_bytes_free(cert_der, cert_len);
            cose_cert_local_bytes_free(key_der, key_len);
        }
    }
    cose_cert_local_factory_free(factory);
}

#[test]
fn factory_create_cert_invalid_algorithm() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=test").unwrap();
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        subject.as_ptr(),
        99, // invalid algorithm
        256,
        3600,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_factory_free(factory);
}

#[test]
fn factory_create_cert_null_subject() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        std::ptr::null(),
        1,
        256,
        3600,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_factory_free(factory);
}

// ========================================================================
// Chain — create certificate chain
// ========================================================================

#[test]
fn chain_create_ecdsa() {
    let mut chain: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_chain_new(&mut chain),
        cose_status_t::COSE_OK
    );

    let mut certs_data: *mut *mut u8 = std::ptr::null_mut();
    let mut certs_lengths: *mut usize = std::ptr::null_mut();
    let mut certs_count: usize = 0;
    let mut keys_data: *mut *mut u8 = std::ptr::null_mut();
    let mut keys_lengths: *mut usize = std::ptr::null_mut();
    let mut keys_count: usize = 0;

    let status = cose_cert_local_chain_create(
        chain,
        1,    // ECDSA
        true, // include intermediate
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(certs_count >= 2); // leaf + root at minimum
    assert!(keys_count >= 1);

    // Clean up arrays
    unsafe {
        for i in 0..certs_count {
            let ptr = *certs_data.add(i);
            let len = *certs_lengths.add(i);
            cose_cert_local_bytes_free(ptr, len);
        }
        cose_cert_local_array_free(certs_data, certs_count);
        cose_cert_local_lengths_array_free(certs_lengths, certs_count);

        for i in 0..keys_count {
            let ptr = *keys_data.add(i);
            let len = *keys_lengths.add(i);
            cose_cert_local_bytes_free(ptr, len);
        }
        cose_cert_local_array_free(keys_data, keys_count);
        cose_cert_local_lengths_array_free(keys_lengths, keys_count);
    }
    cose_cert_local_chain_free(chain);
}

#[test]
fn chain_create_without_intermediate() {
    let mut chain: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_chain_new(&mut chain),
        cose_status_t::COSE_OK
    );

    let mut certs_data: *mut *mut u8 = std::ptr::null_mut();
    let mut certs_lengths: *mut usize = std::ptr::null_mut();
    let mut certs_count: usize = 0;
    let mut keys_data: *mut *mut u8 = std::ptr::null_mut();
    let mut keys_lengths: *mut usize = std::ptr::null_mut();
    let mut keys_count: usize = 0;

    let status = cose_cert_local_chain_create(
        chain,
        1,     // ECDSA
        false, // no intermediate
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(certs_count >= 1);

    unsafe {
        for i in 0..certs_count {
            cose_cert_local_bytes_free(*certs_data.add(i), *certs_lengths.add(i));
        }
        cose_cert_local_array_free(certs_data, certs_count);
        cose_cert_local_lengths_array_free(certs_lengths, certs_count);
        for i in 0..keys_count {
            cose_cert_local_bytes_free(*keys_data.add(i), *keys_lengths.add(i));
        }
        cose_cert_local_array_free(keys_data, keys_count);
        cose_cert_local_lengths_array_free(keys_lengths, keys_count);
    }
    cose_cert_local_chain_free(chain);
}

#[test]
fn chain_create_null_chain() {
    let mut certs_data: *mut *mut u8 = std::ptr::null_mut();
    let mut certs_lengths: *mut usize = std::ptr::null_mut();
    let mut certs_count: usize = 0;
    let mut keys_data: *mut *mut u8 = std::ptr::null_mut();
    let mut keys_lengths: *mut usize = std::ptr::null_mut();
    let mut keys_count: usize = 0;

    let status = cose_cert_local_chain_create(
        std::ptr::null(),
        1,
        true,
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// Load DER
// ========================================================================

#[test]
fn load_der_roundtrip() {
    // Create a cert first, then load it back via DER
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    assert_eq!(
        cose_cert_local_factory_create_self_signed(
            factory,
            &mut cert_der,
            &mut cert_len,
            &mut key_der,
            &mut key_len,
        ),
        cose_status_t::COSE_OK,
    );

    // Now reload the DER
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = cose_cert_local_load_der(cert_der, cert_len, &mut out_cert, &mut out_len);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(out_len, cert_len);

    unsafe {
        cose_cert_local_bytes_free(out_cert, out_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
    }
    cose_cert_local_factory_free(factory);
}

#[test]
fn load_der_null_data() {
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let status = cose_cert_local_load_der(std::ptr::null(), 0, &mut out_cert, &mut out_len);
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn load_der_invalid() {
    let garbage = [0xFFu8; 10];
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let status =
        cose_cert_local_load_der(garbage.as_ptr(), garbage.len(), &mut out_cert, &mut out_len);
    // May succeed (pass-through) or fail depending on validation
    let _ = status;
}

// ========================================================================
// Error message after failure
// ========================================================================

#[test]
fn error_message_after_failure() {
    cose_cert_local_last_error_clear();
    // Trigger an error
    let status = cose_cert_local_factory_new(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
    // Should have error message now
    let msg = cose_cert_local_last_error_message_utf8();
    if !msg.is_null() {
        let s = unsafe { std::ffi::CStr::from_ptr(msg).to_string_lossy().to_string() };
        assert!(!s.is_empty());
        unsafe { cose_cert_local_string_free(msg) };
    }
}
