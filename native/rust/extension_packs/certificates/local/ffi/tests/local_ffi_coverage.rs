// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for certificates/local FFI — targeting uncovered paths.

use cose_sign1_certificates_local_ffi::{
    cose_cert_local_bytes_free, cose_cert_local_chain_create, cose_cert_local_chain_free,
    cose_cert_local_chain_new, cose_cert_local_chain_t, cose_cert_local_factory_create_cert,
    cose_cert_local_factory_create_self_signed, cose_cert_local_factory_free,
    cose_cert_local_factory_new, cose_cert_local_factory_t, cose_cert_local_load_der,
    cose_cert_local_load_pem, cose_cert_local_string_free, cose_status_t,
    cose_cert_local_last_error_message_utf8,
    cose_cert_local_array_free, cose_cert_local_lengths_array_free,
    set_last_error, clear_last_error, with_catch_unwind,
};
use std::ffi::{CStr, CString};

// ========================================================================
// Helper: create a factory + self-signed cert for reuse
// ========================================================================

fn make_self_signed() -> (*mut u8, usize, *mut u8, usize, *mut cose_cert_local_factory_t) {
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
        cose_status_t::COSE_OK
    );
    (cert_der, cert_len, key_der, key_len, factory)
}

// ========================================================================
// load_pem: success path with cert-only PEM
// ========================================================================

#[test]
fn load_pem_cert_only() {
    // Create a DER cert first, encode it as PEM manually
    let (cert_der, cert_len, key_der, key_len, factory) = make_self_signed();

    // Build PEM from DER bytes
    let der_slice = unsafe { std::slice::from_raw_parts(cert_der, cert_len) };
    let b64 = base64_encode(der_slice);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", b64);
    let pem_bytes = pem.as_bytes();

    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_cert_len: usize = 0;
    let mut out_key: *mut u8 = std::ptr::null_mut();
    let mut out_key_len: usize = 0;

    let status = cose_cert_local_load_pem(
        pem_bytes.as_ptr(),
        pem_bytes.len(),
        &mut out_cert,
        &mut out_cert_len,
        &mut out_key,
        &mut out_key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!out_cert.is_null());
    assert!(out_cert_len > 0);
    // cert-only PEM → key should be null
    assert!(out_key.is_null());
    assert_eq!(out_key_len, 0);

    unsafe {
        cose_cert_local_bytes_free(out_cert, out_cert_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
        cose_cert_local_factory_free(factory);
    }
}

// ========================================================================
// load_pem: null data
// ========================================================================

#[test]
fn load_pem_null_data() {
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_cert_len: usize = 0;
    let mut out_key: *mut u8 = std::ptr::null_mut();
    let mut out_key_len: usize = 0;

    let status = cose_cert_local_load_pem(
        std::ptr::null(),
        0,
        &mut out_cert,
        &mut out_cert_len,
        &mut out_key,
        &mut out_key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// load_pem: null output pointers
// ========================================================================

#[test]
fn load_pem_null_outputs() {
    let pem = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
    let status = cose_cert_local_load_pem(
        pem.as_ptr(),
        pem.len(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// load_pem: invalid PEM data
// ========================================================================

#[test]
fn load_pem_invalid_data() {
    let garbage = b"not a pem at all";
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_cert_len: usize = 0;
    let mut out_key: *mut u8 = std::ptr::null_mut();
    let mut out_key_len: usize = 0;

    let status = cose_cert_local_load_pem(
        garbage.as_ptr(),
        garbage.len(),
        &mut out_cert,
        &mut out_cert_len,
        &mut out_key,
        &mut out_key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// load_der: null output pointers
// ========================================================================

#[test]
fn load_der_null_outputs() {
    let garbage = [0xFFu8; 10];
    let status = cose_cert_local_load_der(
        garbage.as_ptr(),
        garbage.len(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// create_cert: null factory
// ========================================================================

#[test]
fn create_cert_null_factory() {
    let subject = CString::new("CN=test").unwrap();
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        std::ptr::null(),
        subject.as_ptr(),
        1,
        256,
        3600,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// create_cert: null output pointers
// ========================================================================

#[test]
fn create_cert_null_outputs() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=test").unwrap();
    let status = cose_cert_local_factory_create_cert(
        factory,
        subject.as_ptr(),
        1,
        256,
        3600,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_factory_free(factory);
}

// ========================================================================
// chain_create: null cert output pointers
// ========================================================================

#[test]
fn chain_create_null_cert_outputs() {
    let mut chain: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_chain_new(&mut chain),
        cose_status_t::COSE_OK
    );

    let mut keys_data: *mut *mut u8 = std::ptr::null_mut();
    let mut keys_lengths: *mut usize = std::ptr::null_mut();
    let mut keys_count: usize = 0;

    let status = cose_cert_local_chain_create(
        chain,
        1,
        true,
        std::ptr::null_mut(), // null cert output
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_chain_free(chain);
}

// ========================================================================
// chain_create: null key output pointers
// ========================================================================

#[test]
fn chain_create_null_key_outputs() {
    let mut chain: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_chain_new(&mut chain),
        cose_status_t::COSE_OK
    );

    let mut certs_data: *mut *mut u8 = std::ptr::null_mut();
    let mut certs_lengths: *mut usize = std::ptr::null_mut();
    let mut certs_count: usize = 0;

    let status = cose_cert_local_chain_create(
        chain,
        1,
        true,
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        std::ptr::null_mut(), // null key output
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_chain_free(chain);
}

// ========================================================================
// chain_create: invalid algorithm
// ========================================================================

#[test]
fn chain_create_invalid_algorithm() {
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
        99, // invalid algorithm
        true,
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_cert_local_chain_free(chain);
}

// ========================================================================
// with_catch_unwind: panic path
// ========================================================================

#[test]
fn catch_unwind_panic_path() {
    let status = with_catch_unwind(|| {
        panic!("deliberate panic for coverage");
    });
    assert_eq!(status, cose_status_t::COSE_PANIC);

    // Verify error message is set
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg).to_string_lossy().to_string() };
    assert!(s.contains("panic"));
    unsafe { cose_cert_local_string_free(msg) };
}

// ========================================================================
// with_catch_unwind: error path
// ========================================================================

#[test]
fn catch_unwind_error_path() {
    let status = with_catch_unwind(|| {
        anyhow::bail!("deliberate error for coverage");
    });
    assert_eq!(status, cose_status_t::COSE_ERR);

    let msg = cose_cert_local_last_error_message_utf8();
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg).to_string_lossy().to_string() };
    assert!(s.contains("deliberate error"));
    unsafe { cose_cert_local_string_free(msg) };
}

// ========================================================================
// with_catch_unwind: success path
// ========================================================================

#[test]
fn catch_unwind_success_path() {
    let status = with_catch_unwind(|| Ok(cose_status_t::COSE_OK));
    assert_eq!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// set_last_error / clear_last_error direct coverage
// ========================================================================

#[test]
fn set_and_clear_last_error() {
    set_last_error("test error message");
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg).to_string_lossy().to_string() };
    assert_eq!(s, "test error message");
    unsafe { cose_cert_local_string_free(msg) };

    // After taking, next call should return null
    let msg2 = cose_cert_local_last_error_message_utf8();
    assert!(msg2.is_null());
}

#[test]
fn clear_last_error_resets() {
    set_last_error("some error");
    clear_last_error();
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(msg.is_null());
}

// ========================================================================
// set_last_error with embedded NUL (edge case)
// ========================================================================

#[test]
fn set_last_error_with_nul_byte() {
    set_last_error("error\0with nul");
    // CString::new will replace with a fallback message
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(!msg.is_null());
    unsafe { cose_cert_local_string_free(msg) };
}

// ========================================================================
// string_from_ptr: invalid UTF-8
// ========================================================================

#[test]
fn create_cert_invalid_utf8_subject() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    // Create a C string with invalid UTF-8: 0xFF is not valid UTF-8
    let invalid = [0xFFu8, 0xFE, 0x00]; // null-terminated but invalid UTF-8
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        invalid.as_ptr() as *const std::ffi::c_char,
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
// load_pem: non-UTF-8 data
// ========================================================================

#[test]
fn load_pem_non_utf8() {
    let invalid = [0xFFu8, 0xFE, 0xFD];
    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_cert_len: usize = 0;
    let mut out_key: *mut u8 = std::ptr::null_mut();
    let mut out_key_len: usize = 0;

    let status = cose_cert_local_load_pem(
        invalid.as_ptr(),
        invalid.len(),
        &mut out_cert,
        &mut out_cert_len,
        &mut out_key,
        &mut out_key_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// chain_create: RSA chain (algorithm 0)
// ========================================================================

#[test]
fn chain_create_rsa() {
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
        0, // RSA
        false,
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );

    if status == cose_status_t::COSE_OK {
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
    }
    cose_cert_local_chain_free(chain);
}

// ========================================================================
// Minimal base64 encoder for PEM test helper
// ========================================================================

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if i + 2 < data.len() {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        i += 3;
    }
    // Add line breaks every 64 chars for proper PEM
    let mut wrapped = String::new();
    for (j, c) in result.chars().enumerate() {
        if j > 0 && j % 64 == 0 {
            wrapped.push('\n');
        }
        wrapped.push(c);
    }
    wrapped
}

// ========================================================================
// load_pem: PEM with both certificate AND private key
// ========================================================================

#[test]
fn load_pem_cert_with_key() {
    // Create a self-signed cert to get both cert and key DER
    let (cert_der, cert_len, key_der, key_len, factory) = make_self_signed();

    let der_cert = unsafe { std::slice::from_raw_parts(cert_der, cert_len) };
    let der_key = unsafe { std::slice::from_raw_parts(key_der, key_len) };

    // Build a PEM that contains both CERTIFICATE and PRIVATE KEY blocks
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n\
         -----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64_encode(der_cert),
        base64_encode(der_key),
    );
    let pem_bytes = pem.as_bytes();

    let mut out_cert: *mut u8 = std::ptr::null_mut();
    let mut out_cert_len: usize = 0;
    let mut out_key: *mut u8 = std::ptr::null_mut();
    let mut out_key_len: usize = 0;

    let status = cose_cert_local_load_pem(
        pem_bytes.as_ptr(),
        pem_bytes.len(),
        &mut out_cert,
        &mut out_cert_len,
        &mut out_key,
        &mut out_key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!out_cert.is_null());
    assert!(out_cert_len > 0);
    // With key present, key output should be non-null
    assert!(!out_key.is_null());
    assert!(out_key_len > 0);

    unsafe {
        cose_cert_local_bytes_free(out_cert, out_cert_len);
        cose_cert_local_bytes_free(out_key, out_key_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
        cose_cert_local_factory_free(factory);
    }
}

// ========================================================================
// string_free: non-null string
// ========================================================================

#[test]
fn string_free_non_null() {
    // Trigger an error to get a non-null error string
    set_last_error("to be freed");
    let msg = cose_cert_local_last_error_message_utf8();
    assert!(!msg.is_null());
    // Free the actual allocated string
    unsafe { cose_cert_local_string_free(msg) };
}

// ========================================================================
// chain_create: ECDSA with intermediate (exercises full loop)
// ========================================================================

#[test]
fn chain_create_ecdsa_with_intermediate_full_cleanup() {
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
        1, // ECDSA
        true,
        &mut certs_data,
        &mut certs_lengths,
        &mut certs_count,
        &mut keys_data,
        &mut keys_lengths,
        &mut keys_count,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(certs_count >= 2);
    assert_eq!(keys_count, certs_count);

    // Verify all cert buffers are non-null and non-zero length
    for i in 0..certs_count {
        let ptr = unsafe { *certs_data.add(i) };
        let len = unsafe { *certs_lengths.add(i) };
        assert!(!ptr.is_null());
        assert!(len > 0);
    }

    // Free everything using the proper free functions (non-null paths)
    unsafe {
        for i in 0..certs_count {
            cose_cert_local_bytes_free(*certs_data.add(i), *certs_lengths.add(i));
        }
        cose_cert_local_array_free(certs_data, certs_count);
        cose_cert_local_lengths_array_free(certs_lengths, certs_count);

        for i in 0..keys_count {
            let ptr = *keys_data.add(i);
            let len = *keys_lengths.add(i);
            if !ptr.is_null() && len > 0 {
                cose_cert_local_bytes_free(ptr, len);
            }
        }
        cose_cert_local_array_free(keys_data, keys_count);
        cose_cert_local_lengths_array_free(keys_lengths, keys_count);
    }
    cose_cert_local_chain_free(chain);
}

// ========================================================================
// factory_create_cert: exercise the ECDSA success path fully
// ========================================================================

#[test]
fn create_cert_ecdsa_full_roundtrip() {
    let mut factory: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    assert_eq!(
        cose_cert_local_factory_new(&mut factory),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=coverage-test-ecdsa").unwrap();
    let mut cert_der: *mut u8 = std::ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_der: *mut u8 = std::ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_cert(
        factory,
        subject.as_ptr(),
        1, // ECDSA
        384,
        7200,
        &mut cert_der,
        &mut cert_len,
        &mut key_der,
        &mut key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(cert_len > 0);
    assert!(key_len > 0);

    // Load the DER back to verify it's valid
    let mut rt_cert: *mut u8 = std::ptr::null_mut();
    let mut rt_len: usize = 0;
    assert_eq!(
        cose_cert_local_load_der(cert_der, cert_len, &mut rt_cert, &mut rt_len),
        cose_status_t::COSE_OK
    );
    assert_eq!(rt_len, cert_len);

    unsafe {
        cose_cert_local_bytes_free(rt_cert, rt_len);
        cose_cert_local_bytes_free(cert_der, cert_len);
        cose_cert_local_bytes_free(key_der, key_len);
        cose_cert_local_factory_free(factory);
    }
}

// ========================================================================
// cose_status_t: Debug/PartialEq coverage
// ========================================================================

#[test]
fn status_enum_properties() {
    assert_eq!(cose_status_t::COSE_OK, cose_status_t::COSE_OK);
    assert_ne!(cose_status_t::COSE_OK, cose_status_t::COSE_ERR);
    assert_ne!(cose_status_t::COSE_PANIC, cose_status_t::COSE_INVALID_ARG);
    // Exercise Debug
    let _ = format!("{:?}", cose_status_t::COSE_OK);
    let _ = format!("{:?}", cose_status_t::COSE_ERR);
    let _ = format!("{:?}", cose_status_t::COSE_PANIC);
    let _ = format!("{:?}", cose_status_t::COSE_INVALID_ARG);
    // Exercise Copy
    let a = cose_status_t::COSE_OK;
    let b = a;
    assert_eq!(a, b);
}

// ========================================================================
// with_catch_unwind: COSE_INVALID_ARG return value path
// ========================================================================

#[test]
fn catch_unwind_returns_invalid_arg() {
    let status = with_catch_unwind(|| Ok(cose_status_t::COSE_INVALID_ARG));
    assert_eq!(status, cose_status_t::COSE_INVALID_ARG);
}

// ========================================================================
// factory_new: exercise success path with immediate use
// ========================================================================

#[test]
fn factory_new_create_and_immediately_free() {
    let mut f: *mut cose_cert_local_factory_t = std::ptr::null_mut();
    let s = cose_cert_local_factory_new(&mut f);
    assert_eq!(s, cose_status_t::COSE_OK);
    assert!(!f.is_null());
    cose_cert_local_factory_free(f);
}

// ========================================================================
// chain_new: exercise success path with immediate use
// ========================================================================

#[test]
fn chain_new_create_and_immediately_free() {
    let mut c: *mut cose_cert_local_chain_t = std::ptr::null_mut();
    let s = cose_cert_local_chain_new(&mut c);
    assert_eq!(s, cose_status_t::COSE_OK);
    assert!(!c.is_null());
    cose_cert_local_chain_free(c);
}
