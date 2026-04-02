// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests for the certificates local FFI crate.

use cose_sign1_certificates_local_ffi::*;
use std::ptr;

#[test]
fn abi_version() {
    assert_eq!(cose_cert_local_ffi_abi_version(), 1);
}

#[test]
fn last_error_clear() {
    cose_cert_local_last_error_clear();
}

#[test]
fn last_error_message_no_error() {
    cose_cert_local_last_error_clear();
    let msg = cose_cert_local_last_error_message_utf8();
    // When no error, returns null
    if !msg.is_null() {
        unsafe { cose_cert_local_string_free(msg) };
    }
}

#[test]
fn factory_new_and_free() {
    let mut factory: *mut cose_cert_local_factory_t = ptr::null_mut();
    let status = cose_cert_local_factory_new(&mut factory);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!factory.is_null());
    unsafe { cose_cert_local_factory_free(factory) };
}

#[test]
fn factory_free_null() {
    unsafe { cose_cert_local_factory_free(ptr::null_mut()) };
}

#[test]
fn factory_new_null_out() {
    let status = cose_cert_local_factory_new(ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn factory_create_self_signed() {
    let mut factory: *mut cose_cert_local_factory_t = ptr::null_mut();
    cose_cert_local_factory_new(&mut factory);

    let mut cert_ptr: *mut u8 = ptr::null_mut();
    let mut cert_len: usize = 0;
    let mut key_ptr: *mut u8 = ptr::null_mut();
    let mut key_len: usize = 0;

    let status = cose_cert_local_factory_create_self_signed(
        factory,
        &mut cert_ptr,
        &mut cert_len,
        &mut key_ptr,
        &mut key_len,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!cert_ptr.is_null());
    assert!(cert_len > 0);
    assert!(!key_ptr.is_null());
    assert!(key_len > 0);

    unsafe {
        cose_cert_local_bytes_free(cert_ptr, cert_len);
        cose_cert_local_bytes_free(key_ptr, key_len);
        cose_cert_local_factory_free(factory);
    }
}

#[test]
fn chain_new_and_free() {
    let mut chain: *mut cose_cert_local_chain_t = ptr::null_mut();
    let status = cose_cert_local_chain_new(&mut chain);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!chain.is_null());
    unsafe { cose_cert_local_chain_free(chain) };
}

#[test]
fn chain_free_null() {
    unsafe { cose_cert_local_chain_free(ptr::null_mut()) };
}

#[test]
fn string_free_null() {
    unsafe { cose_cert_local_string_free(ptr::null_mut()) };
}

#[test]
fn bytes_free_null() {
    unsafe { cose_cert_local_bytes_free(ptr::null_mut(), 0) };
}
