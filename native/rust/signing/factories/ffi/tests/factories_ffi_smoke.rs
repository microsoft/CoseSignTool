// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! FFI smoke tests for cose_sign1_factories_ffi.
//!
//! These tests verify the C calling convention compatibility and handle lifecycle.

use cose_sign1_factories_ffi::*;
use std::ffi::CStr;
use std::ptr;

/// Helper to get error message from an error handle.
fn error_message(err: *const CoseSign1FactoriesErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { cose_sign1_factories_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    unsafe { cose_sign1_factories_string_free(msg) };
    Some(s)
}

#[test]
fn ffi_abi_version() {
    let version = cose_sign1_factories_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn ffi_null_free_is_safe() {
    // All free functions should handle null safely
    unsafe {
        cose_sign1_factories_free(ptr::null_mut());
        cose_sign1_factories_error_free(ptr::null_mut());
        cose_sign1_factories_string_free(ptr::null_mut());
    }
}

#[test]
fn ffi_create_from_crypto_signer_null_inputs() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    // Null out_factory should fail
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(ptr::null_mut(), ptr::null_mut(), &mut err)
    };
    assert_eq!(rc, COSE_SIGN1_FACTORIES_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_factory"));
    unsafe { cose_sign1_factories_error_free(err) };

    // Null signer_handle should fail
    err = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(ptr::null_mut(), &mut factory, &mut err)
    };
    assert_eq!(rc, COSE_SIGN1_FACTORIES_ERR_NULL_POINTER);
    assert!(factory.is_null());
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("signer_handle"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn ffi_create_with_transparency_null_inputs() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    // Null out_factory should fail
    let rc = unsafe {
        cose_sign1_factories_create_with_transparency(
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_FACTORIES_ERR_NULL_POINTER);
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("out_factory"));
    unsafe { cose_sign1_factories_error_free(err) };

    // Null service should fail
    err = ptr::null_mut();
    let rc = unsafe {
        cose_sign1_factories_create_with_transparency(
            ptr::null(),
            ptr::null(),
            0,
            &mut factory,
            &mut err,
        )
    };
    assert_eq!(rc, COSE_SIGN1_FACTORIES_ERR_NULL_POINTER);
    assert!(factory.is_null());
    assert!(!err.is_null());
    let err_msg = error_message(err).unwrap_or_default();
    assert!(err_msg.contains("service"));
    unsafe { cose_sign1_factories_error_free(err) };
}

#[test]
fn ffi_error_handling() {
    let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
    let mut err: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

    // Trigger an error with null signer
    let rc = unsafe {
        cose_sign1_factories_create_from_crypto_signer(ptr::null_mut(), &mut factory, &mut err)
    };
    assert!(rc < 0);
    assert!(!err.is_null());

    // Get error code
    let code = unsafe { cose_sign1_factories_error_code(err) };
    assert!(code < 0);

    // Get error message
    let msg_ptr = unsafe { cose_sign1_factories_error_message(err) };
    assert!(!msg_ptr.is_null());

    let msg_str = unsafe { CStr::from_ptr(msg_ptr) }
        .to_string_lossy()
        .to_string();
    assert!(!msg_str.is_empty());

    unsafe {
        cose_sign1_factories_string_free(msg_ptr);
        cose_sign1_factories_error_free(err);
    };
}
