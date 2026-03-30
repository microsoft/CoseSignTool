//! Basic FFI test coverage for signing factories functions.

use cose_sign1_factories_ffi::*;
use std::ffi::{CStr, CString};
use std::ptr;

#[test]
fn test_abi_version() {
    let version = cose_sign1_factories_abi_version();
    assert_eq!(version, 1);
}

#[test]
fn test_factories_create_from_crypto_signer_null_out_ptr() {
    unsafe {
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Test null out_factory pointer
        let result = cose_sign1_factories_create_from_crypto_signer(
            ptr::null_mut(), // signer (will fail anyway)
            ptr::null_mut(),
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_create_from_signing_service_null_safety() {
    unsafe {
        let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Test null service
        let result = cose_sign1_factories_create_from_signing_service(
            ptr::null_mut(),
            &mut factory,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(factory.is_null());
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_sign_direct_null_safety() {
    unsafe {
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Test null factory
        let result = cose_sign1_factories_sign_direct(
            ptr::null_mut(),
            b"test payload".as_ptr(),
            12,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_sign_direct_detached_null_safety() {
    unsafe {
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Test null factory
        let result = cose_sign1_factories_sign_direct_detached(
            ptr::null_mut(),
            b"test payload".as_ptr(),
            12,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_sign_direct_file_null_safety() {
    unsafe {
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        let file_path = CString::new("nonexistent.txt").unwrap();

        // Test null factory
        let result = cose_sign1_factories_sign_direct_file(
            ptr::null_mut(),
            file_path.as_ptr(),
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_sign_indirect_null_safety() {
    unsafe {
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Test null factory
        let result = cose_sign1_factories_sign_indirect(
            ptr::null_mut(),
            b"test payload".as_ptr(),
            12,
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_sign_indirect_file_null_safety() {
    unsafe {
        let mut out_bytes: *mut u8 = ptr::null_mut();
        let mut out_len: u32 = 0;
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        let file_path = CString::new("nonexistent.txt").unwrap();

        // Test null factory
        let result = cose_sign1_factories_sign_indirect_file(
            ptr::null_mut(),
            file_path.as_ptr(),
            ptr::null(),
            &mut out_bytes,
            &mut out_len,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(out_bytes.is_null());
        assert_eq!(out_len, 0);
        assert!(!error.is_null());

        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_factories_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_sign1_factories_free(ptr::null_mut());
    }
}

#[test]
fn test_factories_bytes_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_sign1_factories_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn test_error_handling() {
    unsafe {
        let mut factory: *mut CoseSign1FactoriesHandle = ptr::null_mut();
        let mut error: *mut CoseSign1FactoriesErrorHandle = ptr::null_mut();

        // Create a null pointer error
        let result = cose_sign1_factories_create_from_crypto_signer(
            ptr::null_mut(),
            &mut factory,
            &mut error,
        );

        assert_ne!(result, COSE_SIGN1_FACTORIES_OK);
        assert!(!error.is_null());

        // Test error code
        let code = cose_sign1_factories_error_code(error);
        assert_ne!(code, COSE_SIGN1_FACTORIES_OK);

        // Test error message
        let msg_ptr = cose_sign1_factories_error_message(error);
        assert!(!msg_ptr.is_null());

        let message = CStr::from_ptr(msg_ptr).to_str().unwrap();
        assert!(!message.is_empty());

        cose_sign1_factories_string_free(msg_ptr);
        cose_sign1_factories_error_free(error);
    }
}

#[test]
fn test_error_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_sign1_factories_error_free(ptr::null_mut());
    }
}

#[test]
fn test_string_free_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_sign1_factories_string_free(ptr::null_mut());
    }
}
