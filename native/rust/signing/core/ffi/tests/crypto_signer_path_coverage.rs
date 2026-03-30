// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the `from_crypto_signer` FFI paths in signing_ffi.
//!
//! These tests cover `impl_signing_service_from_crypto_signer_inner` and
//! `impl_factory_from_crypto_signer_inner` with VALID CryptoSigner handles,
//! exercising the success paths (lines 899-912, 968-983) that were previously
//! only tested with null handles.

use cose_sign1_signing_ffi::*;
use std::ptr;

/// Mock CryptoSigner for testing the from_crypto_signer FFI paths.
struct MockCryptoSigner {
    algorithm_id: i64,
    key_type_str: String,
}

impl MockCryptoSigner {
    fn new() -> Self {
        Self {
            algorithm_id: -7, // ES256
            key_type_str: "EC".to_string(),
        }
    }
}

impl crypto_primitives::CryptoSigner for MockCryptoSigner {
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        // Return a fake signature
        Ok(vec![0xDE; 64])
    }

    fn algorithm(&self) -> i64 {
        self.algorithm_id
    }

    fn key_type(&self) -> &str {
        &self.key_type_str
    }
}

/// Helper: create a CryptoSignerHandle from a mock signer.
///
/// The handle is a `Box<Box<dyn CryptoSigner>>` cast to `*mut CryptoSignerHandle`.
/// Ownership is transferred — the FFI function will free it.
fn create_mock_signer_handle() -> *mut CryptoSignerHandle {
    let signer: Box<dyn crypto_primitives::CryptoSigner> = Box::new(MockCryptoSigner::new());
    Box::into_raw(Box::new(signer)) as *mut CryptoSignerHandle
}

#[test]
fn test_signing_service_from_crypto_signer_valid_handle() {
    let signer_handle = create_mock_signer_handle();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_signing_service_from_crypto_signer_inner(
        signer_handle,
        &mut service,
        &mut error,
    );

    assert_eq!(result, 0, "Expected FFI_OK (0)");
    assert!(!service.is_null(), "Service handle should not be null");
    assert!(error.is_null(), "Error handle should be null on success");

    // Clean up
    unsafe {
        if !service.is_null() {
            cose_sign1_signing_service_free(service);
        }
    }
}

#[test]
fn test_factory_from_crypto_signer_valid_handle() {
    let signer_handle = create_mock_signer_handle();
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_factory_from_crypto_signer_inner(
        signer_handle,
        &mut factory,
        &mut error,
    );

    assert_eq!(result, 0, "Expected FFI_OK (0)");
    assert!(!factory.is_null(), "Factory handle should not be null");
    assert!(error.is_null(), "Error handle should be null on success");

    // Clean up
    unsafe {
        if !factory.is_null() {
            cose_sign1_factory_free(factory);
        }
    }
}

#[test]
fn test_factory_from_crypto_signer_then_sign_direct() {
    // Create factory from mock signer
    let signer_handle = create_mock_signer_handle();
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_factory_from_crypto_signer_inner(
        signer_handle,
        &mut factory,
        &mut error,
    );
    assert_eq!(result, 0);
    assert!(!factory.is_null());

    // Try to sign — this will fail at verification but exercises the sign path
    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let sign_result = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut sign_error,
    );

    // Expected to fail because SimpleSigningService::verify_signature returns Err
    assert_ne!(sign_result, 0, "Expected factory sign to fail (verification not supported)");

    // Clean up
    unsafe {
        if !sign_error.is_null() {
            cose_sign1_signing_error_free(sign_error);
        }
        if !factory.is_null() {
            cose_sign1_factory_free(factory);
        }
    }
}

#[test]
fn test_factory_from_crypto_signer_then_sign_indirect() {
    let signer_handle = create_mock_signer_handle();
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_factory_from_crypto_signer_inner(
        signer_handle,
        &mut factory,
        &mut error,
    );
    assert_eq!(result, 0);

    let payload = b"indirect test payload";
    let content_type = std::ffi::CString::new("text/plain").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut sign_error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let sign_result = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut sign_error,
    );

    // Expected to fail at verification
    assert_ne!(sign_result, 0);

    unsafe {
        if !sign_error.is_null() {
            cose_sign1_signing_error_free(sign_error);
        }
        if !factory.is_null() {
            cose_sign1_factory_free(factory);
        }
    }
}

#[test]
fn test_service_from_crypto_signer_null_out_service() {
    let signer_handle = create_mock_signer_handle();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_signing_service_from_crypto_signer_inner(
        signer_handle,
        ptr::null_mut(), // null out_service
        &mut error,
    );

    assert_ne!(result, 0, "Should fail with null out_service");

    // signer_handle was NOT consumed (function failed before Box::from_raw)
    // We need to free it manually
    unsafe {
        if !signer_handle.is_null() {
            let _ = Box::from_raw(signer_handle as *mut Box<dyn crypto_primitives::CryptoSigner>);
        }
        if !error.is_null() {
            cose_sign1_signing_error_free(error);
        }
    }
}

#[test]
fn test_factory_from_crypto_signer_null_out_factory() {
    let signer_handle = create_mock_signer_handle();
    let mut error: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let result = impl_factory_from_crypto_signer_inner(
        signer_handle,
        ptr::null_mut(), // null out_factory
        &mut error,
    );

    assert_ne!(result, 0);

    unsafe {
        if !signer_handle.is_null() {
            let _ = Box::from_raw(signer_handle as *mut Box<dyn crypto_primitives::CryptoSigner>);
        }
        if !error.is_null() {
            cose_sign1_signing_error_free(error);
        }
    }
}
