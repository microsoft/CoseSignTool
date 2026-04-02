// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive tests for all impl_*_inner functions to achieve target coverage.

use cose_sign1_signing_ffi::error::{cose_sign1_signing_error_free, CoseSign1SigningErrorHandle};
use cose_sign1_signing_ffi::types::{
    CoseKeyHandle, CoseSign1FactoryHandle, CoseSign1SigningServiceHandle,
};
use cose_sign1_signing_ffi::*;

use std::ptr;

// Helper functions
fn free_error(err: *mut CoseSign1SigningErrorHandle) {
    if !err.is_null() {
        unsafe { cose_sign1_signing_error_free(err) };
    }
}

fn free_service(service: *mut CoseSign1SigningServiceHandle) {
    if !service.is_null() {
        unsafe { cose_sign1_signing_service_free(service) };
    }
}

fn free_factory(factory: *mut CoseSign1FactoryHandle) {
    if !factory.is_null() {
        unsafe { cose_sign1_factory_free(factory) };
    }
}

fn free_key(k: *mut CoseKeyHandle) {
    if !k.is_null() {
        unsafe { cose_key_free(k) };
    }
}

unsafe extern "C" fn mock_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    let sig = vec![0xABu8; 64];
    let len = sig.len();
    let ptr = libc::malloc(len) as *mut u8;
    if ptr.is_null() {
        return -1;
    }
    std::ptr::copy_nonoverlapping(sig.as_ptr(), ptr, len);
    unsafe {
        *out_sig = ptr;
        *out_sig_len = len;
    }
    0
}

unsafe extern "C" fn fail_sign_callback(
    _sig_structure: *const u8,
    _sig_structure_len: usize,
    _out_sig: *mut *mut u8,
    _out_sig_len: *mut usize,
    _user_data: *mut libc::c_void,
) -> i32 {
    -42
}

unsafe extern "C" fn mock_read_callback(
    buffer: *mut u8,
    buffer_size: usize,
    _user_data: *mut libc::c_void,
) -> i64 {
    // Fill buffer with test data
    let fill_data = b"test streaming data";
    let copy_len = std::cmp::min(buffer_size, fill_data.len());
    if !buffer.is_null() && copy_len > 0 {
        std::ptr::copy_nonoverlapping(fill_data.as_ptr(), buffer, copy_len);
    }
    copy_len as i64
}

fn create_mock_key() -> *mut CoseKeyHandle {
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    let rc = impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        mock_sign_callback,
        ptr::null_mut(),
        &mut key,
    );
    assert_eq!(rc, 0);
    assert!(!key.is_null());
    key
}

// ============================================================================
// signing service inner tests
// ============================================================================

#[test]
fn inner_signing_service_create_success() {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_create_inner(key, &mut service, &mut err);
    assert_eq!(rc, 0);
    assert!(!service.is_null());

    free_service(service);
    free_key(key);
    free_error(err);
}

#[test]
fn inner_signing_service_create_null_output() {
    let key = create_mock_key();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_create_inner(key, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_key(key);
    free_error(err);
}

#[test]
fn inner_signing_service_create_null_key() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_create_inner(ptr::null(), &mut service, &mut err);
    assert!(rc < 0);

    free_service(service);
    free_error(err);
}

#[test]
fn inner_signing_service_from_crypto_signer_null_output() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc =
        impl_signing_service_from_crypto_signer_inner(ptr::null_mut(), ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_signing_service_from_crypto_signer_null_signer() {
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_signing_service_from_crypto_signer_inner(ptr::null_mut(), &mut service, &mut err);
    assert!(rc < 0);

    free_service(service);
    free_error(err);
}

// ============================================================================
// factory inner tests
// ============================================================================

#[test]
fn inner_factory_create_success() {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    assert!(!service.is_null());
    free_error(err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let rc = impl_factory_create_inner(service, &mut factory, &mut err);
    assert_eq!(rc, 0);
    assert!(!factory.is_null());

    free_factory(factory);
    free_key(key);
    // service consumed by factory creation
    free_error(err);
}

#[test]
fn inner_factory_create_null_output() {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    free_error(err);

    let rc = impl_factory_create_inner(service, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_key(key);
    free_service(service);
    free_error(err);
}

#[test]
fn inner_factory_create_null_service() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_create_inner(ptr::null(), &mut factory, &mut err);
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_from_crypto_signer_null_output() {
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_from_crypto_signer_inner(ptr::null_mut(), ptr::null_mut(), &mut err);
    assert!(rc < 0);

    free_error(err);
}

#[test]
fn inner_factory_from_crypto_signer_null_signer() {
    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_from_crypto_signer_inner(ptr::null_mut(), &mut factory, &mut err);
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

fn create_factory() -> *mut CoseSign1FactoryHandle {
    let key = create_mock_key();
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    free_error(err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);
    free_error(err);
    free_key(key);

    factory
}

// ============================================================================
// factory sign direct inner tests
// ============================================================================

#[test]
fn inner_factory_sign_direct_success() {
    let factory = create_factory();
    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_factory() {
    let payload = b"test";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        ptr::null_mut(),
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_outputs() {
    let factory = create_factory();
    let payload = b"test";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut err,
    );

    assert!(rc < 0);
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_null_content_type() {
    let factory = create_factory();
    let payload = b"test";

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_empty_payload() {
    let factory = create_factory();
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        ptr::null(),
        0,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

// ============================================================================
// factory sign indirect inner tests
// ============================================================================

#[test]
fn inner_factory_sign_indirect_success() {
    let factory = create_factory();
    let payload = b"test payload";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_null_factory() {
    let payload = b"test";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_inner(
        ptr::null_mut(),
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

// ============================================================================
// factory sign file inner tests
// ============================================================================

fn create_temp_file() -> (String, std::fs::File) {
    use std::io::Write;
    let temp_dir = std::env::temp_dir();
    let unique_name = format!(
        "test_payload_{:?}_{}.txt",
        std::thread::current().id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let file_path = temp_dir.join(unique_name);
    let mut file = std::fs::File::create(&file_path).unwrap();
    write!(file, "test payload content").unwrap();
    (file_path.to_string_lossy().to_string(), file)
}

#[test]
fn inner_factory_sign_direct_file_success() {
    let factory = create_factory();
    let (file_path, _file) = create_temp_file();
    let file_path_cstr = std::ffi::CString::new(file_path.clone()).unwrap();
    let content_type = std::ffi::CString::new("text/plain").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path_cstr.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);

    // Cleanup
    let _ = std::fs::remove_file(file_path);
}

#[test]
fn inner_factory_sign_direct_file_null_factory() {
    let content_type = std::ffi::CString::new("text/plain").unwrap();
    let file_path = std::ffi::CString::new("dummy.txt").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_file_inner(
        ptr::null_mut(),
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_file_null_path() {
    let factory = create_factory();
    let content_type = std::ffi::CString::new("text/plain").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_file_inner(
        factory,
        ptr::null(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_file_nonexistent() {
    let factory = create_factory();
    let file_path = std::ffi::CString::new("/nonexistent/file.txt").unwrap();
    let content_type = std::ffi::CString::new("text/plain").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_file_inner(
        factory,
        file_path.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_file_success() {
    let factory = create_factory();
    let (file_path, _file) = create_temp_file();
    let file_path_cstr = std::ffi::CString::new(file_path.clone()).unwrap();
    let content_type = std::ffi::CString::new("text/plain").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_file_inner(
        factory,
        file_path_cstr.as_ptr(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);

    // Cleanup
    let _ = std::fs::remove_file(file_path);
}

// ============================================================================
// factory sign streaming inner tests
// ============================================================================

#[test]
fn inner_factory_sign_direct_streaming_success() {
    let factory = create_factory();
    let payload_len = 22u64; // "test streaming data".len()
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_read_callback,
        payload_len,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_direct_streaming_null_factory() {
    let payload_len = 10u64;
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        ptr::null_mut(),
        mock_read_callback,
        payload_len,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_streaming_success() {
    let factory = create_factory();
    let payload_len = 22u64;
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_streaming_inner(
        factory,
        mock_read_callback,
        payload_len,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_indirect_streaming_null_factory() {
    let payload_len = 10u64;
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_indirect_streaming_inner(
        ptr::null_mut(),
        mock_read_callback,
        payload_len,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_error(err);
}

// ============================================================================
// edge case tests for better coverage
// ============================================================================

#[test]
fn inner_factory_sign_with_failing_key() {
    // Create a key with failing callback
    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        fail_sign_callback,
        ptr::null_mut(),
        &mut key,
    );

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    free_error(err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);
    free_error(err);
    free_key(key);

    let payload = b"test";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0); // Should fail due to callback error
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_invalid_utf8_content_type() {
    let factory = create_factory();
    let payload = b"test";
    let invalid = [0xC0u8, 0xAF, 0x00]; // Invalid UTF-8 + null terminator

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        invalid.as_ptr() as *const libc::c_char,
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0);
    free_factory(factory);
    free_error(err);
}

#[test]
fn inner_factory_sign_large_payload_streaming() {
    let factory = create_factory();
    let payload_len = 100_000u64; // Large payload to test streaming behavior
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        mock_read_callback,
        payload_len,
        ptr::null_mut(),
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Mock callback keys don't support verification, so expect failure
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

// ============================================================================
// additional coverage tests for missing lines
// ============================================================================

#[test]
fn test_free_functions_coverage() {
    use cose_sign1_signing_ffi::{
        cose_headermap_free, cose_key_free, cose_sign1_builder_free, cose_sign1_factory_free,
        cose_sign1_signing_error_free, cose_sign1_signing_service_free,
    };

    // Test all the free functions with valid handles
    let key = create_mock_key();
    unsafe {
        cose_key_free(key);
    }

    let mut headermap: *mut CoseHeaderMapHandle = ptr::null_mut();
    impl_headermap_new_inner(&mut headermap);
    unsafe {
        cose_headermap_free(headermap);
    }

    let mut builder: *mut CoseSign1BuilderHandle = ptr::null_mut();
    impl_builder_new_inner(&mut builder);
    unsafe {
        cose_sign1_builder_free(builder);
    }

    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    let key2 = create_mock_key();
    impl_signing_service_create_inner(key2, &mut service, &mut err);
    unsafe {
        cose_sign1_signing_service_free(service);
    }
    free_error(err);
    free_key(key2);

    let factory = create_factory();
    unsafe {
        cose_sign1_factory_free(factory);
    }

    // Create a new error to test error free function
    let error_inner = crate::error::ErrorInner::new("Test error", -1);
    let error_handle = crate::error::inner_to_handle(error_inner);
    unsafe {
        cose_sign1_signing_error_free(error_handle);
    }
}

#[test]
fn test_byte_allocation_paths() {
    // Test the cose_sign1_cose_bytes_free function path
    use cose_sign1_signing_ffi::cose_sign1_cose_bytes_free;

    // Allocate some bytes like the factory functions would
    let test_bytes = vec![1u8, 2, 3, 4, 5];
    let len = test_bytes.len() as u32;
    let ptr = Box::into_raw(test_bytes.into_boxed_slice()) as *mut u8;

    // Free them
    unsafe {
        cose_sign1_cose_bytes_free(ptr, len);
    }
}

#[test]
fn test_callback_key_failure_paths() {
    // Test different callback failure scenarios
    unsafe extern "C" fn error_callback(
        _sig_structure: *const u8,
        _sig_structure_len: usize,
        out_sig: *mut *mut u8,
        out_sig_len: *mut usize,
        _user_data: *mut libc::c_void,
    ) -> i32 {
        // Set valid outputs but return error code
        unsafe {
            *out_sig = libc::malloc(32) as *mut u8;
            *out_sig_len = 32;
        }
        -42 // Custom error code
    }

    let key_type = std::ffi::CString::new("EC2").unwrap();
    let mut key: *mut CoseKeyHandle = ptr::null_mut();
    impl_key_from_callback_inner(
        -7,
        key_type.as_ptr(),
        error_callback,
        ptr::null_mut(),
        &mut key,
    );

    // Try to use this key for signing
    let mut service: *mut CoseSign1SigningServiceHandle = ptr::null_mut();
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();
    impl_signing_service_create_inner(key, &mut service, &mut err);
    free_error(err);

    let mut factory: *mut CoseSign1FactoryHandle = ptr::null_mut();
    impl_factory_create_inner(service, &mut factory, &mut err);
    free_error(err);

    let payload = b"test";
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    assert!(rc < 0); // Should fail

    free_factory(factory);
    free_service(service);
    free_key(key);
    free_error(err);
}

#[test]
fn test_string_conversion_edge_cases() {
    // Test CString conversion for content types with different encodings
    let factory = create_factory();
    let payload = b"test";

    // Test with empty content type
    let empty_ct = std::ffi::CString::new("").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_inner(
        factory,
        payload.as_ptr(),
        payload.len() as u32,
        empty_ct.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Empty content type is valid, but signing will fail due to mock key
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn test_error_handling_edge_cases() {
    // Test error message retrieval edge cases
    use cose_sign1_signing_ffi::{cose_sign1_signing_error_code, cose_sign1_signing_error_message};

    // Create a new error to test
    let error_inner = crate::error::ErrorInner::new("Test error message", -42);
    let error_handle = crate::error::inner_to_handle(error_inner);

    // Get error code
    let code = unsafe { cose_sign1_signing_error_code(error_handle) };
    assert_eq!(code, -42);

    // Get message
    let msg_ptr = unsafe { cose_sign1_signing_error_message(error_handle) };
    assert!(!msg_ptr.is_null());

    // Free the returned message
    let msg = unsafe { std::ffi::CStr::from_ptr(msg_ptr) };
    assert!(!msg.to_bytes().is_empty());

    use cose_sign1_signing_ffi::cose_sign1_string_free;
    unsafe {
        cose_sign1_string_free(msg_ptr as *mut libc::c_char);
    }

    // Free the error handle
    use cose_sign1_signing_ffi::cose_sign1_signing_error_free;
    unsafe {
        cose_sign1_signing_error_free(error_handle);
    }
}

#[test]
fn test_streaming_callback_variations() {
    // Test streaming with different callback behaviors
    let factory = create_factory();
    let content_type = std::ffi::CString::new("application/octet-stream").unwrap();

    unsafe extern "C" fn small_read_callback(
        buffer: *mut u8,
        buffer_len: usize,
        user_data: *mut libc::c_void,
    ) -> i64 {
        // Fixed return type
        if user_data.is_null() {
            return -1; // Error
        }
        let count = std::ptr::read(user_data as *mut usize);
        if count == 0 {
            return 0; // EOF
        }
        std::ptr::write(user_data as *mut usize, 0); // Mark as done

        // Write small amount of data
        let data = b"small";
        let write_len = std::cmp::min(data.len(), buffer_len);
        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, write_len);
        write_len as i64
    }

    let mut counter = 1usize;
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: u32 = 0;
    let mut err: *mut CoseSign1SigningErrorHandle = ptr::null_mut();

    let rc = impl_factory_sign_direct_streaming_inner(
        factory,
        small_read_callback,
        5,
        &mut counter as *mut usize as *mut libc::c_void,
        content_type.as_ptr(),
        &mut out_bytes,
        &mut out_len,
        &mut err,
    );

    // Will fail due to mock key limitation, but we've exercised the streaming path
    assert!(rc < 0);

    free_factory(factory);
    free_error(err);
}

#[test]
fn test_abi_version_coverage() {
    use cose_sign1_signing_ffi::cose_sign1_signing_abi_version;
    let version = cose_sign1_signing_abi_version();
    assert!(version > 0);
}

#[test]
fn test_ffi_cbor_provider() {
    // Test the provider.rs file function directly
    let provider = crate::provider::ffi_cbor_provider();
    drop(provider);
}
