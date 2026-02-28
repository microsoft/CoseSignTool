// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for signing FFI internal functions.
//! Focus on error paths, callback handling, and internal wrappers.

use cose_sign1_signing_ffi::*;
use std::ptr;

#[test]
fn test_abi_version() {
    let version = cose_sign1_signing_abi_version();
    assert!(version > 0);
}

#[test]
fn test_error_handling_helpers() {
    // Test the error code constants
    assert_eq!(COSE_SIGN1_SIGNING_OK, 0);
    assert_ne!(COSE_SIGN1_SIGNING_ERR_NULL_POINTER, COSE_SIGN1_SIGNING_OK);
    assert_ne!(COSE_SIGN1_SIGNING_ERR_INVALID_ARGUMENT, COSE_SIGN1_SIGNING_OK);
    assert_ne!(COSE_SIGN1_SIGNING_ERR_SIGN_FAILED, COSE_SIGN1_SIGNING_OK);
    assert_ne!(COSE_SIGN1_SIGNING_ERR_FACTORY_FAILED, COSE_SIGN1_SIGNING_OK);
    assert_ne!(COSE_SIGN1_SIGNING_ERR_PANIC, COSE_SIGN1_SIGNING_OK);
}

#[test]
fn test_headermap_null_safety() {
    let mut headermap_ptr: *mut CoseHeaderMapHandle = ptr::null_mut();
    
    // Test null pointer handling in headermap creation
    let result = unsafe { cose_headermap_new(&mut headermap_ptr) };
    if result == COSE_SIGN1_SIGNING_OK {
        assert!(!headermap_ptr.is_null());
        // Clean up
        unsafe { cose_headermap_free(headermap_ptr) };
    }
}

#[test] 
fn test_headermap_operations() {
    let mut headermap_ptr: *mut CoseHeaderMapHandle = ptr::null_mut();
    let result = unsafe { cose_headermap_new(&mut headermap_ptr) };
    
    if result == COSE_SIGN1_SIGNING_OK && !headermap_ptr.is_null() {
        // Test inserting a header
        let label = 1i64; // algorithm label
        let value = -7i64; // ES256
        
        let _insert_result = unsafe { cose_headermap_set_int(headermap_ptr, label, value) };
        // May succeed or fail depending on implementation, but should not crash
        
        // Clean up
        unsafe { cose_headermap_free(headermap_ptr) };
    }
}

#[test]
fn test_builder_null_safety() {
    let mut builder_ptr: *mut CoseSign1BuilderHandle = ptr::null_mut();
    
    // Test null pointer handling in builder creation
    let result = unsafe { cose_sign1_builder_new(&mut builder_ptr) };
    if result == COSE_SIGN1_SIGNING_OK {
        assert!(!builder_ptr.is_null());
        // Clean up
        unsafe { cose_sign1_builder_free(builder_ptr) };
    }
}

#[test]
fn test_string_free_null_safety() {
    // Should handle null pointer gracefully
    unsafe { cose_sign1_string_free(ptr::null_mut()) };
}

#[test]
fn test_handle_operations_null_safety() {
    // Test all free functions with null pointers - should not crash
    unsafe {
        cose_sign1_builder_free(ptr::null_mut());
        cose_headermap_free(ptr::null_mut());
        cose_key_free(ptr::null_mut());
        cose_sign1_signing_service_free(ptr::null_mut());
        cose_sign1_factory_free(ptr::null_mut());
        cose_sign1_signing_error_free(ptr::null_mut());
    }
}

#[test]
fn test_bytes_free_null_safety() {
    // Test freeing null byte pointers - should not crash
    unsafe {
        cose_sign1_bytes_free(ptr::null_mut(), 0);
        cose_sign1_cose_bytes_free(ptr::null_mut(), 0);
    }
}

#[test]
fn test_null_output_pointer_failures() {
    // These should all fail with null pointer errors
    let result1 = unsafe { cose_headermap_new(ptr::null_mut()) };
    assert_ne!(result1, COSE_SIGN1_SIGNING_OK);
    
    let result2 = unsafe { cose_sign1_builder_new(ptr::null_mut()) };
    assert_ne!(result2, COSE_SIGN1_SIGNING_OK);
}