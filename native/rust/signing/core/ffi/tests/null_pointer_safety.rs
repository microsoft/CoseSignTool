// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple null pointer safety tests for signing FFI inner functions.

use cose_sign1_signing_ffi::{
    impl_factory_create_inner, impl_factory_sign_direct_inner,
    error::{FFI_ERR_NULL_POINTER}
};
use std::ptr;

#[test]
fn test_null_pointer_validation_factory_create() {
    let result = impl_factory_create_inner(
        ptr::null(),     // service - should be invalid
        ptr::null_mut(), // out_factory
        ptr::null_mut(), // out_error
    );
    
    assert_eq!(result, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_null_pointer_validation_factory_sign_direct() {
    let result = impl_factory_sign_direct_inner(
        ptr::null(),     // factory - should be invalid
        ptr::null(),     // payload
        0,               // payload_len
        ptr::null(),     // content_type
        ptr::null_mut(), // out_cose_bytes
        ptr::null_mut(), // out_cose_len
        ptr::null_mut(), // out_error
    );
    
    assert_eq!(result, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_null_output_pointers_factory_create() {
    let result = impl_factory_create_inner(
        0x1 as *const _,   // service - non-null but invalid pointer
        ptr::null_mut(),   // out_factory - null should fail
        ptr::null_mut(),   // out_error
    );
    
    assert_eq!(result, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_null_output_pointers_factory_sign() {
    let result = impl_factory_sign_direct_inner(
        0x1 as *const _,   // factory - non-null but invalid pointer
        ptr::null(),       // payload
        0,                 // payload_len
        0x1 as *const _,   // content_type - non-null but invalid
        ptr::null_mut(),   // out_cose_bytes - null should fail
        ptr::null_mut(),   // out_cose_len - null should fail
        ptr::null_mut(),   // out_error
    );
    
    assert_eq!(result, FFI_ERR_NULL_POINTER);
}