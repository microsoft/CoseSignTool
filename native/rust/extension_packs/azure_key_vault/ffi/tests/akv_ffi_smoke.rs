// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests for the Azure Key Vault FFI crate.

use cose_sign1_azure_key_vault_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use std::ffi::CString;
use std::ptr;

#[test]
fn add_akv_pack_null_builder() {
    let result = cose_sign1_validator_builder_with_akv_pack(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn add_akv_pack_default() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_validator_builder_with_akv_pack(builder),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

#[test]
fn add_akv_pack_ex_null_options() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_validator_builder_with_akv_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

#[test]
fn add_akv_pack_ex_null_builder() {
    let result = cose_sign1_validator_builder_with_akv_pack_ex(ptr::null_mut(), ptr::null());
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn client_free_null() {
    unsafe { cose_akv_key_client_free(ptr::null_mut()) };
}
