// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests for the Azure Artifact Signing FFI crate.

use cose_sign1_azure_artifact_signing_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use std::ffi::CString;
use std::ptr;

#[test]
fn abi_version() {
    assert_eq!(cose_sign1_ats_abi_version(), 1);
}

#[test]
fn add_ats_pack_null_builder() {
    let result = cose_sign1_validator_builder_with_ats_pack(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn add_ats_pack_default() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_validator_builder_with_ats_pack(builder),
        cose_status_t::COSE_OK
    );

    unsafe {
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
    }
}

#[test]
fn add_ats_pack_ex_null_options() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    // null options → uses defaults
    assert_eq!(
        cose_sign1_validator_builder_with_ats_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    unsafe {
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
    }
}

#[test]
fn add_ats_pack_ex_with_options() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let endpoint = CString::new("https://ats.example.com").unwrap();
    let account = CString::new("myaccount").unwrap();
    let profile = CString::new("myprofile").unwrap();

    let opts = cose_ats_trust_options_t {
        endpoint: endpoint.as_ptr(),
        account_name: account.as_ptr(),
        certificate_profile_name: profile.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_ats_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    unsafe {
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
    }
}

#[test]
fn add_ats_pack_ex_null_fields() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let opts = cose_ats_trust_options_t {
        endpoint: ptr::null(),
        account_name: ptr::null(),
        certificate_profile_name: ptr::null(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_ats_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    unsafe {
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
    }
}

#[test]
fn add_ats_pack_ex_null_builder() {
    let result = cose_sign1_validator_builder_with_ats_pack_ex(ptr::null_mut(), ptr::null());
    assert_ne!(result, cose_status_t::COSE_OK);
}
