// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Basic tests for Azure Artifact Signing FFI exports.

use cose_sign1_azure_artifact_signing_ffi::{
    cose_sign1_ats_abi_version,
    cose_sign1_validator_builder_with_ats_pack,
    cose_sign1_validator_builder_with_ats_pack_ex,
    cose_ats_trust_options_t,
};
use cose_sign1_validation_ffi::{cose_sign1_validator_builder_t, cose_status_t};
use std::ffi::CString;
use std::sync::Arc;

fn make_builder() -> Box<cose_sign1_validator_builder_t> {
    Box::new(cose_sign1_validator_builder_t {
        packs: Vec::new(),
        compiled_plan: None,
    })
}

#[test]
fn abi_version() {
    assert_eq!(cose_sign1_ats_abi_version(), 1);
}

#[test]
fn with_ats_pack_null_builder() {
    let status = cose_sign1_validator_builder_with_ats_pack(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_ats_pack_success() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_ats_pack(&mut *builder);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(builder.packs.len(), 1);
}

#[test]
fn with_ats_pack_ex_null_builder() {
    let status = cose_sign1_validator_builder_with_ats_pack_ex(
        std::ptr::null_mut(),
        std::ptr::null(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_ats_pack_ex_null_options() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_ats_pack_ex(
        &mut *builder,
        std::ptr::null(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_ats_pack_ex_with_options() {
    let endpoint = CString::new("https://ats.example.com").unwrap();
    let account = CString::new("myaccount").unwrap();
    let profile = CString::new("myprofile").unwrap();
    let opts = cose_ats_trust_options_t {
        endpoint: endpoint.as_ptr(),
        account_name: account.as_ptr(),
        certificate_profile_name: profile.as_ptr(),
    };
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_ats_pack_ex(
        &mut *builder,
        &opts,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_ats_pack_ex_null_strings() {
    let opts = cose_ats_trust_options_t {
        endpoint: std::ptr::null(),
        account_name: std::ptr::null(),
        certificate_profile_name: std::ptr::null(),
    };
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_ats_pack_ex(
        &mut *builder,
        &opts,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}
