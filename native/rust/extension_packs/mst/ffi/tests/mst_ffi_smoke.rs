// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests for the MST FFI crate.

use cose_sign1_transparent_mst_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use std::ffi::CString;
use std::ptr;

// ========================================================================
// Pack registration
// ========================================================================

#[test]
fn add_mst_pack_null_builder() {
    let result = cose_sign1_validator_builder_with_mst_pack(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn add_mst_pack_default() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_validator_builder_with_mst_pack(builder),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

#[test]
fn add_mst_pack_ex_null_options() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_validator_builder_with_mst_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

#[test]
fn add_mst_pack_ex_with_options() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let jwks = CString::new(r#"{"keys":[]}"#).unwrap();
    let api_ver = CString::new("2024-01-01").unwrap();

    let opts = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: jwks.as_ptr(),
        jwks_api_version: api_ver.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

#[test]
fn add_mst_pack_ex_null_string_fields() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let opts = cose_mst_trust_options_t {
        allow_network: true,
        offline_jwks_json: ptr::null(),
        jwks_api_version: ptr::null(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder) };
}

// ========================================================================
// Trust policy builders
// ========================================================================

fn make_policy() -> *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder);
    cose_sign1_validator_builder_with_mst_pack(builder);

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    cose_sign1_validation_primitives_ffi::cose_sign1_trust_policy_builder_new_from_validator_builder(
        builder, &mut policy,
    );
    policy
}

#[test]
fn policy_require_receipt_present() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_present(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_not_present() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_not_present(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_signature_verified() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_signature_not_verified() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_issuer_contains() {
    let p = make_policy();
    let needle = CString::new("example.com").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(p, needle.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_issuer_eq() {
    let p = make_policy();
    let issuer = CString::new("mst.example.com").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(p, issuer.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_kid_eq() {
    let p = make_policy();
    let kid = CString::new("key-1").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(p, kid.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_kid_contains() {
    let p = make_policy();
    let needle = CString::new("key").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(p, needle.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_trusted() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_trusted(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_not_trusted() {
    let p = make_policy();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(p), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_trusted_from_issuer_contains() {
    let p = make_policy();
    let needle = CString::new("example").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(p, needle.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_statement_sha256_eq() {
    let p = make_policy();
    let hex = CString::new("abcdef0123456789").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(p, hex.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_statement_coverage_eq() {
    let p = make_policy();
    let cov = CString::new("full").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(p, cov.as_ptr()), cose_status_t::COSE_OK);
}

#[test]
fn policy_require_receipt_statement_coverage_contains() {
    let p = make_policy();
    let needle = CString::new("sha256").unwrap();
    assert_eq!(cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(p, needle.as_ptr()), cose_status_t::COSE_OK);
}

// ========================================================================
// Null safety on policy builders
// ========================================================================

#[test]
fn policy_null_builder_errors() {
    assert_ne!(cose_sign1_mst_trust_policy_builder_require_receipt_present(ptr::null_mut()), cose_status_t::COSE_OK);
    assert_ne!(cose_sign1_mst_trust_policy_builder_require_receipt_trusted(ptr::null_mut()), cose_status_t::COSE_OK);
}

#[test]
fn policy_null_string_errors() {
    let p = make_policy();
    assert_ne!(cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(p, ptr::null()), cose_status_t::COSE_OK);
}

// ========================================================================
// Client lifecycle
// ========================================================================

#[test]
fn client_new_and_free() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();

    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );
    assert!(!client.is_null());

    unsafe { cose_mst_client_free(client) };
}

#[test]
fn client_new_with_api_key() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let api_ver = CString::new("2024-01-01").unwrap();
    let api_key = CString::new("secret-key").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();

    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), api_ver.as_ptr(), api_key.as_ptr(), &mut client),
        cose_status_t::COSE_OK
    );
    assert!(!client.is_null());

    unsafe { cose_mst_client_free(client) };
}

#[test]
fn client_free_null() {
    unsafe { cose_mst_client_free(ptr::null_mut()) };
}

#[test]
fn client_new_null_endpoint() {
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_ne!(
        cose_mst_client_new(ptr::null(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );
}

#[test]
fn client_new_null_out() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    assert_ne!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}
