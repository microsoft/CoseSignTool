// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for MST FFI exports — trust pack registration and policy builder helpers.

use cose_sign1_transparent_mst_ffi::{
    cose_sign1_validator_builder_with_mst_pack,
    cose_sign1_validator_builder_with_mst_pack_ex,
    cose_sign1_mst_trust_policy_builder_require_receipt_present,
    cose_sign1_mst_trust_policy_builder_require_receipt_not_present,
    cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified,
    cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified,
    cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_trusted,
    cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted,
    cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains,
    cose_mst_client_new,
    cose_mst_client_free,
    cose_mst_bytes_free,
    cose_mst_string_free,
    cose_mst_trust_options_t,
    MstClientHandle,
};
use cose_sign1_validation_ffi::{cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t};
use cose_sign1_validation::fluent::{TrustPlanBuilder, CoseSign1TrustPack};
use cose_sign1_transparent_mst::validation::pack::MstTrustPack;
use std::ffi::CString;
use std::sync::Arc;

fn make_builder() -> Box<cose_sign1_validator_builder_t> {
    Box::new(cose_sign1_validator_builder_t {
        packs: Vec::new(),
        compiled_plan: None,
    })
}

fn make_policy_builder_with_mst() -> Box<cose_trust_policy_builder_t> {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(MstTrustPack::default());
    let builder = TrustPlanBuilder::new(vec![pack]);
    Box::new(cose_trust_policy_builder_t {
        builder: Some(builder),
    })
}

// ========================================================================
// Validator builder — add MST pack
// ========================================================================

#[test]
fn with_mst_pack_null_builder() {
    let status = cose_sign1_validator_builder_with_mst_pack(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_mst_pack_success() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_mst_pack(&mut *builder);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(builder.packs.len(), 1);
}

#[test]
fn with_mst_pack_ex_null_builder() {
    let status = cose_sign1_validator_builder_with_mst_pack_ex(
        std::ptr::null_mut(),
        std::ptr::null(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_mst_pack_ex_null_options() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_mst_pack_ex(
        &mut *builder,
        std::ptr::null(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_mst_pack_ex_with_options() {
    let jwks = CString::new(r#"{"keys":[]}"#).unwrap();
    let api_ver = CString::new("2024-01-01").unwrap();
    let opts = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: jwks.as_ptr(),
        jwks_api_version: api_ver.as_ptr(),
    };
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_mst_pack_ex(
        &mut *builder,
        &opts,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// Trust policy builder helpers
// ========================================================================

#[test]
fn require_receipt_present_null() {
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_present(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_present() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_present(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_not_present() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_not_present(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_signature_verified() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_signature_not_verified() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_trusted() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_trusted(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_receipt_not_trusted() {
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_statement_sha256_eq() {
    let sha = CString::new("abc123def456").unwrap();
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
        &mut *pb, sha.as_ptr(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_statement_coverage_eq() {
    let cov = CString::new("full").unwrap();
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
        &mut *pb, cov.as_ptr(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_statement_coverage_contains() {
    let substr = CString::new("sha256").unwrap();
    let mut pb = make_policy_builder_with_mst();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
        &mut *pb, substr.as_ptr(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// Free null handles
// ========================================================================

#[test]
fn free_null_client() {
    unsafe { cose_mst_client_free(std::ptr::null_mut()) }; // should not crash
}

#[test]
fn free_null_bytes() {
    unsafe { cose_mst_bytes_free(std::ptr::null_mut(), 0) }; // should not crash
}

#[test]
fn free_null_string() {
    unsafe { cose_mst_string_free(std::ptr::null_mut()) }; // should not crash
}

// ========================================================================
// Trust policy builder — string-param functions
// ========================================================================

#[test]
fn require_issuer_contains() {
    let mut pb = make_policy_builder_with_mst();
    let needle = CString::new("mst.example.com").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(&mut *pb, needle.as_ptr());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_issuer_eq() {
    let mut pb = make_policy_builder_with_mst();
    let issuer = CString::new("mst.example.com").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(&mut *pb, issuer.as_ptr());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_kid_eq() {
    let mut pb = make_policy_builder_with_mst();
    let kid = CString::new("key-id-123").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(&mut *pb, kid.as_ptr());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_kid_contains() {
    let mut pb = make_policy_builder_with_mst();
    let needle = CString::new("key-").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(&mut *pb, needle.as_ptr());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_trusted_from_issuer_contains() {
    let mut pb = make_policy_builder_with_mst();
    let needle = CString::new("microsoft.com").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(&mut *pb, needle.as_ptr());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_issuer_contains_null_builder() {
    let needle = CString::new("x").unwrap();
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(std::ptr::null_mut(), needle.as_ptr());
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// MST client — create and free
// ========================================================================

#[test]
fn client_new_creates_handle() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let api_ver = CString::new("2024-01-01").unwrap();
    let mut client: *mut MstClientHandle = std::ptr::null_mut();

    let status = cose_mst_client_new(
        endpoint.as_ptr(),
        api_ver.as_ptr(),
        std::ptr::null(), // no api key
        &mut client,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!client.is_null());
    unsafe { cose_mst_client_free(client) };
}

#[test]
fn client_new_with_api_key() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let api_ver = CString::new("2024-01-01").unwrap();
    let api_key = CString::new("secret-key").unwrap();
    let mut client: *mut MstClientHandle = std::ptr::null_mut();

    let status = cose_mst_client_new(
        endpoint.as_ptr(),
        api_ver.as_ptr(),
        api_key.as_ptr(),
        &mut client,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!client.is_null());
    unsafe { cose_mst_client_free(client) };
}

#[test]
fn client_new_null_endpoint() {
    let mut client: *mut MstClientHandle = std::ptr::null_mut();
    let status = cose_mst_client_new(
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null(),
        &mut client,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn client_new_null_output() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let status = cose_mst_client_new(
        endpoint.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        std::ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}
