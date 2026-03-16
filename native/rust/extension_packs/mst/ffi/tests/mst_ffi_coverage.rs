// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for MST FFI — targeting uncovered null-safety and client error paths.

use cose_sign1_transparent_mst_ffi::{
    cose_mst_bytes_free, cose_mst_client_free, cose_mst_client_new, cose_mst_string_free,
    cose_mst_trust_options_t,
    cose_sign1_mst_create_entry, cose_sign1_mst_get_entry_statement,
    cose_sign1_mst_make_transparent,
    cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_not_present,
    cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted,
    cose_sign1_mst_trust_policy_builder_require_receipt_present,
    cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified,
    cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq,
    cose_sign1_mst_trust_policy_builder_require_receipt_trusted,
    cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains,
    cose_sign1_validator_builder_with_mst_pack,
    cose_sign1_validator_builder_with_mst_pack_ex,
    MstClientHandle,
};
use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t,
};
use std::ffi::{c_char, CString};
use std::ptr;

// ========================================================================
// Helper: create a validator builder with MST pack
// ========================================================================

fn make_builder_with_pack() -> Box<cose_sign1_validator_builder_t> {
    let mut builder = Box::new(cose_sign1_validator_builder_t {
        packs: Vec::new(),
        compiled_plan: None,
    });
    let status = cose_sign1_validator_builder_with_mst_pack(&mut *builder);
    assert_eq!(status, cose_status_t::COSE_OK);
    builder
}

fn make_policy() -> Box<cose_trust_policy_builder_t> {
    use cose_sign1_transparent_mst::validation::pack::MstTrustPack;
    use cose_sign1_validation::fluent::{CoseSign1TrustPack, TrustPlanBuilder};
    use std::sync::Arc;
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(MstTrustPack::default());
    let builder = TrustPlanBuilder::new(vec![pack]);
    Box::new(cose_trust_policy_builder_t {
        builder: Some(builder),
    })
}

// ========================================================================
// make_transparent: null output pointers
// ========================================================================

#[test]
fn make_transparent_null_out_bytes() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let cose = b"fake-cose-bytes";
    let status = cose_sign1_mst_make_transparent(
        client,
        cose.as_ptr(),
        cose.len(),
        ptr::null_mut(), // null out_bytes
        ptr::null_mut(), // null out_len
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// make_transparent: null client
// ========================================================================

#[test]
fn make_transparent_null_client() {
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let cose = b"fake-cose-bytes";
    let status = cose_sign1_mst_make_transparent(
        ptr::null(),
        cose.as_ptr(),
        cose.len(),
        &mut out_bytes,
        &mut out_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// make_transparent: null cose_bytes
// ========================================================================

#[test]
fn make_transparent_null_cose_bytes() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let status = cose_sign1_mst_make_transparent(
        client,
        ptr::null(),
        0,
        &mut out_bytes,
        &mut out_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// create_entry: null output pointers
// ========================================================================

#[test]
fn create_entry_null_out() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let cose = b"fake";
    let status = cose_sign1_mst_create_entry(
        client,
        cose.as_ptr(),
        cose.len(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// create_entry: null client
// ========================================================================

#[test]
fn create_entry_null_client() {
    let cose = b"fake";
    let mut op_id: *mut c_char = ptr::null_mut();
    let mut entry_id: *mut c_char = ptr::null_mut();
    let status = cose_sign1_mst_create_entry(
        ptr::null(),
        cose.as_ptr(),
        cose.len(),
        &mut op_id,
        &mut entry_id,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// create_entry: null cose_bytes
// ========================================================================

#[test]
fn create_entry_null_cose_bytes() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let mut op_id: *mut c_char = ptr::null_mut();
    let mut entry_id: *mut c_char = ptr::null_mut();
    let status = cose_sign1_mst_create_entry(
        client,
        ptr::null(),
        0,
        &mut op_id,
        &mut entry_id,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// get_entry_statement: null output pointers
// ========================================================================

#[test]
fn get_entry_statement_null_out() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let entry_id = CString::new("fake-entry").unwrap();
    let status = cose_sign1_mst_get_entry_statement(
        client,
        entry_id.as_ptr(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// get_entry_statement: null client
// ========================================================================

#[test]
fn get_entry_statement_null_client() {
    let entry_id = CString::new("fake-entry").unwrap();
    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let status = cose_sign1_mst_get_entry_statement(
        ptr::null(),
        entry_id.as_ptr(),
        &mut out_bytes,
        &mut out_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// get_entry_statement: null entry_id
// ========================================================================

#[test]
fn get_entry_statement_null_entry_id() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    assert_eq!(
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client),
        cose_status_t::COSE_OK
    );

    let mut out_bytes: *mut u8 = ptr::null_mut();
    let mut out_len: usize = 0;
    let status = cose_sign1_mst_get_entry_statement(
        client,
        ptr::null(),
        &mut out_bytes,
        &mut out_len,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// client_new: invalid URL
// ========================================================================

#[test]
fn client_new_invalid_url() {
    let bad_url = CString::new("not a url at all").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    let status = cose_mst_client_new(bad_url.as_ptr(), ptr::null(), ptr::null(), &mut client);
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// bytes_free and string_free: non-null handling (exercised indirectly)
// ========================================================================

#[test]
fn bytes_free_null_is_safe() {
    unsafe { cose_mst_bytes_free(ptr::null_mut(), 0) };
    unsafe { cose_mst_bytes_free(ptr::null_mut(), 100) };
}

#[test]
fn string_free_null_is_safe() {
    unsafe { cose_mst_string_free(ptr::null_mut()) };
}

// ========================================================================
// Trust policy builders: null string arguments
// ========================================================================

#[test]
fn policy_require_receipt_not_present_null() {
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_not_present(ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_signature_verified_null() {
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_signature_verified(ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_signature_not_verified_null() {
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_signature_not_verified(ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_not_trusted_null() {
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_not_trusted(ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_kid_eq_null_builder() {
    let kid = CString::new("x").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(ptr::null_mut(), kid.as_ptr()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_kid_contains_null_builder() {
    let needle = CString::new("x").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(
            ptr::null_mut(),
            needle.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_issuer_eq_null_builder() {
    let issuer = CString::new("x").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(
            ptr::null_mut(),
            issuer.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_trusted_null() {
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_trusted(ptr::null_mut()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_receipt_trusted_from_issuer_null_builder() {
    let needle = CString::new("x").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            ptr::null_mut(),
            needle.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_statement_sha256_eq_null_builder() {
    let hex = CString::new("abc").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
            ptr::null_mut(),
            hex.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_statement_coverage_eq_null_builder() {
    let cov = CString::new("full").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
            ptr::null_mut(),
            cov.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_require_statement_coverage_contains_null_builder() {
    let needle = CString::new("sha").unwrap();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
            ptr::null_mut(),
            needle.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

// ========================================================================
// Trust policy builders: null string value (not null builder)
// ========================================================================

#[test]
fn policy_issuer_eq_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_issuer_eq(
            &mut *pb,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_kid_eq_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_eq(&mut *pb, ptr::null()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_kid_contains_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_kid_contains(&mut *pb, ptr::null()),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_trusted_from_issuer_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            &mut *pb,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_statement_sha256_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
            &mut *pb,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_statement_coverage_eq_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
            &mut *pb,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn policy_statement_coverage_contains_null_string() {
    let mut pb = make_policy();
    assert_ne!(
        cose_sign1_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
            &mut *pb,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );
}

// ========================================================================
// with_mst_pack_ex: null builder
// ========================================================================

#[test]
fn with_mst_pack_ex_null_builder() {
    let status =
        cose_sign1_validator_builder_with_mst_pack_ex(ptr::null_mut(), ptr::null());
    assert_ne!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// client_new: exercise all optional parameter combinations
// ========================================================================

#[test]
fn client_new_no_api_version_no_key() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    let status =
        cose_mst_client_new(endpoint.as_ptr(), ptr::null(), ptr::null(), &mut client);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!client.is_null());
    unsafe { cose_mst_client_free(client) };
}

#[test]
fn client_new_with_api_version_only() {
    let endpoint = CString::new("https://mst.example.com").unwrap();
    let api_ver = CString::new("2025-01-01").unwrap();
    let mut client: *mut MstClientHandle = ptr::null_mut();
    let status =
        cose_mst_client_new(endpoint.as_ptr(), api_ver.as_ptr(), ptr::null(), &mut client);
    assert_eq!(status, cose_status_t::COSE_OK);
    unsafe { cose_mst_client_free(client) };
}

// ========================================================================
// pack_ex: allow_network=true with null JWKS
// ========================================================================

#[test]
fn pack_ex_online_mode_null_jwks() {
    let mut builder = Box::new(cose_sign1_validator_builder_t {
        packs: Vec::new(),
        compiled_plan: None,
    });
    let opts = cose_mst_trust_options_t {
        allow_network: true,
        offline_jwks_json: ptr::null(),
        jwks_api_version: ptr::null(),
    };
    let status = cose_sign1_validator_builder_with_mst_pack_ex(&mut *builder, &opts);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(builder.packs.len(), 1);
}

// ========================================================================
// string_from_ptr: invalid UTF-8
// ========================================================================

#[test]
fn client_new_invalid_utf8_endpoint() {
    let invalid = [0xFFu8, 0xFE, 0x00]; // null-terminated invalid UTF-8
    let mut client: *mut MstClientHandle = ptr::null_mut();
    let status = cose_mst_client_new(
        invalid.as_ptr() as *const c_char,
        ptr::null(),
        ptr::null(),
        &mut client,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn policy_issuer_contains_invalid_utf8() {
    let mut pb = make_policy();
    let invalid = [0xFFu8, 0xFE, 0x00];
    let status = cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(
        &mut *pb,
        invalid.as_ptr() as *const c_char,
    );
    assert_ne!(status, cose_status_t::COSE_OK);
}
