use cose_sign1_validation_ffi::{
    cose_last_error_message_utf8, cose_status_t, cose_string_free, cose_trust_policy_builder_t,
    cose_validator_builder_free, cose_validator_builder_new, cose_validator_builder_t,
};
use cose_sign1_validation_ffi_mst::*;
use cose_sign1_validation_ffi_trust::{
    cose_trust_policy_builder_free, cose_trust_policy_builder_new_from_validator_builder,
};
use std::ffi::{c_char, CStr, CString};
use std::ptr;

fn last_error_string() -> Option<String> {
    let p = cose_last_error_message_utf8();
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
    unsafe { cose_string_free(p) };
    Some(s)
}

#[test]
fn mst_pack_helpers_reject_null_builder() {
    assert_eq!(
        cose_validator_builder_with_mst_pack(ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(ptr::null_mut(), ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());
}

#[test]
fn mst_pack_ex_rejects_invalid_utf8_in_options() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);

    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    let bad_ptr = bad_utf8.as_ptr() as *const c_char;

    // offline_jwks_json invalid UTF-8
    let opts = cose_mst_trust_options_t {
        allow_network: true,
        offline_jwks_json: bad_ptr,
        jwks_api_version: ptr::null(),
    };
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // jwks_api_version invalid UTF-8
    let opts = cose_mst_trust_options_t {
        allow_network: true,
        offline_jwks_json: ptr::null(),
        jwks_api_version: bad_ptr,
    };
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // options can be NULL (treated as online)
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    cose_validator_builder_free(builder);
}

#[test]
fn mst_policy_helpers_reject_null_policy_and_null_strings() {
    // Null policy hits the with_trust_policy_builder_mut error path.
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_present(ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Now create a real policy builder to test string parsing errors.
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);

    // Seed MST pack so downstream rule building has the pack available.
    assert_eq!(cose_validator_builder_with_mst_pack(builder), cose_status_t::COSE_OK);

    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_kid_eq(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_kid_contains(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Invalid UTF-8 string args.
    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    let bad_ptr = bad_utf8.as_ptr() as *const c_char;

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy, bad_ptr),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Invalid UTF-8 in SHA256 string.
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(policy, bad_ptr),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Valid strings still succeed after prior errors.
    let issuer = CString::new("issuer").unwrap();
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy, issuer.as_ptr()),
        cose_status_t::COSE_OK
    );

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
}
