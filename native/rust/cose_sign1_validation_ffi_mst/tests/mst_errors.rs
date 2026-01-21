use cose_sign1_validation_ffi::{
    cose_last_error_message_utf8, cose_status_t, cose_string_free, cose_trust_policy_builder_t,
    cose_validator_builder_free, cose_validator_builder_new, cose_validator_builder_t,
};
use cose_sign1_validation_ffi_mst::*;
use cose_sign1_validation_ffi_trust::{
    cose_trust_policy_builder_free, cose_trust_policy_builder_new_from_validator_builder,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
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

fn assert_err(status: cose_status_t) {
    assert_eq!(status, cose_status_t::COSE_ERR);
    assert!(last_error_string().is_some());
}

fn invalid_utf8_ptr() -> *const c_char {
    // Valid C string (NUL-terminated) but invalid UTF-8.
    static BYTES: [u8; 2] = [0xFF, 0x00];
    BYTES.as_ptr() as *const c_char
}

#[test]
fn mst_pack_and_policy_error_branches_are_exercised() {
    // Null builder error paths.
    assert_err(cose_validator_builder_with_mst_pack(ptr::null_mut()));
    assert_err(cose_validator_builder_with_mst_pack_ex(ptr::null_mut(), ptr::null()));

    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Options parsing: all-null optional strings.
    let opts_all_null = cose_mst_trust_options_t {
        allow_network: true,
        offline_jwks_json: ptr::null(),
        jwks_api_version: ptr::null(),
    };
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, &opts_all_null),
        cose_status_t::COSE_OK
    );

    // Options parsing: invalid UTF-8 for offline_jwks_json.
    let opts_bad_offline = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: invalid_utf8_ptr(),
        jwks_api_version: ptr::null(),
    };
    assert_err(cose_validator_builder_with_mst_pack_ex(builder, &opts_bad_offline));

    // Options parsing: invalid UTF-8 for jwks_api_version.
    let opts_bad_api_version = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: ptr::null(),
        jwks_api_version: invalid_utf8_ptr(),
    };
    assert_err(cose_validator_builder_with_mst_pack_ex(builder, &opts_bad_api_version));

    // Create a policy builder so we can exercise string parsing failures.
    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // Null policy_builder paths.
    assert_err(cose_mst_trust_policy_builder_require_receipt_present(ptr::null_mut()));
    assert_err(cose_mst_trust_policy_builder_require_receipt_signature_verified(
        ptr::null_mut(),
    ));

    // For string-taking helpers: valid string + null policy (covers policy_builder null after parsing).
    let needle = CString::new("needle").unwrap();
    assert_err(cose_mst_trust_policy_builder_require_receipt_issuer_contains(
        ptr::null_mut(),
        needle.as_ptr(),
    ));

    // String parsing error branches (null and invalid UTF-8).
    assert_err(cose_mst_trust_policy_builder_require_receipt_issuer_contains(
        policy,
        ptr::null(),
    ));
    assert_err(cose_mst_trust_policy_builder_require_receipt_kid_contains(
        policy,
        invalid_utf8_ptr(),
    ));

    // SHA-256 helper also exercises string_from_ptr.
    assert_err(cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
        policy,
        ptr::null(),
    ));

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
}
