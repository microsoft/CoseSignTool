use cose_sign1_validation_ffi::{
    cose_status_t, cose_trust_policy_builder_t, cose_validator_builder_free, cose_validator_builder_new,
    cose_validator_builder_t,
};
use cose_sign1_validation_ffi_mst::*;
use cose_sign1_validation_ffi_trust::{
    cose_trust_policy_builder_free, cose_trust_policy_builder_new_from_validator_builder,
};
use std::ffi::CString;
use std::ptr;

#[test]
fn mst_ffi_exports_succeed_with_valid_inputs() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Cover the "online" (default) constructor.
    assert_eq!(
        cose_validator_builder_with_mst_pack(builder),
        cose_status_t::COSE_OK
    );

    // Cover options parsing in the "custom" constructor.
    let offline_jwks = CString::new("{}").unwrap();
    let api_version = CString::new("2024-01-01").unwrap();
    let opts = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: offline_jwks.as_ptr(),
        jwks_api_version: api_version.as_ptr(),
    };
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    // Create a policy builder so we can exercise all trust-policy helper exports.
    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_present(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_not_present(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_signature_verified(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_signature_not_verified(policy),
        cose_status_t::COSE_OK
    );

    let needle = CString::new("needle").unwrap();
    let issuer = CString::new("issuer").unwrap();
    let kid = CString::new("kid").unwrap();

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy, needle.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy, issuer.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_kid_eq(policy, kid.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_kid_contains(policy, needle.as_ptr()),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_trusted(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_not_trusted(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            policy,
            needle.as_ptr(),
        ),
        cose_status_t::COSE_OK
    );

    let sha256_hex = CString::new("0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(policy, sha256_hex.as_ptr()),
        cose_status_t::COSE_OK
    );

    let coverage = CString::new("coverage").unwrap();
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(policy, coverage.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
            policy,
            needle.as_ptr(),
        ),
        cose_status_t::COSE_OK
    );

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
}
