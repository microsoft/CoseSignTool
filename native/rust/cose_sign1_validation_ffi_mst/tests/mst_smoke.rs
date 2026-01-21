use cose_sign1_validation_ffi::cose_status_t;
use cose_sign1_validation_ffi_mst::*;
use cose_sign1_validation_ffi_trust::*;
use std::ffi::CString;
use std::ptr;

fn minimal_cose_sign1() -> Vec<u8> {
    vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g']
}

#[test]
fn mst_ffi_end_to_end_calls() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_validator_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );
    assert!(!builder.is_null());

    // Pack add: default and custom option branches.
    assert_eq!(cose_validator_builder_with_mst_pack(builder), cose_status_t::COSE_OK);
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    let jwks = CString::new("{\"keys\":[]}").unwrap();
    let api_version = CString::new("2023-11-01").unwrap();
    let opts = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: jwks.as_ptr(),
        jwks_api_version: api_version.as_ptr(),
    };
    assert_eq!(
        cose_validator_builder_with_mst_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    // Create a policy builder and exercise all MST policy helpers.
    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
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

    let issuer = CString::new("issuer").unwrap();
    let needle = CString::new("iss").unwrap();
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy, needle.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy, issuer.as_ptr()),
        cose_status_t::COSE_OK
    );

    let kid = CString::new("kid").unwrap();
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
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(policy, issuer.as_ptr()),
        cose_status_t::COSE_OK
    );

    let sha256_hex = CString::new("0000000000000000000000000000000000000000000000000000000000000000")
        .unwrap();
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
        cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(policy, needle.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Compile and attach.
    let mut plan: *mut cose_compiled_trust_plan_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_trust_policy_builder_free(policy);

    assert_eq!(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        cose_status_t::COSE_OK
    );
    cose_compiled_trust_plan_free(plan);

    // Validate once (result may be failure, but should be COSE_OK).
    let mut validator: *mut cose_sign1_validation_ffi::cose_validator_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    let bytes = minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_ffi::cose_validation_result_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_validate_bytes(
            validator,
            bytes.as_ptr(),
            bytes.len(),
            ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK
    );
    assert!(!result.is_null());
    cose_sign1_validation_ffi::cose_validation_result_free(result);

    cose_sign1_validation_ffi::cose_validator_free(validator);
    cose_sign1_validation_ffi::cose_validator_builder_free(builder);
}
