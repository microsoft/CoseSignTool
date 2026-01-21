use cose_sign1_validation::fluent::TrustPlanBuilder;
use cose_sign1_validation_ffi::{cose_status_t, cose_trust_policy_builder_t};
use cose_sign1_validation_ffi_akv::*;
use cose_sign1_validation_ffi_trust::*;
use std::ffi::CString;
use std::ptr;

fn minimal_cose_sign1() -> Vec<u8> {
    vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g']
}

#[test]
fn akv_policy_helpers_compile_without_trust_pack() {
    let mut policy = cose_trust_policy_builder_t {
        builder: Some(TrustPlanBuilder::new(Vec::new())),
    };

    let status = cose_akv_trust_policy_builder_require_azure_key_vault_kid(&mut policy);
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(&mut policy);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn akv_ffi_end_to_end_calls() {
    // Base builder.
    let mut builder: *mut cose_sign1_validation_ffi::cose_validator_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );
    assert!(!builder.is_null());

    // Pack add: default options.
    assert_eq!(cose_validator_builder_with_akv_pack(builder), cose_status_t::COSE_OK);

    // Pack add: null options => default options branch.
    assert_eq!(
        cose_validator_builder_with_akv_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    // Pack add: options provided but patterns empty => defaults branch.
    let empty_list: [*const i8; 1] = [ptr::null()];
    let opts_empty = cose_akv_trust_options_t {
        require_azure_key_vault_kid: true,
        allowed_kid_patterns: empty_list.as_ptr(),
    };
    assert_eq!(
        cose_validator_builder_with_akv_pack_ex(builder, &opts_empty),
        cose_status_t::COSE_OK
    );

    // Pack add: options with explicit patterns.
    let p1 = CString::new("https://*.vault.azure.net/keys/*").unwrap();
    let patterns: [*const i8; 2] = [p1.as_ptr(), ptr::null()];
    let opts_patterns = cose_akv_trust_options_t {
        require_azure_key_vault_kid: false,
        allowed_kid_patterns: patterns.as_ptr(),
    };
    assert_eq!(
        cose_validator_builder_with_akv_pack_ex(builder, &opts_patterns),
        cose_status_t::COSE_OK
    );

    // Create policy builder from configured packs.
    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // Exercise policy helper exports.
    assert_eq!(
        cose_akv_trust_policy_builder_require_azure_key_vault_kid(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_akv_trust_policy_builder_require_not_azure_key_vault_kid(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(policy),
        cose_status_t::COSE_OK
    );

    // Compile policy and attach it.
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

    // Build a validator and call validate_bytes to ensure everything links and runs.
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
