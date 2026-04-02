// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for trust policy builder FFI functions.
//!
//! This test file exercises all the `cose_sign1_trust_policy_builder_require_*`
//! functions to achieve maximum line coverage.

use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t,
};
use cose_sign1_validation_primitives_ffi::*;
use std::ffi::CString;
use std::ptr;

/// Helper to create a validator builder for testing.
fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status =
        unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    builder
}

/// Helper to create a trust policy builder from a validator builder.
fn create_trust_policy_builder() -> *mut cose_trust_policy_builder_t {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder,
            &mut policy_builder,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!policy_builder.is_null());

    // Clean up validator builder as it's no longer needed
    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder) };

    policy_builder
}

/// Helper to compile a policy and clean up resources.
fn compile_and_cleanup(policy_builder: *mut cose_trust_policy_builder_t) {
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder, &mut plan) };

    // Policy builder is consumed by compile, don't free it

    if status == cose_status_t::COSE_OK && !plan.is_null() {
        unsafe { cose_sign1_compiled_trust_plan_free(plan) };
    }
}

#[test]
fn test_trust_policy_builder_lifecycle() {
    let policy_builder = create_trust_policy_builder();

    // Test that we can compile an empty policy
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder, &mut plan) };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    unsafe { cose_sign1_compiled_trust_plan_free(plan) };
}

#[test]
fn test_require_content_type_functions() {
    let policy_builder = create_trust_policy_builder();

    // Test require_content_type_non_empty
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_content_type_non_empty(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_content_type_eq
    let content_type = CString::new("application/cose").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_content_type_eq(
            policy_builder,
            content_type.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_detached_payload_functions() {
    let policy_builder = create_trust_policy_builder();

    // Test require_detached_payload_present
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_detached_payload_present(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_detached_payload_absent
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_detached_payload_absent(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_counter_signature_function() {
    let policy_builder = create_trust_policy_builder();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(policy_builder)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claims_present_absent() {
    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_claims_present
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_present(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_claims_absent
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_absent(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_standard_claims() {
    // Test require_cwt_iss_eq
    let policy_builder = create_trust_policy_builder();
    let issuer = CString::new("test-issuer").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iss_eq(policy_builder, issuer.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_sub_eq
    let policy_builder = create_trust_policy_builder();
    let subject = CString::new("test-subject").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_sub_eq(policy_builder, subject.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_aud_eq
    let policy_builder = create_trust_policy_builder();
    let audience = CString::new("test-audience").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_aud_eq(policy_builder, audience.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_presence() {
    // Test require_cwt_claim_label_present
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_present(policy_builder, 1)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_present
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("custom-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_present(
            policy_builder,
            claim_name.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_values() {
    // Test require_cwt_claim_label_i64_eq
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(policy_builder, 1, 42)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_label_bool_eq
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(policy_builder, 2, true)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_label_i64_ge
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(policy_builder, 3, 10)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_label_i64_le
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_le(policy_builder, 4, 100)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_strings() {
    // Test require_cwt_claim_label_str_eq
    let policy_builder = create_trust_policy_builder();
    let value = CString::new("expected-value").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_eq(
            policy_builder,
            1,
            value.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_label_str_starts_with
    let policy_builder = create_trust_policy_builder();
    let prefix = CString::new("prefix").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy_builder,
            2,
            prefix.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_label_str_contains
    let policy_builder = create_trust_policy_builder();
    let substring = CString::new("substring").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_contains(
            policy_builder,
            3,
            substring.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_values() {
    // Test require_cwt_claim_text_str_eq
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("claim-name").unwrap();
    let value = CString::new("expected-value").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            claim_name.as_ptr(),
            value.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_str_starts_with
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("claim-name").unwrap();
    let prefix = CString::new("prefix").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy_builder,
            claim_name.as_ptr(),
            prefix.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_str_contains
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("claim-name").unwrap();
    let substring = CString::new("substring").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            claim_name.as_ptr(),
            substring.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_bool_eq
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("bool-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder,
            claim_name.as_ptr(),
            false,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_i64_ge
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("number-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_ge(
            policy_builder,
            claim_name.as_ptr(),
            5,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_i64_le
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("number-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_le(
            policy_builder,
            claim_name.as_ptr(),
            50,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_claim_text_i64_eq
    let policy_builder = create_trust_policy_builder();
    let claim_name = CString::new("number-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_eq(
            policy_builder,
            claim_name.as_ptr(),
            25,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_time_claims() {
    // Test require_cwt_exp_ge
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, 1234567890) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_exp_le
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, 9876543210) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_nbf_ge
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_ge(policy_builder, 1000000000) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_nbf_le
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, 2000000000) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_iat_ge
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, 1500000000) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);

    // Test require_cwt_iat_le
    let policy_builder = create_trust_policy_builder();
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_le(policy_builder, 1800000000) };
    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_trust_plan_builder_functions() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan_builder.is_null());

    // Test pack count
    let mut count = 0usize;
    let status = unsafe { cose_sign1_trust_plan_builder_pack_count(plan_builder, &mut count) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test pack name functions (if any packs are available)
    if count > 0 {
        let pack_name = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 0) };
        if !pack_name.is_null() {
            // Test has_default_plan
            let mut has_default = false;
            let status = unsafe {
                cose_sign1_trust_plan_builder_pack_has_default_plan(
                    plan_builder,
                    0,
                    &mut has_default,
                )
            };
            assert_eq!(status, cose_status_t::COSE_OK);
            // has_default can be true or false, just ensure it doesn't crash

            unsafe { cose_sign1_validation_ffi::cose_string_free(pack_name) };
        }
    }

    // Test clear_selected_plans
    let status = unsafe { cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test compilation functions
    let mut allow_all_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_allow_all(plan_builder, &mut allow_all_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!allow_all_plan.is_null());

    // Create a second plan builder for deny_all test
    let validator_builder2 = create_validator_builder();
    let mut plan_builder2: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder2,
            &mut plan_builder2,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut deny_all_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_deny_all(plan_builder2, &mut deny_all_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!deny_all_plan.is_null());

    // Test attaching plan to validator builder
    let status = unsafe {
        cose_sign1_validator_builder_with_compiled_trust_plan(validator_builder, allow_all_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Clean up
    unsafe {
        cose_sign1_compiled_trust_plan_free(allow_all_plan);
        cose_sign1_compiled_trust_plan_free(deny_all_plan);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    };
}

#[test]
fn test_policy_builder_logical_operations() {
    let policy_builder = create_trust_policy_builder();

    // Test AND operation
    let status = unsafe { cose_sign1_trust_policy_builder_and(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test OR operation
    let status = unsafe { cose_sign1_trust_policy_builder_or(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_null_safety() {
    // Test null policy builder with various functions
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_content_type_non_empty(ptr::null_mut()) };
    assert_ne!(status, cose_status_t::COSE_OK);

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_detached_payload_present(ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_present(ptr::null_mut()) };
    assert_ne!(status, cose_status_t::COSE_OK);

    // Test null string parameters
    let policy_builder = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_content_type_eq(policy_builder, ptr::null())
    };
    assert_ne!(status, cose_status_t::COSE_OK);

    unsafe { cose_sign1_trust_policy_builder_free(policy_builder) };
}

#[test]
fn test_free_functions_null_safety() {
    // All free functions should handle null safely
    unsafe {
        cose_sign1_trust_policy_builder_free(ptr::null_mut());
        cose_sign1_trust_plan_builder_free(ptr::null_mut());
        cose_sign1_compiled_trust_plan_free(ptr::null_mut());
    }
}
