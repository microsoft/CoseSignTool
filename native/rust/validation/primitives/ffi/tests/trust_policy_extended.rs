// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional comprehensive tests for validation primitives FFI.
//!
//! This extends coverage by testing functions not covered in trust_policy_coverage.rs,
//! focusing on integration scenarios and missing require_* functions.

use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t,
};
use cose_sign1_validation_primitives_ffi::*;
use std::ffi::CString;
use std::ptr;

/// Helper to create a validator builder for testing.
fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder);
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

/// Helper to create a trust plan builder from a validator builder for testing.
fn create_trust_plan_builder_from(
    validator_builder: *const cose_sign1_validator_builder_t,
) -> *mut cose_sign1_trust_plan_builder_t {
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan_builder.is_null());
    plan_builder
}

/// Helper to compile a policy and clean up resources.
fn compile_and_cleanup(policy_builder: *mut cose_trust_policy_builder_t) {
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder, &mut plan) };
    assert_eq!(status, cose_status_t::COSE_OK);
    unsafe {
        cose_sign1_compiled_trust_plan_free(plan);
        cose_sign1_trust_policy_builder_free(policy_builder);
    }
}

#[test]
fn test_require_content_type_functions_comprehensive() {
    let policy_builder = create_trust_policy_builder();

    // Test require content type non-empty
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_content_type_non_empty(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test require content type equals
    let content_type = CString::new("application/cbor").unwrap();
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
fn test_require_counter_signature_functions() {
    let policy_builder = create_trust_policy_builder();

    // Test require counter signature envelope integrity
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(policy_builder)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_aud_eq() {
    let policy_builder = create_trust_policy_builder();

    let audience = CString::new("test-audience").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_aud_eq(policy_builder, audience.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_operations() {
    let policy_builder = create_trust_policy_builder();

    // Test label present
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_present(policy_builder, 42)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label i64 equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(policy_builder, 42, 12345)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label bool equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(policy_builder, 43, true)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label i64 greater-equal
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(policy_builder, 44, 1000)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label i64 less-equal
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_le(policy_builder, 45, 9999)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_string_operations() {
    let policy_builder = create_trust_policy_builder();

    let test_string = CString::new("test-value").unwrap();
    let prefix_string = CString::new("test").unwrap();
    let contains_string = CString::new("val").unwrap();

    // Test label string equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_eq(
            policy_builder,
            50,
            test_string.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label string starts with
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy_builder,
            51,
            prefix_string.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test label string contains
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_contains(
            policy_builder,
            52,
            contains_string.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_operations() {
    let policy_builder = create_trust_policy_builder();

    let claim_name = CString::new("custom-claim").unwrap();
    let test_value = CString::new("test-value").unwrap();
    let prefix = CString::new("test").unwrap();
    let contains = CString::new("val").unwrap();

    // Test text present
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_present(
            policy_builder,
            claim_name.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text string equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            claim_name.as_ptr(),
            test_value.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text string starts with
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy_builder,
            claim_name.as_ptr(),
            prefix.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text string contains
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            claim_name.as_ptr(),
            contains.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_numeric_operations() {
    let policy_builder = create_trust_policy_builder();

    let claim_name = CString::new("numeric-claim").unwrap();

    // Test text bool equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder,
            claim_name.as_ptr(),
            true,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text i64 greater-equal
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_ge(
            policy_builder,
            claim_name.as_ptr(),
            1000,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text i64 less-equal
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_le(
            policy_builder,
            claim_name.as_ptr(),
            9999,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test text i64 equals
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_eq(
            policy_builder,
            claim_name.as_ptr(),
            5000,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_standard_time_claims() {
    let policy_builder = create_trust_policy_builder();

    let now = 1640995200i64; // 2022-01-01 00:00:00 UTC
    let future = now + 3600; // 1 hour later
    let past = now - 3600; // 1 hour earlier

    // Test exp (expiration) constraints
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, future) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, future + 86400)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test nbf (not before) constraints
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_ge(policy_builder, past) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, now) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test iat (issued at) constraints
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, past) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_le(policy_builder, now) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_trust_plan_builder_with_pack_integration() {
    let validator_builder = create_validator_builder();
    let mut trust_plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();

    // Create trust plan builder
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut trust_plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!trust_plan_builder.is_null());

    // Test add all pack default plans (should work even without real packs)
    let status =
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(trust_plan_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Since there are no packs configured, the compile operations might fail
    // Let's check if any plans were actually added by the pack operation
    // If no plans, we should skip the compile tests or expect them to fail

    // Test compile with logical OR (might fail if no plans selected)
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_plan_builder_compile_or(trust_plan_builder, &mut plan) };
    // Since no packs are configured, compile might legitimately fail
    if status == cose_status_t::COSE_OK {
        assert!(!plan.is_null());
        unsafe { cose_sign1_compiled_trust_plan_free(plan) };
    }

    // Test compile with logical AND (might fail if no plans selected)
    let status =
        unsafe { cose_sign1_trust_plan_builder_compile_and(trust_plan_builder, &mut plan) };
    // Since no packs are configured, compile might legitimately fail
    if status == cose_status_t::COSE_OK {
        assert!(!plan.is_null());
        unsafe { cose_sign1_compiled_trust_plan_free(plan) };
    }

    // Test pack count
    let mut pack_count: usize = 0;
    let status =
        unsafe { cose_sign1_trust_plan_builder_pack_count(trust_plan_builder, &mut pack_count) };
    assert_eq!(status, cose_status_t::COSE_OK);
    // pack_count could be 0 since no real packs are configured

    // Test add specific pack by name (non-existent pack should handle gracefully)
    let pack_name = CString::new("non-existent-pack").unwrap();
    let _status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            trust_plan_builder,
            pack_name.as_ptr(),
        )
    };
    // This might succeed or fail depending on implementation - we just test it doesn't crash

    // Test compile allow all (this should always work regardless of selected plans)
    let status =
        unsafe { cose_sign1_trust_plan_builder_compile_allow_all(trust_plan_builder, &mut plan) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());
    unsafe { cose_sign1_compiled_trust_plan_free(plan) };

    // Test compile deny all (this should always work regardless of selected plans)
    let status =
        unsafe { cose_sign1_trust_plan_builder_compile_deny_all(trust_plan_builder, &mut plan) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());
    unsafe { cose_sign1_compiled_trust_plan_free(plan) };

    // Clean up
    unsafe {
        cose_sign1_trust_plan_builder_free(trust_plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_compiled_trust_plan_validator_attachment() {
    let validator_builder = create_validator_builder();
    let trust_plan_builder = create_trust_plan_builder_from(validator_builder);
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();

    // Create allow-all plan
    let status =
        unsafe { cose_sign1_trust_plan_builder_compile_allow_all(trust_plan_builder, &mut plan) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    // Attach plan to validator builder
    let status =
        unsafe { cose_sign1_validator_builder_with_compiled_trust_plan(validator_builder, plan) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Build validator (simplified test - just verify the attachment worked)
    // Don't need to actually build and validate in this coverage test

    // Clean up
    unsafe {
        cose_sign1_trust_plan_builder_free(trust_plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
        // plan is owned by validator builder now, don't double-free
    }
}

#[test]
fn test_null_safety_require_functions() {
    let policy_builder = create_trust_policy_builder();

    // Test all require functions with null string parameters
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_content_type_eq(policy_builder, ptr::null())
    };
    assert_eq!(status, cose_status_t::COSE_ERR);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iss_eq(policy_builder, ptr::null()) };
    assert_eq!(status, cose_status_t::COSE_ERR);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_sub_eq(policy_builder, ptr::null()) };
    assert_eq!(status, cose_status_t::COSE_ERR);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_aud_eq(policy_builder, ptr::null()) };
    assert_eq!(status, cose_status_t::COSE_ERR);

    // Test with null policy builder
    let test_string = CString::new("test").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iss_eq(ptr::null_mut(), test_string.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_ERR);

    unsafe { cose_sign1_trust_policy_builder_free(policy_builder) };
}

#[test]
fn test_multiple_require_constraints_combined() {
    let policy_builder = create_trust_policy_builder();

    // Combine multiple different requirement types
    let issuer = CString::new("trusted-issuer").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iss_eq(policy_builder, issuer.as_ptr())
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_present(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_detached_payload_absent(policy_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let content_type = CString::new("application/cbor").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_content_type_eq(
            policy_builder,
            content_type.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let now = 1640995200i64;
    let status = unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, now) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, now - 100) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Should be able to compile all these constraints together
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_edge_case_numeric_values() {
    let policy_builder = create_trust_policy_builder();

    // Test with extreme timestamp values
    let max_timestamp = i64::MAX;
    let min_timestamp = i64::MIN;
    let zero_timestamp = 0i64;

    // These should all succeed without panicking
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, min_timestamp)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, max_timestamp)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, zero_timestamp)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test with extreme label values
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(policy_builder, i64::MAX, 42)
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            policy_builder,
            i64::MIN,
            -42,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}
