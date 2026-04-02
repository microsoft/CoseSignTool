// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test coverage for CWT claim related FFI functions.
//!
//! This test file exercises the `cose_sign1_trust_policy_builder_require_cwt_claim_*`
//! functions and related functions to achieve maximum line coverage.

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
fn test_require_cwt_claim_label_str_eq() {
    let policy_builder = create_trust_policy_builder();
    let value = CString::new("expected_value").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_eq(
            policy_builder,
            42,
            value.as_ptr(),
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_str_starts_with() {
    let policy_builder = create_trust_policy_builder();
    let prefix = CString::new("test_prefix").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy_builder,
            42,
            prefix.as_ptr(),
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_str_contains() {
    let policy_builder = create_trust_policy_builder();
    let substring = CString::new("test_substring").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_contains(
            policy_builder,
            42,
            substring.as_ptr(),
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_starts_with() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();
    let prefix = CString::new("test_prefix").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy_builder,
            key.as_ptr(),
            prefix.as_ptr(),
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_contains() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();
    let substring = CString::new("test_substring").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            key.as_ptr(),
            substring.as_ptr(),
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_bool_eq() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder,
            key.as_ptr(),
            true,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_i64_ge() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_ge(
            policy_builder,
            key.as_ptr(),
            100,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_i64_le() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_le(
            policy_builder,
            key.as_ptr(),
            500,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_i64_eq() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_eq(
            policy_builder,
            key.as_ptr(),
            42,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_exp_ge_le() {
    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_exp_ge
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, 1234567890) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_exp_le
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, 9876543210) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_nbf_ge_le() {
    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_nbf_ge
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_ge(policy_builder, 1000000000) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_nbf_le
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, 2000000000) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_require_cwt_iat_ge_le() {
    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_iat_ge
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, 1500000000) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder = create_trust_policy_builder();

    // Test require_cwt_iat_le
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_le(policy_builder, 1800000000) };
    assert_eq!(status, cose_status_t::COSE_OK);

    compile_and_cleanup(policy_builder);
}

#[test]
fn test_trust_policy_builder_compile() {
    let policy_builder = create_trust_policy_builder();
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();

    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder, &mut plan) };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    unsafe { cose_sign1_compiled_trust_plan_free(plan) };
}

#[test]
fn test_compile_and_selected_multiple_builders() {
    let policy_builder1 = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    // Add a requirement to the first builder
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder1,
            key.as_ptr(),
            true,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let policy_builder2 = create_trust_policy_builder();

    // Add a requirement to the second builder
    let status =
        unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder2, 1234567890) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Compile both plans
    let mut plan1: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder1, &mut plan1) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan1.is_null());

    let mut plan2: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder2, &mut plan2) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan2.is_null());

    unsafe {
        cose_sign1_compiled_trust_plan_free(plan1);
        cose_sign1_compiled_trust_plan_free(plan2);
    };
}

#[test]
fn test_compile_or_selected() {
    let policy_builder = create_trust_policy_builder();
    let key = CString::new("test_key").unwrap();

    // Add multiple requirements
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder,
            key.as_ptr(),
            true,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Compile the plan
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_policy_builder_compile(policy_builder, &mut plan) };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    unsafe { cose_sign1_compiled_trust_plan_free(plan) };
}
