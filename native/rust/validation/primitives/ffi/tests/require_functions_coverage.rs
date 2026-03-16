// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional require_* function coverage tests for validation primitives FFI.
//!
//! These tests target the remaining require_* variants that need coverage to reach 90%

use cose_sign1_validation_ffi::{cose_status_t, cose_sign1_validator_builder_t, cose_trust_policy_builder_t};
use cose_sign1_validation_primitives_ffi::*;
use std::ffi::CString;
use std::ptr;

/// Helper to create a validator builder for testing.
fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder) };
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
            &mut policy_builder
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!policy_builder.is_null());
    
    // Clean up validator builder as it's no longer needed
    unsafe { cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder) };
    
    policy_builder
}

// Helper to clean up policy builder
fn cleanup_policy_builder(builder: *mut cose_trust_policy_builder_t) {
    unsafe { cose_sign1_trust_policy_builder_free(builder) };
}

#[test]
fn test_require_cwt_claim_text_present_complete_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("test-claim").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_present(
            policy_builder, 
            claim_key.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_present_null_key() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_present(
            policy_builder,
            ptr::null()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_present_null_builder() {
    let claim_key = CString::new("test").unwrap();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_present(
            ptr::null_mut(),
            claim_key.as_ptr()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn test_require_cwt_claim_label_i64_eq_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            policy_builder,
            1000,  // label
            42     // expected value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_i64_eq_null_builder() {
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            ptr::null_mut(),
            1000,
            42
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn test_require_cwt_claim_label_bool_eq_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(
            policy_builder,
            1001,  // label
            true   // expected value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test with false value
    let policy_builder2 = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(
            policy_builder2,
            1002,
            false
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
    cleanup_policy_builder(policy_builder2);
}

#[test]
fn test_require_cwt_claim_label_bool_eq_null_builder() {
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(
            ptr::null_mut(),
            1001,
            true
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn test_require_cwt_claim_label_i64_ge_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(
            policy_builder,
            1003,  // label
            100    // minimum value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_i64_le_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_le(
            policy_builder,
            1004,  // label
            1000   // maximum value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_eq_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("custom-claim").unwrap();
    let expected_value = CString::new("expected-value").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            claim_key.as_ptr(),
            expected_value.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_eq_null_params() {
    let policy_builder = create_trust_policy_builder();
    let claim_key = CString::new("test").unwrap();
    let expected_value = CString::new("value").unwrap();
    
    // Test null builder
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            ptr::null_mut(),
            claim_key.as_ptr(),
            expected_value.as_ptr()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test null key
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            ptr::null(),
            expected_value.as_ptr()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test null value
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            claim_key.as_ptr(),
            ptr::null()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_str_starts_with_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let prefix = CString::new("https://").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy_builder,
            1005,  // label
            prefix.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_starts_with_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("url-claim").unwrap();
    let prefix = CString::new("https://").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy_builder,
            claim_key.as_ptr(),
            prefix.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_label_str_contains_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let substring = CString::new("example").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_contains(
            policy_builder,
            1006,  // label
            substring.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_str_contains_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("description").unwrap();
    let substring = CString::new("important").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            claim_key.as_ptr(),
            substring.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_bool_eq_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("is-active").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder,
            claim_key.as_ptr(),
            true
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test with false value
    let policy_builder2 = create_trust_policy_builder();
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_bool_eq(
            policy_builder2,
            claim_key.as_ptr(),
            false
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
    cleanup_policy_builder(policy_builder2);
}

#[test]
fn test_require_cwt_claim_text_i64_ge_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("score").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_ge(
            policy_builder,
            claim_key.as_ptr(),
            75  // minimum score
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_i64_le_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("max-score").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_le(
            policy_builder,
            claim_key.as_ptr(),
            100  // maximum score
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_claim_text_i64_eq_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let claim_key = CString::new("version").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_i64_eq(
            policy_builder,
            claim_key.as_ptr(),
            2  // expected version
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_exp_ge_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let now = 1640995200; // Some Unix timestamp
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, now)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_exp_le_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let future = 2000000000; // Some future Unix timestamp
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, future)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_nbf_ge_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let past = 1600000000;
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_nbf_ge(policy_builder, past)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_nbf_le_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let now = 1640995200;
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, now)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_iat_ge_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let past = 1600000000;
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, past)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_cwt_iat_le_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let now = 1640995200;
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iat_le(policy_builder, now)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_counter_signature_envelope_sig_structure_intact_or_missing_coverage() {
    let policy_builder = create_trust_policy_builder();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(
            policy_builder
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_require_counter_signature_envelope_sig_structure_null_builder() {
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(
            ptr::null_mut()
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn test_edge_cases_negative_numbers() {
    let policy_builder = create_trust_policy_builder();
    
    // Test with negative labels
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            policy_builder,
            -100,  // negative label
            -42    // negative value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_edge_cases_large_numbers() {
    let policy_builder = create_trust_policy_builder();
    
    // Test with large numbers
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(
            policy_builder,
            i64::MAX - 1,
            i64::MAX
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_edge_cases_zero_values() {
    let policy_builder = create_trust_policy_builder();
    
    // Test with zero values
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            policy_builder,
            0,  // zero label
            0   // zero value
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_empty_strings() {
    let policy_builder = create_trust_policy_builder();
    
    let empty_key = CString::new("").unwrap();
    let empty_value = CString::new("").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            empty_key.as_ptr(),
            empty_value.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_unicode_strings() {
    let policy_builder = create_trust_policy_builder();
    
    let unicode_key = CString::new("🔑-key").unwrap();
    let unicode_value = CString::new("🌍 Unicode Value 中文").unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            unicode_key.as_ptr(),
            unicode_value.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_long_strings() {
    let policy_builder = create_trust_policy_builder();
    
    let long_key = "a".repeat(1000);
    let long_value = "x".repeat(2000);
    
    let long_key_c = CString::new(long_key).unwrap();
    let long_value_c = CString::new(long_value).unwrap();
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            long_key_c.as_ptr(),
            long_value_c.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}

#[test]
fn test_comprehensive_claim_combinations() {
    let policy_builder = create_trust_policy_builder();
    
    // Add multiple requirements to the same builder
    let claim_key = CString::new("multi-test").unwrap();
    let string_value = CString::new("test-value").unwrap();
    let prefix = CString::new("test").unwrap();
    let substring = CString::new("value").unwrap();
    
    // Add multiple text-based claims
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_eq(
            policy_builder,
            claim_key.as_ptr(),
            string_value.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy_builder,
            claim_key.as_ptr(),
            prefix.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy_builder,
            claim_key.as_ptr(),
            substring.as_ptr()
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Add numeric requirements
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(
            policy_builder,
            1000,
            50
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_le(
            policy_builder,
            1001,
            100
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Add boolean requirement
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(
            policy_builder,
            1002,
            true
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Add timestamp requirements
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, 1640995200)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    let status = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, 1672531200)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    cleanup_policy_builder(policy_builder);
}
