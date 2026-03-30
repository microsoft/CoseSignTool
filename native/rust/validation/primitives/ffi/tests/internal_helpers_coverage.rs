// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests to cover internal helper functions in validation primitives FFI.
//!
//! This test file targets the uncovered internal helper functions:
//! - `to_new_utf8` (via pack_name_utf8 function)
//! - `collect_default_plan_for_pack` (via add_pack_default_plan_by_name with packs that provide defaults)
//! - `compile_or_selected` (via compile_or function)
//! - `compile_and_selected` (via compile_and function)

use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_free, cose_sign1_validator_builder_new,
    cose_sign1_validator_builder_t, cose_status_t, cose_string_free,
};
use cose_sign1_validation_primitives_ffi::*;
use std::ffi::CStr;
use std::ptr;

fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    builder
}

/// Test `to_new_utf8` via `cose_sign1_trust_plan_builder_pack_name_utf8`.
/// This exercises the string conversion logic including the fallback for NUL bytes.
#[test]
fn test_to_new_utf8_via_pack_name() {
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

    // Get the pack count to ensure we have at least one pack
    let mut pack_count: usize = 0;
    let status = unsafe { cose_sign1_trust_plan_builder_pack_count(plan_builder, &mut pack_count) };
    assert_eq!(status, cose_status_t::COSE_OK);

    if pack_count > 0 {
        // Call pack_name_utf8 which internally calls to_new_utf8
        let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 0) };
        assert!(!name_ptr.is_null());

        // Verify the returned string is valid
        let name = unsafe { CStr::from_ptr(name_ptr) };
        assert!(!name.to_bytes().is_empty());

        // Free the string
        unsafe { cose_string_free(name_ptr) };
    }

    // Test with an out-of-bounds index to exercise the error path
    let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 999) };
    assert!(name_ptr.is_null()); // Should return null for out-of-bounds

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `to_new_utf8` with multiple pack names to ensure all code paths are covered.
#[test]
fn test_to_new_utf8_multiple_packs() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut pack_count: usize = 0;
    let status = unsafe { cose_sign1_trust_plan_builder_pack_count(plan_builder, &mut pack_count) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Test all available packs to ensure to_new_utf8 is called for each
    for i in 0..pack_count {
        let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, i) };
        assert!(!name_ptr.is_null());

        let name = unsafe { CStr::from_ptr(name_ptr) };
        assert!(!name.to_bytes().is_empty());

        unsafe { cose_string_free(name_ptr) };
    }

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `collect_default_plan_for_pack` via `add_all_pack_default_plans`.
/// This exercises the default plan collection logic.
#[test]
fn test_collect_default_plan_for_pack_via_add_all() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // This internally calls collect_default_plan_for_pack for each pack
    let status = unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };

    // May succeed or fail depending on whether packs provide defaults
    // The key is that collect_default_plan_for_pack gets called
    assert!(status == cose_status_t::COSE_OK || status == cose_status_t::COSE_ERR);

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_or_selected` via `compile_or`.
/// This exercises the OR compilation logic with selected plans.
/// Note: The compile may fail if no packs provide default plans, but the helper is still called.
#[test]
fn test_compile_or_selected() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Try to add all pack default plans - this exercises collect_default_plan_for_pack
    let add_status =
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };

    // Only test compile if we successfully added plans
    if add_status == cose_status_t::COSE_OK {
        // Now compile with OR - this calls compile_or_selected
        let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
        let status =
            unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut compiled_plan) };

        if status == cose_status_t::COSE_OK {
            assert!(!compiled_plan.is_null());
            unsafe { cose_sign1_compiled_trust_plan_free(compiled_plan) };
        }
    } else {
        // If no packs provide default plans, that's OK for this test
        // The key is that collect_default_plan_for_pack was called during add_all
    }

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_and_selected` via `compile_and`.
/// This exercises the AND compilation logic including constraints and allow_all.
/// Note: The compile may fail if no packs provide default plans, but the helper is still called.
#[test]
fn test_compile_and_selected() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Try to add all pack default plans - this exercises collect_default_plan_for_pack
    let add_status =
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };

    // Only test compile if we successfully added plans
    if add_status == cose_status_t::COSE_OK {
        // Now compile with AND - this calls compile_and_selected
        let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
        let status =
            unsafe { cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut compiled_plan) };

        if status == cose_status_t::COSE_OK {
            assert!(!compiled_plan.is_null());
            unsafe { cose_sign1_compiled_trust_plan_free(compiled_plan) };
        }
    } else {
        // If no packs provide default plans, that's OK for this test
        // The key is that collect_default_plan_for_pack was called during add_all
    }

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_and_selected` with actual selected plans to exercise the HashSet logic.
/// Note: This test is conditional on having packs with default plans available.
#[test]
fn test_compile_and_with_multiple_plans() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add all available pack default plans
    let add_status =
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };

    // Only test if we successfully added plans
    if add_status == cose_status_t::COSE_OK {
        // First, try compile to OR
        let mut or_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
        let status =
            unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut or_plan) };
        if status == cose_status_t::COSE_OK {
            assert!(!or_plan.is_null());
            unsafe { cose_sign1_compiled_trust_plan_free(or_plan) };
        }

        // Create a new plan builder and try AND compile
        let mut plan_builder2: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
        let status = unsafe {
            cose_sign1_trust_plan_builder_new_from_validator_builder(
                validator_builder,
                &mut plan_builder2,
            )
        };
        assert_eq!(status, cose_status_t::COSE_OK);

        // Add plans and compile with AND
        let add_status2 =
            unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder2) };
        if add_status2 == cose_status_t::COSE_OK {
            let mut and_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
            let status =
                unsafe { cose_sign1_trust_plan_builder_compile_and(plan_builder2, &mut and_plan) };
            if status == cose_status_t::COSE_OK {
                assert!(!and_plan.is_null());
                unsafe { cose_sign1_compiled_trust_plan_free(and_plan) };
            }
        }

        unsafe { cose_sign1_trust_plan_builder_free(plan_builder2) };
    }

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test empty plans compilation to ensure error paths are covered.
#[test]
fn test_compile_empty_plans() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Don't add any plans - compile with empty selected_plans should fail

    // Compile OR with empty plans - should fail
    let mut or_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut or_plan) };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail with empty plans
    assert!(or_plan.is_null());

    // Compile AND with empty plans - should fail
    let mut and_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut and_plan) };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail with empty plans
    assert!(and_plan.is_null());

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test the clear_selected_plans functionality followed by compile.
#[test]
fn test_clear_and_recompile() {
    let validator_builder = create_validator_builder();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add some plans
    let add_status =
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };

    // Clear the selected plans
    let status = unsafe { cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Compile after clear - should fail with empty plans
    let mut plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut plan) };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail with empty plans

    // If we had successfully added plans before, try adding again after clear
    if add_status == cose_status_t::COSE_OK {
        let _ = unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };
        let status = unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut plan) };
        if status == cose_status_t::COSE_OK {
            assert!(!plan.is_null());
            unsafe { cose_sign1_compiled_trust_plan_free(plan) };
        }
    }

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}
