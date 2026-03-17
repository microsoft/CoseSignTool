// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests to cover specific uncovered lines in validation primitives FFI helper functions.
//!
//! This test file specifically targets:
//! - Error paths in helper functions
//! - Edge cases not covered by existing tests
//! - Paths that require specific pack configurations

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_free, cose_sign1_validator_builder_new,
    cose_sign1_validator_builder_t, cose_status_t, cose_string_free,
};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::rules::allow_all;
use cose_sign1_validation_primitives_ffi::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Arc;

/// Create a validator builder with multiple packs including ones with and without default plans.
fn create_validator_builder_with_mixed_packs() -> *mut cose_sign1_validator_builder_t {
    // Create base validator builder
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Create packs
    let plan_with_default = CompiledTrustPlan::new(
        vec![],
        vec![],
        vec![allow_all("test_trust_source")],
        vec![],
    );
    let pack_with_default = Arc::new(SimpleTrustPack::no_facts("test_pack_with_default")
        .with_default_trust_plan(plan_with_default));

    let pack_without_default = Arc::new(SimpleTrustPack::no_facts("test_pack_no_default"));

    let plan_with_default_2 = CompiledTrustPlan::new(
        vec![],
        vec![],
        vec![allow_all("test_trust_source_2")],
        vec![],
    );
    let pack_with_default_2 = Arc::new(SimpleTrustPack::no_facts("test_pack_with_default_2")
        .with_default_trust_plan(plan_with_default_2));

    // Add packs directly to the builder's packs vector
    // SAFETY: builder was verified non-null above via assert, and was allocated by
    // cose_sign1_validator_builder_new which returns a valid heap-allocated object.
    // This test intentionally manipulates the builder's internal state for FFI edge case testing.
    unsafe {
        let builder_ref = builder.as_mut().expect("builder pointer must be valid");
        builder_ref.packs.push(pack_with_default);
        builder_ref.packs.push(pack_without_default);
        builder_ref.packs.push(pack_with_default_2);
    }

    builder
}

/// Test `pack_name_from_ptr` error path with null pointer.
#[test]
fn test_pack_name_from_ptr_null() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Try to add a pack with null name - this exercises pack_name_from_ptr error path
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, ptr::null())
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail with null pack name

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `collect_default_plan_for_pack` error path when pack doesn't provide a default plan.
#[test]
fn test_collect_default_plan_for_pack_no_default() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Try to add a pack that doesn't have a default plan
    let pack_name = CString::new("test_pack_no_default").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail - no default plan

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `add_pack_default_plan_by_name` with nonexistent pack name.
#[test]
fn test_add_pack_default_plan_nonexistent_pack() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Try to add a pack that doesn't exist
    let pack_name = CString::new("nonexistent_pack_name").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail - pack doesn't exist

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `add_pack_default_plan_by_name` success path.
#[test]
fn test_add_pack_default_plan_by_name_success() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add a pack that has a default plan
    let pack_name = CString::new("test_pack_with_default").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK); // Should succeed

    // Now compile the plan - this exercises compile_or_selected
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut compiled_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compiled_plan.is_null());

    // Cleanup
    unsafe {
        cose_sign1_compiled_trust_plan_free(compiled_plan);
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `pack_name_utf8` with all available packs to ensure `to_new_utf8` is covered.
#[test]
fn test_to_new_utf8_all_packs() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut pack_count: usize = 0;
    let status = unsafe {
        cose_sign1_trust_plan_builder_pack_count(plan_builder, &mut pack_count)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(pack_count, 3); // We created 3 packs

    // Get name for each pack - this exercises to_new_utf8
    for i in 0..pack_count {
        let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, i) };
        assert!(!name_ptr.is_null());

        let name = unsafe { CStr::from_ptr(name_ptr) };
        let name_str = name.to_str().unwrap();
        assert!(name_str.starts_with("test_pack"));

        unsafe { cose_string_free(name_ptr) };
    }

    // Test null pointer path for pack_name_utf8
    let name_ptr = unsafe {
        cose_sign1_trust_plan_builder_pack_name_utf8(ptr::null(), 0)
    };
    assert!(name_ptr.is_null());

    // Test out of bounds index
    let name_ptr = unsafe {
        cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 999)
    };
    assert!(name_ptr.is_null());

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_and_selected` with multiple plans to exercise the HashSet and loop logic.
#[test]
fn test_compile_and_selected_multiple_plans() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add multiple packs with default plans
    let pack_name_1 = CString::new("test_pack_with_default").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name_1.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    let pack_name_2 = CString::new("test_pack_with_default_2").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name_2.as_ptr(),
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Compile with AND - this exercises compile_and_selected with multiple plans
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut compiled_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compiled_plan.is_null());

    // Cleanup
    unsafe {
        cose_sign1_compiled_trust_plan_free(compiled_plan);
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_or` null pointer error paths.
#[test]
fn test_compile_or_null_pointers() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add a plan
    let pack_name = CString::new("test_pack_with_default").unwrap();
    let _ = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };

    // Try compile_or with null out_plan
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(plan_builder, ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail

    // Try compile_or with null plan_builder
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(ptr::null_mut(), &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_and` null pointer error paths.
#[test]
fn test_compile_and_null_pointers() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Add a plan
    let pack_name = CString::new("test_pack_with_default").unwrap();
    let _ = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };

    // Try compile_and with null out_plan
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(plan_builder, ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail

    // Try compile_and with null plan_builder
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(ptr::null_mut(), &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK); // Should fail

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

/// Test `compile_or` and `compile_and` with empty selected plans.
#[test]
fn test_compile_empty_selected_plans() {
    let validator_builder = create_validator_builder_with_mixed_packs();

    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Don't add any plans - both compile functions should fail with "no plans selected"

    let mut or_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut or_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(or_plan.is_null());

    let mut and_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut and_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(and_plan.is_null());

    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}
