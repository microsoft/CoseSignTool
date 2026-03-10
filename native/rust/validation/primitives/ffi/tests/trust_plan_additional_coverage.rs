// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional tests for trust plan builder FFI functions that need more coverage.

use cose_sign1_validation_ffi::{cose_status_t, cose_sign1_validator_builder_t, cose_sign1_validator_builder_new};
use cose_sign1_validation_primitives_ffi::*;
use std::ptr;
use std::ffi::CString;

fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    builder
}

#[test]
fn test_trust_plan_builder_add_all_pack_default_plans() {
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
    
    // Test adding all pack default plans
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_add_pack_by_name() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test with non-existent pack name (should fail gracefully)
    let pack_name = CString::new("non_existent_pack").unwrap();
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            pack_name.as_ptr(),
        )
    };
    // Should fail since pack doesn't exist
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test with null pack name
    let status = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder,
            ptr::null(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_pack_queries_edge_cases() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test pack count with null output pointer
    let status = unsafe {
        cose_sign1_trust_plan_builder_pack_count(plan_builder, ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test pack count with null plan builder
    let mut count = 0usize;
    let status = unsafe {
        cose_sign1_trust_plan_builder_pack_count(ptr::null(), &mut count)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test pack name with invalid index
    let pack_name_ptr = unsafe {
        cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 999)
    };
    assert!(pack_name_ptr.is_null());
    
    // Test pack has default with invalid index
    let mut has_default = false;
    let status = unsafe {
        cose_sign1_trust_plan_builder_pack_has_default_plan(
            plan_builder,
            999,
            &mut has_default,
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test pack has default with null output
    let status = unsafe {
        cose_sign1_trust_plan_builder_pack_has_default_plan(
            plan_builder,
            0,
            ptr::null_mut(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_compile_functions() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test compile_or with null output
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(plan_builder, ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test compile_and with null output
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(plan_builder, ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test compile_or with null plan builder
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(ptr::null_mut(), &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test compile_and with null plan builder
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(ptr::null_mut(), &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test compile_or with empty plan (should fail - no plans selected)
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test compile_and with empty plan (should fail - no plans selected)
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut compiled_plan)
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_validator_builder_with_compiled_trust_plan() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Create a compiled plan
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_compile_allow_all(plan_builder, &mut compiled_plan)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compiled_plan.is_null());
    
    // Test attaching compiled plan to validator builder
    let status = unsafe {
        cose_sign1_validator_builder_with_compiled_trust_plan(
            validator_builder,
            compiled_plan,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test with null validator builder
    let status = unsafe {
        cose_sign1_validator_builder_with_compiled_trust_plan(
            ptr::null_mut(),
            compiled_plan,
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Test with null compiled plan
    let status = unsafe {
        cose_sign1_validator_builder_with_compiled_trust_plan(
            validator_builder,
            ptr::null_mut(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup (note: compiled plan ownership transferred to validator)
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_new_edge_cases() {
    // Test with null validator builder
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            ptr::null(),
            &mut plan_builder,
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    let validator_builder = create_validator_builder();
    
    // Test with null output pointer
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            ptr::null_mut(),
        )
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_clear_selected_plans_edge_cases() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder,
            &mut plan_builder,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test clear on empty plan (should succeed)
    let status = unsafe {
        cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    
    // Test clear with null plan builder
    let status = unsafe {
        cose_sign1_trust_plan_builder_clear_selected_plans(ptr::null_mut())
    };
    assert_ne!(status, cose_status_t::COSE_OK);
    
    // Cleanup
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validation_ffi::cose_sign1_validator_builder_free(validator_builder);
    }
}