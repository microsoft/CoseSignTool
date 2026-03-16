//! Basic FFI test coverage for validation primitives functions.

use std::ptr;
use std::ffi::CString;
use cose_sign1_validation_ffi::{
    cose_status_t, cose_sign1_validator_builder_new, cose_sign1_validator_builder_free,
    cose_trust_policy_builder_t, cose_sign1_validator_builder_t
};
use cose_sign1_validation_primitives_ffi::*;

// Import the status constants properly
const COSE_OK: cose_status_t = cose_sign1_validation_ffi::cose_status_t::COSE_OK;

// Helper to create a validator builder
unsafe fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let result = cose_sign1_validator_builder_new(&mut builder);
    assert_eq!(result, COSE_OK);
    assert!(!builder.is_null());
    builder
}

#[test]
fn test_trust_plan_builder_lifecycle() {
    unsafe {
        let validator_builder = create_validator_builder();
        
        let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
        let result = cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        );
        
        assert_eq!(result, COSE_OK);
        assert!(!plan_builder.is_null());
        
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_null_safety() {
    unsafe {
        // Should not crash with null pointer
        cose_sign1_trust_plan_builder_free(ptr::null_mut());
        
        // Test null validator
        let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
        let result = cose_sign1_trust_plan_builder_new_from_validator_builder(
            ptr::null(), 
            &mut plan_builder
        );
        assert_ne!(result, COSE_OK);
        assert!(plan_builder.is_null());
        
        // Test null output
        let validator_builder = create_validator_builder();
        let result = cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            ptr::null_mut()
        );
        assert_ne!(result, COSE_OK);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_operations() {
    unsafe {
        let validator_builder = create_validator_builder();
        let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
        
        let result = cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        );
        assert_eq!(result, COSE_OK);
        
        // Test add all pack default plans
        let result = cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder);
        assert_eq!(result, COSE_OK);
        
        // Test clear selected plans
        let result = cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder);
        assert_eq!(result, COSE_OK);
        
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_compiled_trust_plan_operations() {
    unsafe {
        let validator_builder = create_validator_builder();
        let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
        
        let result = cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        );
        assert_eq!(result, COSE_OK);
        
        // Test compile allow all
        let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
        let result = cose_sign1_trust_plan_builder_compile_allow_all(plan_builder, &mut compiled_plan);
        assert_eq!(result, COSE_OK);
        assert!(!compiled_plan.is_null());
        
        // Test attaching to validator
        let result = cose_sign1_validator_builder_with_compiled_trust_plan(
            validator_builder, 
            compiled_plan
        );
        assert_eq!(result, COSE_OK);
        
        // Note: compiled_plan ownership transferred, don't free it
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_lifecycle() {
    unsafe {
        let validator_builder = create_validator_builder();
        
        let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
        let result = cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        );
        
        assert_eq!(result, COSE_OK);
        assert!(!policy_builder.is_null());
        
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_operations() {
    unsafe {
        let validator_builder = create_validator_builder();
        let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
        
        let result = cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        );
        assert_eq!(result, COSE_OK);
        
        // Test logical operations
        let result = cose_sign1_trust_policy_builder_and(policy_builder);
        assert_eq!(result, COSE_OK);
        
        let result = cose_sign1_trust_policy_builder_or(policy_builder);
        assert_eq!(result, COSE_OK);
        
        // Test content type requirements
        let result = cose_sign1_trust_policy_builder_require_content_type_non_empty(policy_builder);
        assert_eq!(result, COSE_OK);
        
        let content_type = CString::new("application/test").unwrap();
        let result = cose_sign1_trust_policy_builder_require_content_type_eq(
            policy_builder, 
            content_type.as_ptr()
        );
        assert_eq!(result, COSE_OK);
        
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_null_safety() {
    // Should not crash with null pointer
    unsafe { cose_sign1_trust_policy_builder_free(ptr::null_mut()); }
    
    unsafe {
        // Test various functions with null policy builders
        assert_ne!(cose_sign1_trust_policy_builder_and(ptr::null_mut()), COSE_OK);
        assert_ne!(cose_sign1_trust_policy_builder_or(ptr::null_mut()), COSE_OK);
        assert_ne!(
            cose_sign1_trust_policy_builder_require_content_type_non_empty(ptr::null_mut()), 
            COSE_OK
        );
    }
}
