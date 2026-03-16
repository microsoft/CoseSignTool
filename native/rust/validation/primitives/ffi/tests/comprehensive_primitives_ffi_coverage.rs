//! Comprehensive FFI test coverage for validation primitives functions.

use std::ptr;
use std::ffi::{CStr, CString};
use cose_sign1_validation_ffi::{
    cose_status_t, cose_sign1_validator_builder_new, cose_sign1_validator_builder_free,
    cose_trust_policy_builder_t, cose_sign1_validator_builder_t
};
use cose_sign1_validation_primitives_ffi::*;

// Helper to create a validator builder
fn create_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let result = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    builder
}

#[test]
fn test_trust_plan_builder_new_from_validator_builder() {
    let validator_builder = create_validator_builder();
    
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let result = unsafe { 
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    
    assert_eq!(result, cose_status_t::COSE_OK);
    assert!(!plan_builder.is_null());
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_new_null_validator() {
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            ptr::null(), 
            &mut plan_builder
        )
    };
    
    assert_ne!(result, cose_status_t::COSE_OK);
    assert!(plan_builder.is_null());
}

#[test]
fn test_trust_plan_builder_new_null_out_ptr() {
    let validator_builder = create_validator_builder();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            ptr::null_mut()
        )
    };
    
    assert_ne!(result, cose_status_t::COSE_OK);
    
    unsafe { cose_sign1_validator_builder_free(validator_builder); }
}

#[test]
fn test_trust_plan_builder_free_null_safety() {
    // Should not crash with null pointer
    unsafe { cose_sign1_trust_plan_builder_free(ptr::null_mut()); }
}

#[test]
fn test_trust_plan_builder_pack_operations() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test pack count
    let mut count: usize = 0;
    let result = unsafe { cose_sign1_trust_plan_builder_pack_count(plan_builder, &mut count) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    if count > 0 {
        // Test pack name for first pack
        let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 0) };
        assert!(!name_ptr.is_null());
        let name = unsafe { CStr::from_ptr(name_ptr).to_str().unwrap() };
        assert!(!name.is_empty());
        
        // Test has default plan
        let mut has_default: bool = false;
        let result = unsafe {
            cose_sign1_trust_plan_builder_pack_has_default_plan(plan_builder, 0, &mut has_default)
        };
        assert_eq!(result, cose_status_t::COSE_OK);
    }
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_pack_name_invalid_index() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test invalid index
    let name_ptr = unsafe { cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, 999) };
    assert!(name_ptr.is_null());
    
    let mut has_default: bool = false;
    let result = unsafe {
        cose_sign1_trust_plan_builder_pack_has_default_plan(plan_builder, 999, &mut has_default)
    };
    assert_ne!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_add_all_pack_default_plans() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_add_pack_default_plan_by_name() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test with non-existent pack name - should fail now
    let pack_name = CString::new("nonexistent-pack").unwrap();
    let result = unsafe {
        cose_sign1_trust_plan_builder_add_pack_default_plan_by_name(
            plan_builder, 
            pack_name.as_ptr()
        )
    };
    assert_ne!(result, cose_status_t::COSE_OK);  // Should fail for non-existent pack
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_clear_selected_plans() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_plan_builder_clear_selected_plans(plan_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_compile_or() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Add a default plan first so compile doesn't fail
    let result = unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let result = unsafe { cose_sign1_trust_plan_builder_compile_or(plan_builder, &mut compiled_plan) };
    
    // Will succeed if there are plans, fail if none available
    if result == cose_status_t::COSE_OK {
        assert!(!compiled_plan.is_null());
        unsafe { cose_sign1_compiled_trust_plan_free(compiled_plan); }
    }
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_compile_and() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Add a default plan first
    let result = unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let result = unsafe { cose_sign1_trust_plan_builder_compile_and(plan_builder, &mut compiled_plan) };
    
    if result == cose_status_t::COSE_OK {
        assert!(!compiled_plan.is_null());
        unsafe { cose_sign1_compiled_trust_plan_free(compiled_plan); }
    }
    
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_compile_allow_all() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let result = unsafe { cose_sign1_trust_plan_builder_compile_allow_all(plan_builder, &mut compiled_plan) };
    assert_eq!(result, cose_status_t::COSE_OK);
    assert!(!compiled_plan.is_null());
    
    unsafe {
        cose_sign1_compiled_trust_plan_free(compiled_plan);
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_plan_builder_compile_deny_all() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let result = unsafe { cose_sign1_trust_plan_builder_compile_deny_all(plan_builder, &mut compiled_plan) };
    assert_eq!(result, cose_status_t::COSE_OK);
    assert!(!compiled_plan.is_null());
    
    unsafe {
        cose_sign1_compiled_trust_plan_free(compiled_plan);
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_compiled_trust_plan_free_null_safety() {
    // Should not crash with null pointer
    unsafe { cose_sign1_compiled_trust_plan_free(ptr::null_mut()); }
}

#[test]
fn test_validator_builder_with_compiled_trust_plan() {
    let validator_builder = create_validator_builder();
    let mut plan_builder: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_plan_builder_new_from_validator_builder(
            validator_builder, 
            &mut plan_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let result = unsafe { cose_sign1_trust_plan_builder_compile_allow_all(plan_builder, &mut compiled_plan) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Attach to validator builder
    let result = unsafe {
        cose_sign1_validator_builder_with_compiled_trust_plan(
            validator_builder, 
            compiled_plan
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Note: compiled_plan ownership transferred to validator_builder, don't free it
    unsafe {
        cose_sign1_trust_plan_builder_free(plan_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_new_from_validator_builder() {
    let validator_builder = create_validator_builder();
    
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    
    assert_eq!(result, cose_status_t::COSE_OK);
    assert!(!policy_builder.is_null());
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_free_null_safety() {
    // Should not crash with null pointer
    unsafe { cose_sign1_trust_policy_builder_free(ptr::null_mut()); }
}

#[test]
fn test_trust_policy_builder_logical_operations() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test AND operation
    let result = unsafe { cose_sign1_trust_policy_builder_and(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test OR operation
    let result = unsafe { cose_sign1_trust_policy_builder_or(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_content_type_requirements() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test require content type non-empty
    let result = unsafe { cose_sign1_trust_policy_builder_require_content_type_non_empty(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test require content type equals
    let content_type = CString::new("application/test").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_content_type_eq(
            policy_builder, 
            content_type.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_payload_requirements() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test require detached payload present
    let result = unsafe { cose_sign1_trust_policy_builder_require_detached_payload_present(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test require detached payload absent
    let result = unsafe { cose_sign1_trust_policy_builder_require_detached_payload_absent(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_cwt_claims_requirements() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test require CWT claims present/absent
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_present(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_absent(policy_builder) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test standard claims
    let issuer = CString::new("test-issuer").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_iss_eq(
            policy_builder, 
            issuer.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let subject = CString::new("test-subject").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_sub_eq(
            policy_builder, 
            subject.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let audience = CString::new("test-audience").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_aud_eq(
            policy_builder, 
            audience.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_cwt_time_requirements() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let test_time = 1640995200i64; // 2022-01-01
    
    // Test expiration requirements
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_ge(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_exp_le(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test not before requirements
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_ge(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_nbf_le(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test issued at requirements
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_ge(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe { cose_sign1_trust_policy_builder_require_cwt_iat_le(policy_builder, test_time) };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_cwt_claim_label_requirements() {
    let validator_builder = create_validator_builder();
    let mut policy_builder: *mut cose_trust_policy_builder_t = ptr::null_mut();
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_new_from_validator_builder(
            validator_builder, 
            &mut policy_builder
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test claim present by label
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_present(
            policy_builder, 
            100  // Custom claim label
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test integer comparisons
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_eq(
            policy_builder, 
            100, 
            42
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_ge(
            policy_builder, 
            101, 
            10
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_i64_le(
            policy_builder, 
            102, 
            100
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test boolean comparison
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_bool_eq(
            policy_builder, 
            103, 
            true
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    // Test string comparisons
    let test_value = CString::new("test-value").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_eq(
            policy_builder, 
            104, 
            test_value.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let test_prefix = CString::new("test").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy_builder, 
            105, 
            test_prefix.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    let test_substring = CString::new("est").unwrap();
    let result = unsafe {
        cose_sign1_trust_policy_builder_require_cwt_claim_label_str_contains(
            policy_builder, 
            106, 
            test_substring.as_ptr()
        )
    };
    assert_eq!(result, cose_status_t::COSE_OK);
    
    unsafe {
        cose_sign1_trust_policy_builder_free(policy_builder);
        cose_sign1_validator_builder_free(validator_builder);
    }
}

#[test]
fn test_trust_policy_builder_null_pointer_safety() {
    // Test various functions with null policy builders
    assert_ne!(unsafe { cose_sign1_trust_policy_builder_and(ptr::null_mut()) }, cose_status_t::COSE_OK);
    assert_ne!(unsafe { cose_sign1_trust_policy_builder_or(ptr::null_mut()) }, cose_status_t::COSE_OK);
    assert_ne!(
        unsafe { cose_sign1_trust_policy_builder_require_content_type_non_empty(ptr::null_mut()) },
        cose_status_t::COSE_OK
    );
    assert_ne!(
        unsafe { cose_sign1_trust_policy_builder_require_cwt_claims_present(ptr::null_mut()) },
        cose_status_t::COSE_OK
    );
    
    let test_string = CString::new("test").unwrap();
    assert_ne!(
        unsafe {
            cose_sign1_trust_policy_builder_require_content_type_eq(
                ptr::null_mut(), 
                test_string.as_ptr()
            )
        },
        cose_status_t::COSE_OK
    );
}

#[test]
fn test_trust_plan_builder_null_pointer_safety() {
    // Test various functions with null plan builders
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_add_all_pack_default_plans(ptr::null_mut()) },
        cose_status_t::COSE_OK
    );
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_clear_selected_plans(ptr::null_mut()) },
        cose_status_t::COSE_OK
    );
    
    let mut count: usize = 0;
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_pack_count(ptr::null_mut(), &mut count) },
        cose_status_t::COSE_OK
    );
    
    let mut compiled_plan: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_compile_or(ptr::null_mut(), &mut compiled_plan) },
        cose_status_t::COSE_OK
    );
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_compile_and(ptr::null_mut(), &mut compiled_plan) },
        cose_status_t::COSE_OK
    );
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_compile_allow_all(ptr::null_mut(), &mut compiled_plan) },
        cose_status_t::COSE_OK
    );
    assert_ne!(
        unsafe { cose_sign1_trust_plan_builder_compile_deny_all(ptr::null_mut(), &mut compiled_plan) },
        cose_status_t::COSE_OK
    );
}
