use cose_sign1_validation_ffi::{
    cose_last_error_message_utf8, cose_status_t, cose_string_free, cose_validator_builder_free,
    cose_trust_policy_builder_t, cose_validator_builder_new, cose_validator_builder_t,
};
use cose_sign1_validation_ffi_trust::*;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::ptr;

fn last_error_string() -> Option<String> {
    let p = cose_last_error_message_utf8();
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
    unsafe { cose_string_free(p) };
    Some(s)
}

fn assert_err(status: cose_status_t) {
    assert_eq!(status, cose_status_t::COSE_ERR);
    assert!(last_error_string().is_some());
}

fn invalid_utf8_ptr() -> *const c_char {
    // Valid C string (NUL-terminated) but invalid UTF-8.
    static BYTES: [u8; 2] = [0xFF, 0x00];
    BYTES.as_ptr() as *const c_char
}

#[test]
fn trust_ffi_error_branches_are_exercised() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Plan builder creation error branches.
    let mut bogus_out: *mut cose_trust_plan_builder_t = ptr::null_mut();
    assert_err(cose_trust_plan_builder_new_from_validator_builder(
        ptr::null(),
        &mut bogus_out,
    ));
    assert_err(cose_trust_plan_builder_new_from_validator_builder(
        builder,
        ptr::null_mut(),
    ));

    let mut plan_builder: *mut cose_trust_plan_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, &mut plan_builder),
        cose_status_t::COSE_OK
    );
    assert!(!plan_builder.is_null());

    // Pack enumeration null out params.
    assert_err(cose_trust_plan_builder_pack_count(plan_builder, ptr::null_mut()));
    assert_err(cose_trust_plan_builder_pack_has_default_plan(
        plan_builder,
        0,
        ptr::null_mut(),
    ));

    // pack_name_from_ptr: invalid UTF-8.
    assert_err(cose_trust_plan_builder_add_pack_default_plan_by_name(
        plan_builder,
        invalid_utf8_ptr(),
    ));

    // Compile helpers: null out_plan.
    assert_err(cose_trust_plan_builder_compile_or(plan_builder, ptr::null_mut()));
    assert_err(cose_trust_plan_builder_compile_and(plan_builder, ptr::null_mut()));
    assert_err(cose_trust_plan_builder_compile_allow_all(
        plan_builder,
        ptr::null_mut(),
    ));
    assert_err(cose_trust_plan_builder_compile_deny_all(plan_builder, ptr::null_mut()));

    // builder + plan attach error branches.
    assert_err(cose_validator_builder_with_compiled_trust_plan(
        ptr::null_mut(),
        ptr::null(),
    ));

    cose_trust_plan_builder_free(plan_builder);

    // Policy builder creation error branch.
    assert_err(cose_trust_policy_builder_new_from_validator_builder(
        builder,
        ptr::null_mut(),
    ));

    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // String parsing error branches.
    assert_err(cose_trust_policy_builder_require_content_type_eq(
        policy,
        ptr::null(),
    ));
    assert_err(cose_trust_policy_builder_require_cwt_claim_text_str_contains(
        policy,
        invalid_utf8_ptr(),
        invalid_utf8_ptr(),
    ));

    // compile error branches.
    assert_err(cose_trust_policy_builder_compile(policy, ptr::null_mut()));

    let mut plan: *mut cose_compiled_trust_plan_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_compiled_trust_plan_free(plan);

    // compile again should fail (policy_builder consumed).
    let mut plan2: *mut cose_compiled_trust_plan_t = ptr::null_mut();
    assert_err(cose_trust_policy_builder_compile(policy, &mut plan2));

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
}

#[test]
fn trust_pack_name_utf8_null_builder_sets_last_error() {
    // This function returns a pointer; error surface is via last_error.
    let p = cose_trust_plan_builder_pack_name_utf8(ptr::null(), 0);
    assert!(p.is_null());
    assert!(last_error_string().is_some());
}
