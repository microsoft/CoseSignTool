// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Null-safety coverage for validation-primitives FFI functions.

#![allow(unused_unsafe)]

use std::ptr;
use cose_sign1_validation_ffi::{
    cose_status_t, cose_sign1_validator_builder_new, cose_sign1_validator_builder_free,
    cose_trust_policy_builder_t, cose_sign1_validator_builder_t,
};
use cose_sign1_validation_primitives_ffi::*;

const COSE_OK: cose_status_t = cose_status_t::COSE_OK;

fn make_validator_builder() -> *mut cose_sign1_validator_builder_t {
    let mut b: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let r = cose_sign1_validator_builder_new(&mut b);
    assert_eq!(r, COSE_OK);
    b
}

// ---------- trust plan builder null checks ----------

#[test]
fn plan_builder_new_null_out() {
    let vb = make_validator_builder();
    let r = cose_sign1_trust_plan_builder_new_from_validator_builder(vb, ptr::null_mut());
    assert_ne!(r, COSE_OK);
    cose_sign1_validator_builder_free(vb);
}

#[test]
fn plan_builder_new_null_builder() {
    let mut out: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    let r = cose_sign1_trust_plan_builder_new_from_validator_builder(ptr::null(), &mut out);
    assert_ne!(r, COSE_OK);
}

#[test]
fn plan_builder_add_all_null() {
    let r = cose_sign1_trust_plan_builder_add_all_pack_default_plans(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn plan_builder_pack_count_null_builder() {
    let mut count: usize = 99;
    let r = cose_sign1_trust_plan_builder_pack_count(ptr::null(), &mut count);
    assert_ne!(r, COSE_OK);
}

#[test]
fn plan_builder_pack_count_null_out() {
    let vb = make_validator_builder();
    let mut pb: *mut cose_sign1_trust_plan_builder_t = ptr::null_mut();
    cose_sign1_trust_plan_builder_new_from_validator_builder(vb, &mut pb);
    let r = cose_sign1_trust_plan_builder_pack_count(pb, ptr::null_mut());
    assert_ne!(r, COSE_OK);
    cose_sign1_trust_plan_builder_free(pb);
    cose_sign1_validator_builder_free(vb);
}

#[test]
fn plan_builder_compile_or_null() {
    let mut out: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let r = cose_sign1_trust_plan_builder_compile_or(ptr::null_mut(), &mut out);
    assert_ne!(r, COSE_OK);
}

#[test]
fn plan_builder_compile_and_null() {
    let mut out: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let r = cose_sign1_trust_plan_builder_compile_and(ptr::null_mut(), &mut out);
    assert_ne!(r, COSE_OK);
}

#[test]
fn plan_builder_clear_null() {
    let r = cose_sign1_trust_plan_builder_clear_selected_plans(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

// ---------- trust policy builder null checks ----------

#[test]
fn policy_builder_new_null_out() {
    let vb = make_validator_builder();
    let r = cose_sign1_trust_policy_builder_new_from_validator_builder(vb, ptr::null_mut());
    assert_ne!(r, COSE_OK);
    cose_sign1_validator_builder_free(vb);
}

#[test]
fn policy_builder_and_null() {
    let r = cose_sign1_trust_policy_builder_and(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn policy_builder_or_null() {
    let r = cose_sign1_trust_policy_builder_or(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

// ---------- require_* with null policy builder ----------

#[test]
fn require_content_type_non_empty_null() {
    let r = cose_sign1_trust_policy_builder_require_content_type_non_empty(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn require_detached_payload_present_null() {
    let r = cose_sign1_trust_policy_builder_require_detached_payload_present(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn require_detached_payload_absent_null() {
    let r = cose_sign1_trust_policy_builder_require_detached_payload_absent(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn require_cwt_claims_present_null() {
    let r = cose_sign1_trust_policy_builder_require_cwt_claims_present(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

#[test]
fn require_cwt_claims_absent_null() {
    let r = cose_sign1_trust_policy_builder_require_cwt_claims_absent(ptr::null_mut());
    assert_ne!(r, COSE_OK);
}

// ---------- compile null checks ----------

#[test]
fn policy_builder_compile_null_builder() {
    let mut out: *mut cose_sign1_compiled_trust_plan_t = ptr::null_mut();
    let r = cose_sign1_trust_policy_builder_compile(ptr::null_mut(), &mut out);
    assert_ne!(r, COSE_OK);
}

#[test]
fn policy_builder_compile_null_out() {
    let vb = make_validator_builder();
    let mut pb: *mut cose_trust_policy_builder_t = ptr::null_mut();
    cose_sign1_trust_policy_builder_new_from_validator_builder(vb, &mut pb);
    let r = cose_sign1_trust_policy_builder_compile(pb, ptr::null_mut());
    assert_ne!(r, COSE_OK);
    cose_sign1_trust_policy_builder_free(pb);
    cose_sign1_validator_builder_free(vb);
}

// ---------- free null is no-op ----------

#[test]
fn plan_builder_free_null_is_noop() {
    cose_sign1_trust_plan_builder_free(ptr::null_mut());
}

#[test]
fn policy_builder_free_null_is_noop() {
    cose_sign1_trust_policy_builder_free(ptr::null_mut());
}

#[test]
fn compiled_plan_free_null_is_noop() {
    cose_sign1_compiled_trust_plan_free(ptr::null_mut());
}
