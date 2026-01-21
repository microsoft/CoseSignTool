//! Trust policy authoring FFI bindings.
//!
//! This crate exposes a C ABI for authoring a bundled compiled trust plan and attaching it
//! to a validator builder.
//!
//! Design goal: per-pack modularity.
//! - Packs (certificates/MST/AKV/...) remain separate crates and can be added to the base
//!   `cose_validator_builder_t` independently.
//! - Trust-plan authoring is exposed as a separate pack (`cose_sign1_validation_ffi_trust`).
//!
//! Current scope (M3 foundation): compile a bundled plan by composing the *default trust plans*
//! provided by configured trust packs. This is the minimal, deterministic authoring surface that
//! works well across C and C++.
//!
//! Future expansions can add declarative rule/predicate authoring in a stable way.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation::fluent::{
    CoseSign1CompiledTrustPlan, CoseSign1TrustPack, CwtClaimsFact, CwtClaimsWhereExt,
    CounterSignatureEnvelopeIntegrityFact, MessageScopeRulesExt, TrustPlanBuilder,
};
use cose_sign1_validation_ffi::{
    cose_status_t, cose_trust_policy_builder_t, cose_validator_builder_t, with_catch_unwind,
    with_trust_policy_builder_mut as with_policy_builder_mut,
};
use cose_sign1_validation_trust::fact_properties::FactValueOwned;
use cose_sign1_validation_trust::field::Field;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use cose_sign1_validation_trust::rules::{
    allow_all, all_of, any_of, require_fact_matches_with_missing_behavior, FactSelector,
    MissingBehavior, PropertyPredicate,
};
use std::collections::HashSet;
use std::ffi::{c_char, CStr};
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;

#[repr(C)]
pub struct cose_trust_plan_builder_t {
    packs: Vec<Arc<dyn CoseSign1TrustPack>>,
    selected_plans: Vec<CompiledTrustPlan>,
}

#[repr(C)]
pub struct cose_compiled_trust_plan_t {
    bundled: CoseSign1CompiledTrustPlan,
}

#[inline(never)]
fn to_new_utf8(s: &str) -> *mut c_char {
    CString::new(s)
        .unwrap_or_else(|_| CString::new("string contained NUL").unwrap())
        .into_raw()
}

#[inline(never)]
fn pack_name_from_ptr(pack_name_utf8: *const c_char) -> Result<String, anyhow::Error> {
    if pack_name_utf8.is_null() {
        anyhow::bail!("pack_name_utf8 must not be null");
    }
    let s = unsafe { CStr::from_ptr(pack_name_utf8) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("pack_name_utf8 must be valid UTF-8"))?;
    Ok(s.to_string())
}

#[inline(never)]
fn string_from_ptr(arg_name: &'static str, s: *const c_char) -> Result<String, anyhow::Error> {
    if s.is_null() {
        anyhow::bail!("{arg_name} must not be null");
    }
    let s = unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("{arg_name} must be valid UTF-8"))?;
    Ok(s.to_string())
}


fn collect_default_plan_for_pack(
    pack: &Arc<dyn CoseSign1TrustPack>,
) -> Result<CompiledTrustPlan, anyhow::Error> {
    pack.default_trust_plan()
        .ok_or_else(|| anyhow::anyhow!("pack '{}' does not provide a default trust plan", pack.name()))
}

#[inline(never)]
fn compile_or_selected(selected: Vec<CompiledTrustPlan>) -> CompiledTrustPlan {
    CompiledTrustPlan::or_plans(selected)
}

#[inline(never)]
fn compile_and_selected(selected: Vec<CompiledTrustPlan>) -> CompiledTrustPlan {
    // AND multiple independent plans by treating them as constraints and providing an allow_all
    // trust source to satisfy the plan semantics:
    // constraints AND (OR trust_sources) AND NOT(OR vetoes)
    // => all(plans) AND allow_all AND true
    let mut required = HashSet::new();
    let mut rules = Vec::new();
    for plan in &selected {
        for k in plan.required_facts() {
            required.insert(*k);
        }
        rules.push(plan.as_rule_ref());
    }

    let constraints_rule = all_of("and_plans", rules);
    CompiledTrustPlan::new(
        required.into_iter().collect(),
        vec![constraints_rule],
        vec![allow_all("and_trust_sources")],
        Vec::new(),
    )
}

#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_new_from_validator_builder(
    builder: *const cose_validator_builder_t,
    out: *mut *mut cose_trust_plan_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }
        let builder = unsafe { builder.as_ref() }.ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        let boxed = Box::new(cose_trust_plan_builder_t {
            packs: builder.packs.clone(),
            selected_plans: Vec::new(),
        });

        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_free(plan_builder: *mut cose_trust_plan_builder_t) {
    if plan_builder.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(plan_builder));
    }
}

/// Select all configured packs' default trust plans.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_add_all_pack_default_plans(
    plan_builder: *mut cose_trust_plan_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        for pack in &plan_builder.packs {
            if let Some(p) = pack.default_trust_plan() {
                plan_builder.selected_plans.push(p);
            }
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Select a specific pack's default trust plan by pack name.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_add_pack_default_plan_by_name(
    plan_builder: *mut cose_trust_plan_builder_t,
    pack_name_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;
        let pack_name = pack_name_from_ptr(pack_name_utf8)?;

        let Some(pack) = plan_builder
            .packs
            .iter()
            .find(|p| p.name() == pack_name.as_str())
        else {
            anyhow::bail!("no configured pack named '{pack_name}'");
        };

        let plan = collect_default_plan_for_pack(pack)?;
        plan_builder.selected_plans.push(plan);
        Ok(cose_status_t::COSE_OK)
    })
}

/// Returns the number of packs configured on this plan builder.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_pack_count(
    plan_builder: *const cose_trust_plan_builder_t,
    out_count: *mut usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_count.is_null() {
            anyhow::bail!("out_count must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        unsafe {
            *out_count = plan_builder.packs.len();
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Returns the pack name at `index` as a newly-allocated UTF-8 string.
///
/// Ownership: caller must free via `cose_string_free`.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_pack_name_utf8(
    plan_builder: *const cose_trust_plan_builder_t,
    index: usize,
) -> *mut c_char {
    cose_sign1_validation_ffi::clear_last_error();
    let Some(plan_builder) = (unsafe { plan_builder.as_ref() }) else {
        cose_sign1_validation_ffi::set_last_error("plan_builder must not be null");
        return ptr::null_mut();
    };

    let Some(pack) = plan_builder.packs.get(index) else {
        cose_sign1_validation_ffi::set_last_error("index out of range");
        return ptr::null_mut();
    };

    to_new_utf8(pack.name())
}

/// Returns whether the pack at `index` provides a default trust plan.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_pack_has_default_plan(
    plan_builder: *const cose_trust_plan_builder_t,
    index: usize,
    out_has_default: *mut bool,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_has_default.is_null() {
            anyhow::bail!("out_has_default must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;
        let pack = plan_builder
            .packs
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("index out of range"))?;

        unsafe {
            *out_has_default = pack.default_trust_plan().is_some();
        }

        Ok(cose_status_t::COSE_OK)
    })
}

/// Clears any selected plans on the builder.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_clear_selected_plans(
    plan_builder: *mut cose_trust_plan_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;
        plan_builder.selected_plans.clear();
        Ok(cose_status_t::COSE_OK)
    })
}

#[no_mangle]
pub extern "C" fn cose_compiled_trust_plan_free(plan: *mut cose_compiled_trust_plan_t) {
    if plan.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(plan));
    }
}

/// Compile the selected plans as an OR-composed bundled plan.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_compile_or(
    plan_builder: *mut cose_trust_plan_builder_t,
    out_plan: *mut *mut cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        if plan_builder.selected_plans.is_empty() {
            anyhow::bail!("no plans selected; call cose_trust_plan_builder_add_* first");
        }

        let plan = compile_or_selected(std::mem::take(&mut plan_builder.selected_plans));
        let bundled = CoseSign1CompiledTrustPlan::from_parts(plan, plan_builder.packs.clone())?;
        let boxed = Box::new(cose_compiled_trust_plan_t { bundled });
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Compile the selected plans as an AND-composed bundled plan.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_compile_and(
    plan_builder: *mut cose_trust_plan_builder_t,
    out_plan: *mut *mut cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        if plan_builder.selected_plans.is_empty() {
            anyhow::bail!("no plans selected; call cose_trust_plan_builder_add_* first");
        }

        let plan = compile_and_selected(std::mem::take(&mut plan_builder.selected_plans));
        let bundled = CoseSign1CompiledTrustPlan::from_parts(plan, plan_builder.packs.clone())?;
        let boxed = Box::new(cose_compiled_trust_plan_t { bundled });
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Compile an allow-all bundled plan.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_compile_allow_all(
    plan_builder: *mut cose_trust_plan_builder_t,
    out_plan: *mut *mut cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        let plan = CompiledTrustPlan::new(Vec::new(), Vec::new(), vec![allow_all("AllowAll")], Vec::new());
        let bundled = CoseSign1CompiledTrustPlan::from_parts(plan, plan_builder.packs.clone())?;
        let boxed = Box::new(cose_compiled_trust_plan_t { bundled });
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Compile a deny-all bundled plan.
#[no_mangle]
pub extern "C" fn cose_trust_plan_builder_compile_deny_all(
    plan_builder: *mut cose_trust_plan_builder_t,
    out_plan: *mut *mut cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        let plan_builder = unsafe { plan_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("plan_builder must not be null"))?;

        let plan = CompiledTrustPlan::new(Vec::new(), Vec::new(), vec![any_of("DenyAll", Vec::new())], Vec::new());
        let bundled = CoseSign1CompiledTrustPlan::from_parts(plan, plan_builder.packs.clone())?;
        let boxed = Box::new(cose_compiled_trust_plan_t { bundled });
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

/// Attach a bundled compiled trust plan to a validator builder.
///
/// This causes the eventual validator to use the bundled plan instead of OR-composing
/// pack default plans.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_compiled_trust_plan(
    builder: *mut cose_validator_builder_t,
    plan: *const cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        let plan = unsafe { plan.as_ref() }.ok_or_else(|| anyhow::anyhow!("plan must not be null"))?;

        builder.compiled_plan = Some(plan.bundled.clone());
        Ok(cose_status_t::COSE_OK)
    })
}

/// Create a trust-policy builder from the packs configured on the validator builder.
///
/// This builder starts empty and lets callers express a small, stable subset of message-scope
/// requirements without referencing Rust fact types.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_new_from_validator_builder(
    builder: *const cose_validator_builder_t,
    out: *mut *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out.is_null() {
            anyhow::bail!("out must not be null");
        }
        let builder = unsafe { builder.as_ref() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;

        let plan_builder = TrustPlanBuilder::new(builder.packs.clone());
        let boxed = Box::new(cose_trust_policy_builder_t {
            builder: Some(plan_builder),
        });
        unsafe {
            *out = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}

#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_free(policy_builder: *mut cose_trust_policy_builder_t) {
    if policy_builder.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(policy_builder));
    }
}

/// Set the next composition operator to AND.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_and(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| b.and())?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Set the next composition operator to OR.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_or(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| b.or())?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that Content-Type is present and non-empty.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_content_type_non_empty(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_content_type_non_empty())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that Content-Type equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_content_type_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    content_type_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let content_type = string_from_ptr("content_type_utf8", content_type_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_content_type_eq(content_type))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a detached payload is present.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_detached_payload_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_detached_payload_present())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a detached payload is absent.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_detached_payload_absent(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_detached_payload_absent())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// If the counter-signature verifier produced `CounterSignatureEnvelopeIntegrityFact`, require
/// that `sig_structure_intact` is `true`.
///
/// If the fact is missing, this requirement is treated as trusted (so it does not require
/// linking any optional counter-signature pack).
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                let selector = FactSelector::first().where_pred(
                    "sig_structure_intact",
                    PropertyPredicate::Eq(FactValueOwned::Bool(true)),
                );

                let rule = require_fact_matches_with_missing_behavior::<
                    CounterSignatureEnvelopeIntegrityFact,
                    _,
                >(
                    std::any::type_name::<CounterSignatureEnvelopeIntegrityFact>(),
                    |subj| subj.clone(),
                    selector,
                    MissingBehavior::Allow,
                    "RequirementNotSatisfied",
                );

                s.require_rule(rule, [])
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT Claims are present.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claims_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_cwt_claims_present())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT Claims are absent.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claims_absent(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_cwt_claims_absent())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `iss` (issuer) equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_iss_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    iss_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let iss = string_from_ptr("iss_utf8", iss_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require::<CwtClaimsFact>(|w| w.iss_eq(iss)))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `sub` (subject) equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_sub_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    sub_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let sub = string_from_ptr("sub_utf8", sub_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require::<CwtClaimsFact>(|w| w.sub_eq(sub)))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `aud` (audience) equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_aud_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    aud_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let aud = string_from_ptr("aud_utf8", aud_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require::<CwtClaimsFact>(|w| w.aud_eq(aud)))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim is present (and can be decoded).
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_present(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_cwt_claim(label, |_r| true))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim is present (and can be decoded).
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_present(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| s.require_cwt_claim(key, |_r| true))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to an `i64` and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_i64_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    value: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| matches!(r.decode::<i64>(), Some(v) if v == value))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to a `bool` and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_bool_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    value: bool,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| matches!(r.decode::<bool>(), Some(v) if v == value))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to an `i64` and is >= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_i64_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    min: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| matches!(r.decode::<i64>(), Some(v) if v >= min))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to an `i64` and is <= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_i64_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    max: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| matches!(r.decode::<i64>(), Some(v) if v <= max))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to a UTF-8 string and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_str_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    value_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        let value = string_from_ptr("value_utf8", value_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v == value)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to a UTF-8 string and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_str_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    value_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let value = string_from_ptr("value_utf8", value_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v == value)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to a UTF-8 string and starts with `prefix`.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    prefix_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let prefix = string_from_ptr("prefix_utf8", prefix_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v.starts_with(prefix.as_str()))
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to a UTF-8 string and starts with `prefix`.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    prefix_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        let prefix = string_from_ptr("prefix_utf8", prefix_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v.starts_with(prefix.as_str()))
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a numeric-label CWT claim decodes to a UTF-8 string and contains `needle`.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_label_str_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    label: i64,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(label, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v.contains(needle.as_str()))
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to a UTF-8 string and contains `needle`.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_str_contains(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    needle_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        let needle = string_from_ptr("needle_utf8", needle_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| {
                    matches!(r.decode::<String>(), Some(v) if v.contains(needle.as_str()))
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to a `bool` and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_bool_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    value: bool,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| matches!(r.decode::<bool>(), Some(v) if v == value))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to an `i64` and is >= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_i64_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    min: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| matches!(r.decode::<i64>(), Some(v) if v >= min))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to an `i64` and is <= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_i64_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    max: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| matches!(r.decode::<i64>(), Some(v) if v <= max))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that a text-key CWT claim decodes to an `i64` and equals the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_claim_text_i64_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    key_utf8: *const c_char,
    value: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        let key = string_from_ptr("key_utf8", key_utf8)?;
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require_cwt_claim(key, move |r| {
                    matches!(r.decode::<i64>(), Some(v) if v == value)
                })
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `exp` (expiration time) is >= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_exp_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    min: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_ge(Field::new("exp"), min))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `exp` (expiration time) is <= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_exp_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    max: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_le(Field::new("exp"), max))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `nbf` (not before) is >= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_nbf_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    min: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_ge(Field::new("nbf"), min))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `nbf` (not before) is <= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_nbf_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    max: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_le(Field::new("nbf"), max))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `iat` (issued at) is >= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_iat_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    min: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_ge(Field::new("iat"), min))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Require that CWT `iat` (issued at) is <= the provided value.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_require_cwt_iat_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    max: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_policy_builder_mut(policy_builder, |b| {
            b.for_message(|s| {
                s.require::<CwtClaimsFact>(|w| w.i64_le(Field::new("iat"), max))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Compile this policy into a bundled compiled trust plan.
#[no_mangle]
pub extern "C" fn cose_trust_policy_builder_compile(
    policy_builder: *mut cose_trust_policy_builder_t,
    out_plan: *mut *mut cose_compiled_trust_plan_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        if out_plan.is_null() {
            anyhow::bail!("out_plan must not be null");
        }
        let policy_builder = unsafe { policy_builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("policy_builder must not be null"))?;
        let builder = policy_builder
            .builder
            .take()
            .ok_or_else(|| anyhow::anyhow!("policy_builder already compiled or invalid"))?;

        let bundled = builder.compile()?;
        let boxed = Box::new(cose_compiled_trust_plan_t { bundled });
        unsafe {
            *out_plan = Box::into_raw(boxed);
        }
        Ok(cose_status_t::COSE_OK)
    })
}
