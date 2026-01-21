use cose_sign1_validation_ffi::*;
use cose_sign1_validation_ffi_trust::*;
use cose_sign1_validation::fluent::{CoseSign1TrustPack, CwtClaimsFact};
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::ffi::{CStr, CString};
use std::sync::Arc;

fn last_error_string() -> Option<String> {
    let p = cose_last_error_message_utf8();
    if p.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().to_string();
    unsafe { cose_string_free(p) };
    Some(s)
}

fn minimal_cose_sign1() -> Vec<u8> {
    vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g']
}

struct DummyProducer;

impl TrustFactProducer for DummyProducer {
    fn name(&self) -> &'static str {
        "DummyProducer"
    }

    fn produce(&self, _ctx: &mut TrustFactContext<'_>) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        &[]
    }
}

struct DummyPack;

impl CoseSign1TrustPack for DummyPack {
    fn name(&self) -> &'static str {
        "DummyPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(DummyProducer)
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        // Keep it deterministic and plan-only: allow_all as a trust source.
        // Include a required fact so `compile_and_selected` exercises required-fact merging.
        Some(CompiledTrustPlan::new(
            vec![FactKey::of::<CwtClaimsFact>()],
            Vec::new(),
            vec![cose_sign1_validation_trust::rules::allow_all("dummy_allow")],
            Vec::new(),
        ))
    }
}

#[test]
fn trust_plan_builder_clear_and_free_null_paths() {
    // Null frees are no-ops.
    cose_trust_plan_builder_free(std::ptr::null_mut());
    cose_trust_policy_builder_free(std::ptr::null_mut());
    cose_compiled_trust_plan_free(std::ptr::null_mut());

    // Create a plan builder so we can explicitly clear selections.
    let mut builder: *mut cose_validator_builder_t = std::ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    unsafe {
        (*builder).packs.push(Arc::new(DummyPack));
    }

    let mut plan_builder: *mut cose_trust_plan_builder_t = std::ptr::null_mut();
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, &mut plan_builder),
        cose_status_t::COSE_OK
    );
    assert!(!plan_builder.is_null());

    assert_eq!(
        cose_trust_plan_builder_add_all_pack_default_plans(plan_builder),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_plan_builder_clear_selected_plans(plan_builder),
        cose_status_t::COSE_OK
    );

    cose_trust_plan_builder_free(plan_builder);
    cose_validator_builder_free(builder);
}

#[test]
fn policy_builder_compiles_and_attaches() {
    let mut builder: *mut cose_validator_builder_t = std::ptr::null_mut();
    let status = cose_validator_builder_new(&mut builder);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    let mut policy: *mut cose_trust_policy_builder_t = std::ptr::null_mut();
    let status = cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!policy.is_null());

    let status = cose_trust_policy_builder_require_detached_payload_absent(policy);
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut plan: *mut cose_compiled_trust_plan_t = std::ptr::null_mut();
    let status = cose_trust_policy_builder_compile(policy, &mut plan);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    cose_trust_policy_builder_free(policy);

    let status = cose_validator_builder_with_compiled_trust_plan(builder, plan);
    assert_eq!(status, cose_status_t::COSE_OK);
    cose_compiled_trust_plan_free(plan);

    let mut validator: *mut cose_validator_t = std::ptr::null_mut();
    let status = cose_validator_builder_build(builder, &mut validator);
    assert_eq!(status, cose_status_t::COSE_OK, "{:?}", last_error_string());
    assert!(!validator.is_null());

    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}

#[test]
fn trust_plan_builder_exports_are_exercised() {
    // Create a base builder and seed it with a pack that has a default plan.
    let mut builder: *mut cose_validator_builder_t = std::ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());
    unsafe {
        (*builder).packs.push(Arc::new(DummyPack));
    }

    // new_from_validator_builder: null out => error
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, std::ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    let mut plan_builder: *mut cose_trust_plan_builder_t = std::ptr::null_mut();
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, &mut plan_builder),
        cose_status_t::COSE_OK
    );
    assert!(!plan_builder.is_null());

    // Pack enumeration.
    let mut count: usize = 0;
    assert_eq!(
        cose_trust_plan_builder_pack_count(plan_builder, &mut count),
        cose_status_t::COSE_OK
    );
    assert!(count >= 1);

    let name_ptr = cose_trust_plan_builder_pack_name_utf8(plan_builder, 0);
    assert!(!name_ptr.is_null());
    unsafe { cose_string_free(name_ptr) };

    // Index out of range => null + last_error.
    let bad = cose_trust_plan_builder_pack_name_utf8(plan_builder, 999);
    assert!(bad.is_null());
    assert!(last_error_string().is_some());

    let mut has_default = false;
    assert_eq!(
        cose_trust_plan_builder_pack_has_default_plan(plan_builder, 0, &mut has_default),
        cose_status_t::COSE_OK
    );
    assert!(has_default);

    // Selection helpers.
    assert_eq!(
        cose_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, std::ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    let dummy = CString::new("DummyPack").unwrap();
    assert_eq!(
        cose_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, dummy.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Compile OR/AND paths.
    let mut plan: *mut cose_compiled_trust_plan_t = std::ptr::null_mut();
    assert_eq!(
        cose_trust_plan_builder_compile_or(plan_builder, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_compiled_trust_plan_free(plan);

    // Selected plans were drained; compiling again should fail until we select again.
    assert_eq!(
        cose_trust_plan_builder_compile_or(plan_builder, &mut plan),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    assert_eq!(
        cose_trust_plan_builder_add_all_pack_default_plans(plan_builder),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_plan_builder_compile_and(plan_builder, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_compiled_trust_plan_free(plan);

    // allow-all / deny-all compile paths.
    assert_eq!(
        cose_trust_plan_builder_compile_allow_all(plan_builder, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_compiled_trust_plan_free(plan);

    assert_eq!(
        cose_trust_plan_builder_compile_deny_all(plan_builder, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_compiled_trust_plan_free(plan);

    cose_trust_plan_builder_free(plan_builder);
    cose_validator_builder_free(builder);
}

#[test]
fn trust_policy_builder_exports_are_exercised() {
    let mut builder: *mut cose_validator_builder_t = std::ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    let mut policy: *mut cose_trust_policy_builder_t = std::ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // Composition operators.
    assert_eq!(cose_trust_policy_builder_and(policy), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_or(policy), cose_status_t::COSE_OK);

    // Message-scope helpers.
    assert_eq!(
        cose_trust_policy_builder_require_content_type_non_empty(policy),
        cose_status_t::COSE_OK
    );
    let ct = CString::new("application/test").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_content_type_eq(policy, ct.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_detached_payload_present(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_detached_payload_absent(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(policy),
        cose_status_t::COSE_OK
    );

    // CWT helpers (exercise the remaining exports quickly).
    assert_eq!(cose_trust_policy_builder_require_cwt_claims_present(policy), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claims_absent(policy), cose_status_t::COSE_OK);
    let iss = CString::new("issuer").unwrap();
    let sub = CString::new("subject").unwrap();
    let aud = CString::new("audience").unwrap();
    assert_eq!(cose_trust_policy_builder_require_cwt_iss_eq(policy, iss.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_sub_eq(policy, sub.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_aud_eq(policy, aud.as_ptr()), cose_status_t::COSE_OK);

    let key = CString::new("nonce").unwrap();
    let val = CString::new("v").unwrap();
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_present(policy, 1), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_present(policy, key.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_i64_eq(policy, 1, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_bool_eq(policy, 1, true), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_i64_ge(policy, 1, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_i64_le(policy, 1, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_bool_eq(policy, key.as_ptr(), true), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_i64_ge(policy, key.as_ptr(), 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_i64_le(policy, key.as_ptr(), 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_i64_eq(policy, key.as_ptr(), 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_str_eq(policy, key.as_ptr(), val.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_str_eq(policy, 2, val.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(policy, 2, val.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(policy, key.as_ptr(), val.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_label_str_contains(policy, 2, val.as_ptr()), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_claim_text_str_contains(policy, key.as_ptr(), val.as_ptr()), cose_status_t::COSE_OK);

    assert_eq!(cose_trust_policy_builder_require_cwt_exp_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_exp_le(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_le(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_le(policy, 0), cose_status_t::COSE_OK);

    // Compile + attach + validate to execute the compiled-plan attach path.
    let mut plan: *mut cose_compiled_trust_plan_t = std::ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_OK,
        "{:?}",
        last_error_string()
    );
    assert!(!plan.is_null());
    cose_trust_policy_builder_free(policy);

    assert_eq!(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        cose_status_t::COSE_OK
    );
    cose_compiled_trust_plan_free(plan);

    let mut validator: *mut cose_validator_t = std::ptr::null_mut();
    assert_eq!(
        cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    let bytes = minimal_cose_sign1();
    let mut result: *mut cose_validation_result_t = std::ptr::null_mut();
    assert_eq!(
        cose_validator_validate_bytes(
            validator,
            bytes.as_ptr(),
            bytes.len(),
            std::ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK
    );
    assert!(!result.is_null());
    cose_validation_result_free(result);
    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}

#[test]
fn policy_builder_cwt_claim_string_helpers_compile() {
    let mut builder: *mut cose_validator_builder_t = std::ptr::null_mut();
    let status = cose_validator_builder_new(&mut builder);
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut policy: *mut cose_trust_policy_builder_t = std::ptr::null_mut();
    let status = cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy);
    assert_eq!(status, cose_status_t::COSE_OK);

    // These should compile as they only depend on message facts.
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claims_present(policy),
        cose_status_t::COSE_OK
    );

    let iss = CString::new("issuer.example").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_iss_eq(policy, iss.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Generic claim helpers: presence + simple equality.
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_present(policy, 6),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_eq(policy, 6, 123),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_bool_eq(policy, 6, true),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_ge(policy, 6, 123),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_le(policy, 6, 123),
        cose_status_t::COSE_OK
    );

    let key = CString::new("nonce").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_present(policy, key.as_ptr()),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_bool_eq(policy, key.as_ptr(), true),
        cose_status_t::COSE_OK
    );

    let value = CString::new("abc").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_eq(policy, key.as_ptr(), value.as_ptr()),
        cose_status_t::COSE_OK
    );

    let prefix = CString::new("a").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy,
            key.as_ptr(),
            prefix.as_ptr()
        ),
        cose_status_t::COSE_OK
    );

    let needle = CString::new("b").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_contains(policy, key.as_ptr(), needle.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Label-string helpers (compile-only here).
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(policy, 1000, prefix.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_str_contains(policy, 1000, needle.as_ptr()),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_i64_ge(policy, key.as_ptr(), 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_i64_le(policy, key.as_ptr(), 0),
        cose_status_t::COSE_OK
    );

    // Fixed helpers for standard time claims.
    assert_eq!(cose_trust_policy_builder_require_cwt_exp_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_exp_le(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_le(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_le(policy, 0), cose_status_t::COSE_OK);

    // Optional helper: does not require optional packs.
    assert_eq!(
        cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(policy),
        cose_status_t::COSE_OK
    );

    let mut plan: *mut cose_compiled_trust_plan_t = std::ptr::null_mut();
    let status = cose_trust_policy_builder_compile(policy, &mut plan);
    assert_eq!(status, cose_status_t::COSE_OK, "{:?}", last_error_string());
    assert!(!plan.is_null());

    cose_trust_policy_builder_free(policy);
    cose_compiled_trust_plan_free(plan);
    cose_validator_builder_free(builder);
}
