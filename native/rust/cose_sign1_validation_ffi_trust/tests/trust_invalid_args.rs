use cose_sign1_validation_ffi::*;
use cose_sign1_validation_ffi_trust::*;
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::ffi::{c_char, CStr, CString};
use std::ptr;
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

struct NoDefaultPlanProducer;

impl TrustFactProducer for NoDefaultPlanProducer {
    fn name(&self) -> &'static str {
        "NoDefaultPlanProducer"
    }

    fn produce(&self, _ctx: &mut TrustFactContext<'_>) -> Result<(), cose_sign1_validation_trust::error::TrustError> {
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        &[]
    }
}

struct NoDefaultPlanPack;

impl CoseSign1TrustPack for NoDefaultPlanPack {
    fn name(&self) -> &'static str {
        "NoDefaultPlanPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(NoDefaultPlanProducer)
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None
    }
}

#[test]
fn trust_plan_builder_errors_cover_nulls_invalid_utf8_and_missing_default_plan() {
    // Null builder.
    let mut plan_builder: *mut cose_trust_plan_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(ptr::null(), &mut plan_builder),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Null out.
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // Create plan builder with a pack that has NO default plan.
    unsafe {
        (*builder).packs.push(Arc::new(NoDefaultPlanPack));
    }
    assert_eq!(
        cose_trust_plan_builder_new_from_validator_builder(builder, &mut plan_builder),
        cose_status_t::COSE_OK
    );

    // pack_count: null out
    assert_eq!(
        cose_trust_plan_builder_pack_count(plan_builder, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // pack_name_utf8: null plan_builder
    let p = cose_trust_plan_builder_pack_name_utf8(ptr::null(), 0);
    assert!(p.is_null());
    assert!(last_error_string().is_some());

    // pack_has_default_plan: out_has_default null
    assert_eq!(
        cose_trust_plan_builder_pack_has_default_plan(plan_builder, 0, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // pack_has_default_plan: index out of range
    let mut has_default = false;
    assert_eq!(
        cose_trust_plan_builder_pack_has_default_plan(plan_builder, 999, &mut has_default),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // add_pack_default_plan_by_name: invalid UTF-8
    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    let bad_ptr = bad_utf8.as_ptr() as *const c_char;
    assert_eq!(
        cose_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, bad_ptr),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // add_pack_default_plan_by_name: no configured pack
    let nope = CString::new("NoSuchPack").unwrap();
    assert_eq!(
        cose_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, nope.as_ptr()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // add_pack_default_plan_by_name: pack exists but has no default plan
    let name = CString::new("NoDefaultPlanPack").unwrap();
    assert_eq!(
        cose_trust_plan_builder_add_pack_default_plan_by_name(plan_builder, name.as_ptr()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // compile_or: out_plan null
    assert_eq!(
        cose_trust_plan_builder_compile_or(plan_builder, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    cose_trust_plan_builder_free(plan_builder);
    cose_validator_builder_free(builder);
}

#[test]
fn trust_policy_builder_errors_cover_invalid_strings_and_double_compile() {
    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);

    // new_from_validator_builder: null out
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // string args: null
    assert_eq!(
        cose_trust_policy_builder_require_content_type_eq(policy, ptr::null()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // string args: invalid UTF-8
    let bad_utf8: [u8; 2] = [0xFF, 0x00];
    let bad_ptr = bad_utf8.as_ptr() as *const c_char;
    assert_eq!(
        cose_trust_policy_builder_require_cwt_iss_eq(policy, bad_ptr),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // compile: null out_plan
    assert_eq!(
        cose_trust_policy_builder_compile(policy, ptr::null_mut()),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    // compile: success, then double-compile error path.
    let mut plan: *mut cose_compiled_trust_plan_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_OK,
        "{:?}",
        last_error_string()
    );
    assert!(!plan.is_null());

    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_ERR
    );
    assert!(last_error_string().is_some());

    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
}
