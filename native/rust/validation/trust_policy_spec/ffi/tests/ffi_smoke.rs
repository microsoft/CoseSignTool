// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end FFI smoke tests.
//!
//! Round-trips translate → diagnostic-introspect → bind → compile → free entirely
//! through the C ABI surface. Catches signature mistakes that the header drift
//! assertion alone cannot.

use cose_sign1_trust_policy_spec_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use std::ptr;

fn translate(json: &str) -> *mut cose_sign1_trust_policy_translation_result_t {
    let mut result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let bytes = json.as_bytes();
    let status = cose_sign1_trust_policy_translate_json(bytes.as_ptr(), bytes.len(), &mut result);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());
    result
}

fn read_diag_code(diag: *const cose_sign1_trust_policy_diagnostic_t) -> String {
    let mut sev: u8 = 99;
    let mut code_ptr: *const u8 = ptr::null();
    let mut code_len: usize = 0;
    cose_sign1_trust_policy_diagnostic_read(
        diag,
        &mut sev,
        &mut code_ptr,
        &mut code_len,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert!(!code_ptr.is_null());
    let bytes = unsafe { std::slice::from_raw_parts(code_ptr, code_len) };
    std::str::from_utf8(bytes).unwrap().to_string()
}

#[test]
fn translate_succeeds_on_minimal_document() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    }"#;
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 1);
    assert_eq!(cose_sign1_trust_policy_result_diagnostic_count(result), 0);

    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn translate_surfaces_parse_error_via_diagnostic() {
    let doc = "{ broken json"; // not valid JSON
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 0);
    assert!(cose_sign1_trust_policy_result_diagnostic_count(result) >= 1);

    let diag = cose_sign1_trust_policy_result_diagnostic_at(result, 0);
    assert!(!diag.is_null());
    let code = read_diag_code(diag);
    assert_eq!(code, "TPX001");

    // Spec accessor returns null for unsuccessful results.
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(spec.is_null());

    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn translate_surfaces_schema_violation_via_diagnostic() {
    let doc = r#"{ "frontend": "wrong/v1" }"#;
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 0);
    let count = cose_sign1_trust_policy_result_diagnostic_count(result);
    assert!(count >= 1);

    // Read every diagnostic so the borrow path is exercised.
    for i in 0..count {
        let diag = cose_sign1_trust_policy_result_diagnostic_at(result, i);
        assert!(!diag.is_null());
        let code = read_diag_code(diag);
        assert!(code.starts_with("TPX1"), "got code: {code}");
    }

    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn diagnostic_at_out_of_bounds_returns_null() {
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let diag = cose_sign1_trust_policy_result_diagnostic_at(result, 999);
    assert!(diag.is_null());
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn null_handling_is_defensive() {
    // Every accessor tolerates a null handle.
    assert_eq!(
        cose_sign1_trust_policy_result_diagnostic_count(ptr::null()),
        0
    );
    assert!(cose_sign1_trust_policy_result_diagnostic_at(ptr::null(), 0).is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(ptr::null()), 0);
    assert!(cose_sign1_trust_policy_result_spec(ptr::null()).is_null());
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(ptr::null()), 0);

    // Read with null handle does nothing (does not deref any out_*).
    cose_sign1_trust_policy_diagnostic_read(
        ptr::null(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );

    // Free of null is a no-op.
    cose_sign1_trust_policy_spec_free(ptr::null_mut());
    cose_sign1_trust_policy_result_free(ptr::null_mut());
    cose_sign1_trust_policy_compiled_plan_free(ptr::null_mut());
}

#[test]
fn null_out_param_is_an_error() {
    let bytes = b"{}";
    let status =
        cose_sign1_trust_policy_translate_json(bytes.as_ptr(), bytes.len(), ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn null_json_with_nonzero_len_is_an_error() {
    let mut result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_translate_json(ptr::null(), 42, &mut result);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(result.is_null());
}

#[test]
fn non_utf8_json_input_is_an_error() {
    // Lone 0xFF is not legal UTF-8.
    let bytes: [u8; 4] = [0xFF, 0x00, 0x7B, 0x7D];
    let mut result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_translate_json(bytes.as_ptr(), bytes.len(), &mut result);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(result.is_null());
}

#[test]
fn bind_returns_new_result_and_substitutes_parameters() {
    // RequireFact with a parameter reference embedded in the predicate value.
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "expected", "default": "abc" } }
        }
    }"#;
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 1);
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    // has_parameters detects the embedded $param.
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(spec), 1);

    let params = br#"{"expected": "abc"}"#;
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_spec_bind(spec, params.as_ptr(), params.len(), &mut bound);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!bound.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(bound), 1);

    // The bound spec no longer contains parameter references.
    let bound_spec = cose_sign1_trust_policy_result_spec(bound);
    assert!(!bound_spec.is_null());
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(bound_spec), 0);

    cose_sign1_trust_policy_spec_free(bound_spec);
    cose_sign1_trust_policy_result_free(bound);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_with_empty_parameter_buffer_uses_defaults() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "x", "default": "fallback" } }
        }
    }"#;
    let result = translate(doc);
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_bind(spec, ptr::null(), 0, &mut bound);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!bound.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(bound), 1);

    cose_sign1_trust_policy_result_free(bound);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_missing_parameter_surfaces_tpx400() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "x" } }
        }
    }"#;
    let result = translate(doc);
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    // No parameters supplied + no default => TPX400.
    let params = b"{}";
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_spec_bind(spec, params.as_ptr(), params.len(), &mut bound);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!bound.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(bound), 0);
    let count = cose_sign1_trust_policy_result_diagnostic_count(bound);
    assert!(count >= 1);
    let diag = cose_sign1_trust_policy_result_diagnostic_at(bound, 0);
    let code = read_diag_code(diag);
    assert_eq!(code, "TPX400");

    cose_sign1_trust_policy_result_free(bound);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_with_non_object_parameters_is_an_error() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    }"#;
    let result = translate(doc);
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    let params = b"[1,2,3]";
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_spec_bind(spec, params.as_ptr(), params.len(), &mut bound);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(bound.is_null());

    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_with_null_spec_is_an_error() {
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_spec_bind(ptr::null(), ptr::null(), 0, &mut bound);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(bound.is_null());
}

#[test]
fn bind_with_null_out_result_is_an_error() {
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let status = cose_sign1_trust_policy_spec_bind(spec, ptr::null(), 0, ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_succeeds_on_structural_spec() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    }"#;
    let result = translate(doc);
    let spec = cose_sign1_trust_policy_result_spec(result);

    let mut plan: *mut cose_sign1_trust_policy_compiled_plan_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile(spec, &mut plan);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!plan.is_null());

    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_with_null_out_plan_is_an_error() {
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let status = cose_sign1_trust_policy_spec_compile(spec, ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_with_null_spec_is_an_error() {
    let mut plan: *mut cose_sign1_trust_policy_compiled_plan_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile(ptr::null(), &mut plan);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(plan.is_null());
}

#[test]
fn compile_to_result_succeeds_and_optionally_returns_plan() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "message": { "allow_all": true }
    }"#;
    let result = translate(doc);
    let spec = cose_sign1_trust_policy_result_spec(result);

    // First pass: out_plan is non-null — receive the plan.
    let mut compile_result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let mut plan: *mut cose_sign1_trust_policy_compiled_plan_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        spec,
        &mut compile_result,
        &mut plan,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compile_result.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(compile_result), 1);
    assert!(!plan.is_null());
    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_result_free(compile_result);

    // Second pass: out_plan is null — compile-validate only.
    let mut compile_result_2: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        spec,
        &mut compile_result_2,
        ptr::null_mut(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compile_result_2.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(compile_result_2), 1);
    cose_sign1_trust_policy_result_free(compile_result_2);

    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
#[test]
fn compile_to_result_null_args() {
    // Null spec — error.
    let mut r1: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        ptr::null(),
        &mut r1,
        ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);

    // Null out_result — error.
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        spec,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn frontend_id_is_canonical_value() {
    let p = cose_sign1_trust_policy_frontend_id();
    assert!(!p.is_null());
    let s = unsafe { std::ffi::CStr::from_ptr(p) };
    assert_eq!(s.to_str().unwrap(), "cose-tp-json/v1");

    // Two calls return the same static pointer (cached).
    let p2 = cose_sign1_trust_policy_frontend_id();
    assert_eq!(p, p2);
}

#[test]
fn diagnostic_read_with_partial_out_pointers() {
    // Trigger a diagnostic.
    let result = translate("not json");
    let diag = cose_sign1_trust_policy_result_diagnostic_at(result, 0);
    assert!(!diag.is_null());

    // Severity-only read.
    let mut sev: u8 = 99;
    cose_sign1_trust_policy_diagnostic_read(
        diag,
        &mut sev,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert_eq!(sev, 0); // Error.

    // Location-only read on a parse error (location should be present).
    let mut line: u32 = 99;
    let mut col: u32 = 99;
    cose_sign1_trust_policy_diagnostic_read(
        diag,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut line,
        &mut col,
    );
    // Parser surfaces a line/col anchor for the syntax error; both should be > 0.
    assert!(line >= 1);
    assert!(col >= 1);

    // Message-only read.
    let mut msg_ptr: *const u8 = ptr::null();
    let mut msg_len: usize = 0;
    cose_sign1_trust_policy_diagnostic_read(
        diag,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut msg_ptr,
        &mut msg_len,
        ptr::null_mut(),
        ptr::null_mut(),
    );
    assert!(!msg_ptr.is_null());
    assert!(msg_len > 0);
    let msg_bytes = unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) };
    let msg = std::str::from_utf8(msg_bytes).unwrap();
    assert!(msg.to_lowercase().contains("malformed") || msg.to_lowercase().contains("json"));

    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_with_null_params_and_nonzero_len_is_an_error() {
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_bind(spec, ptr::null(), 42, &mut bound);
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn bind_with_malformed_json_parameters_is_an_error() {
    let result = translate(r#"{ "frontend": "cose-tp-json/v1", "message": {"allow_all": true} }"#);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let params = b"{ broken json";
    let mut bound: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status =
        cose_sign1_trust_policy_spec_bind(spec, params.as_ptr(), params.len(), &mut bound);
    assert_ne!(status, cose_status_t::COSE_OK);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_to_result_with_unknown_fact_id_carries_diagnostic() {
    // The schema accepts any well-formed fact-id slug. Translation does NOT
    // verify the id against a registry (capability gating is opt-in via
    // TrustPolicyTranslationContext::available_facts, and we use the empty
    // context). So translate succeeds and compile is the place that surfaces
    // the unknown id as TPX200.
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "totally-not-a-real-fact/v1",
            "predicate": { "is_real": false }
        }
    }"#;
    let result = translate(doc);
    assert_eq!(
        cose_sign1_trust_policy_result_is_success(result),
        1,
        "translate must succeed without capability gating; diagnostics={:?}",
        (0..cose_sign1_trust_policy_result_diagnostic_count(result))
            .map(|i| read_diag_code(cose_sign1_trust_policy_result_diagnostic_at(result, i)))
            .collect::<Vec<_>>()
    );
    let spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!spec.is_null());

    let mut compile_result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        spec,
        &mut compile_result,
        ptr::null_mut(),
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!compile_result.is_null());
    assert_eq!(cose_sign1_trust_policy_result_is_success(compile_result), 0);
    let diag = cose_sign1_trust_policy_result_diagnostic_at(compile_result, 0);
    assert!(!diag.is_null());
    let code = read_diag_code(diag);
    assert_eq!(code, "TPX200");

    cose_sign1_trust_policy_result_free(compile_result);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_with_unknown_fact_id_returns_error_status() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "totally-not-a-real-fact/v1",
            "predicate": { "is_real": false }
        }
    }"#;
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 1);
    let spec = cose_sign1_trust_policy_result_spec(result);
    let mut plan: *mut cose_sign1_trust_policy_compiled_plan_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile(spec, &mut plan);
    assert_ne!(status, cose_status_t::COSE_OK);
    assert!(plan.is_null());
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn compile_to_result_error_clears_out_plan() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "totally-not-a-real-fact/v1",
            "predicate": { "is_real": false }
        }
    }"#;
    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 1);
    let spec = cose_sign1_trust_policy_result_spec(result);

    // Pre-populate out_plan with a sentinel so the error path's explicit overwrite is
    // observable.
    let sentinel: *mut cose_sign1_trust_policy_compiled_plan_t = 0xDEADBEEF as *mut _;
    let mut plan = sentinel;
    let mut compile_result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    let status = cose_sign1_trust_policy_spec_compile_to_result(
        spec,
        &mut compile_result,
        &mut plan,
    );
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(cose_sign1_trust_policy_result_is_success(compile_result), 0);
    assert!(plan.is_null(), "compile-error path must reset out_plan to null");

    cose_sign1_trust_policy_result_free(compile_result);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
}

#[test]
fn has_parameters_walks_logical_combinators() {
    // and / or — must be inside a scope per the schema.
    let doc_and = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "all_of": [
                { "fact": "x509-cert-identity/v1",
                  "predicate": { "thumbprint": { "$param": "x", "default": "abc" } } },
                { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } }
            ]
        }
    }"#;
    let r = translate(doc_and);
    assert_eq!(cose_sign1_trust_policy_result_is_success(r), 1);
    let s = cose_sign1_trust_policy_result_spec(r);
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(s), 1);
    cose_sign1_trust_policy_spec_free(s);
    cose_sign1_trust_policy_result_free(r);

    let doc_or = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "any_of": [
                { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } },
                { "fact": "x509-cert-eku/v1",      "predicate": { "is_eku": true } }
            ]
        }
    }"#;
    let r = translate(doc_or);
    assert_eq!(cose_sign1_trust_policy_result_is_success(r), 1);
    let s = cose_sign1_trust_policy_result_spec(r);
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(s), 0);
    cose_sign1_trust_policy_spec_free(s);
    cose_sign1_trust_policy_result_free(r);

    // not — also inside a scope.
    let doc_not = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "not": { "fact": "x509-cert-eku/v1", "predicate": { "is_codesigning": true } },
            "reason": "must not be code-signing"
        }
    }"#;
    let r = translate(doc_not);
    if cose_sign1_trust_policy_result_is_success(r) == 1 {
        let s = cose_sign1_trust_policy_result_spec(r);
        assert_eq!(cose_sign1_trust_policy_spec_has_parameters(s), 0);
        cose_sign1_trust_policy_spec_free(s);
    }
    cose_sign1_trust_policy_result_free(r);
}

#[test]
fn has_parameters_walks_property_assertion_and_path_operator_predicates() {
    // path-operator predicate without a $param is parameter-free.
    let doc_path = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "path": "thumbprint", "operator": "exists" }
        }
    }"#;
    let r = translate(doc_path);
    if cose_sign1_trust_policy_result_is_success(r) == 1 {
        let s = cose_sign1_trust_policy_result_spec(r);
        assert_eq!(cose_sign1_trust_policy_spec_has_parameters(s), 0);
        cose_sign1_trust_policy_spec_free(s);
    }
    cose_sign1_trust_policy_result_free(r);

    // property-assertion predicate without a $param.
    let doc_prop = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": "abc" }
        }
    }"#;
    let r = translate(doc_prop);
    if cose_sign1_trust_policy_result_is_success(r) == 1 {
        let s = cose_sign1_trust_policy_result_spec(r);
        assert_eq!(cose_sign1_trust_policy_spec_has_parameters(s), 0);
        cose_sign1_trust_policy_spec_free(s);
    }
    cose_sign1_trust_policy_result_free(r);
}

#[test]
fn diagnostic_severity_mapping_is_round_trip_stable() {
    use cose_sign1_trust_policy_spec::TrustPolicySeverity;
    use cose_sign1_trust_policy_spec_ffi::cose_sign1_trust_policy_severity_t;

    assert_eq!(
        cose_sign1_trust_policy_severity_t::from_severity(TrustPolicySeverity::Error) as u8,
        cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_ERROR as u8,
    );
    assert_eq!(
        cose_sign1_trust_policy_severity_t::from_severity(TrustPolicySeverity::Warning) as u8,
        cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_WARNING as u8,
    );
    assert_eq!(
        cose_sign1_trust_policy_severity_t::from_severity(TrustPolicySeverity::Info) as u8,
        cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_INFO as u8,
    );

    // Discriminants are ABI-stable.
    assert_eq!(cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_ERROR as u8, 0);
    assert_eq!(cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_WARNING as u8, 1);
    assert_eq!(cose_sign1_trust_policy_severity_t::COSE_TP_SEVERITY_INFO as u8, 2);
}

#[test]
fn end_to_end_translate_bind_compile_lifecycle() {
    let doc = r#"{
        "frontend": "cose-tp-json/v1",
        "primary_signing_key": {
            "fact": "x509-cert-identity/v1",
            "predicate": { "thumbprint": { "$param": "tp", "default": "abc" } }
        }
    }"#;

    let result = translate(doc);
    assert_eq!(cose_sign1_trust_policy_result_is_success(result), 1);

    let unbound_spec = cose_sign1_trust_policy_result_spec(result);
    assert!(!unbound_spec.is_null());
    assert_eq!(cose_sign1_trust_policy_spec_has_parameters(unbound_spec), 1);

    let params = br#"{"tp": "expected-thumbprint"}"#;
    let mut bind_result: *mut cose_sign1_trust_policy_translation_result_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_spec_bind(
            unbound_spec,
            params.as_ptr(),
            params.len(),
            &mut bind_result,
        ),
        cose_status_t::COSE_OK
    );
    assert_eq!(cose_sign1_trust_policy_result_is_success(bind_result), 1);
    let bound_spec = cose_sign1_trust_policy_result_spec(bind_result);
    assert!(!bound_spec.is_null());

    let mut plan: *mut cose_sign1_trust_policy_compiled_plan_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_spec_compile(bound_spec, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());

    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_spec_free(bound_spec);
    cose_sign1_trust_policy_result_free(bind_result);
    cose_sign1_trust_policy_spec_free(unbound_spec);
    cose_sign1_trust_policy_result_free(result);
}
