// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI tests for validation: error handling, trust policy builder,
//! result inspection, and detached payload paths.

use cose_sign1_validation_ffi::*;
use std::ffi::CStr;
use std::ptr;

// ========== set_last_error / take_last_error / cose_last_error_message_utf8 ==========

#[test]
fn last_error_set_and_retrieve() {
    set_last_error("test error message");
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
    assert_eq!(msg, "test error message");
    unsafe { cose_string_free(msg_ptr) };
}

#[test]
fn last_error_clear_returns_null() {
    clear_last_error();
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(msg_ptr.is_null());
}

#[test]
fn last_error_overwrite() {
    set_last_error("first");
    set_last_error("second");
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
    assert_eq!(msg, "second");
    unsafe { cose_string_free(msg_ptr) };
}

#[test]
fn last_error_consumed_after_take() {
    set_last_error("consume me");
    let _ = unsafe { cose_last_error_message_utf8() }; // consumes
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(msg_ptr.is_null()); // already consumed
}

// ========== with_catch_unwind ==========

#[test]
fn with_catch_unwind_ok_path() {
    let result = with_catch_unwind(|| Ok(cose_status_t::COSE_OK));
    assert_eq!(result, cose_status_t::COSE_OK);
}

#[test]
fn with_catch_unwind_err_path() {
    let result = with_catch_unwind(|| Err(anyhow::anyhow!("test error")));
    assert_eq!(result, cose_status_t::COSE_ERR);
    // Error message should be set
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
    assert!(msg.contains("test error"));
    unsafe { cose_string_free(msg_ptr) };
}

// ========== with_trust_policy_builder_mut ==========

#[test]
fn trust_policy_builder_mut_null_ptr() {
    let result = with_trust_policy_builder_mut(ptr::null_mut(), |b| b);
    assert!(result.is_err());
}

#[test]
fn trust_policy_builder_mut_already_consumed() {
    // Create a builder with no inner builder (already compiled)
    let mut raw = cose_trust_policy_builder_t { builder: None };
    let result = with_trust_policy_builder_mut(&mut raw, |b| b);
    assert!(result.is_err());
}

// ========== ABI version ==========

#[test]
fn abi_version() {
    let ver = unsafe { cose_sign1_validation_abi_version() };
    assert_eq!(ver, 1);
}

// ========== cose_last_error_clear ==========

#[test]
fn cose_clear_error() {
    set_last_error("will be cleared");
    unsafe { cose_last_error_clear() };
    let msg_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(msg_ptr.is_null());
}

// ========== cose_string_free null ==========

#[test]
fn cose_string_free_null() {
    unsafe { cose_string_free(ptr::null_mut()) }; // should not crash
}

// ========== validator_builder_free null ==========

#[test]
fn builder_free_null() {
    unsafe { cose_sign1_validator_builder_free(ptr::null_mut()) };
}

// ========== validator_free null ==========

#[test]
fn validator_free_null() {
    unsafe { cose_sign1_validator_free(ptr::null_mut()) };
}

// ========== result_free null ==========

#[test]
fn result_free_null() {
    unsafe { cose_sign1_validation_result_free(ptr::null_mut()) };
}

// ========== validation_result_is_success ==========

#[test]
fn result_is_success_null_result() {
    let mut out_ok = true;
    let status = unsafe {
        cose_sign1_validation_result_is_success(ptr::null(), &mut out_ok)
    };
    assert_eq!(status, cose_status_t::COSE_ERR);
}

#[test]
fn result_is_success_null_out() {
    // Create a result directly
    let result = Box::into_raw(Box::new(cose_sign1_validation_result_t {
        ok: true,
        failure_message: None,
    }));
    let status = unsafe {
        cose_sign1_validation_result_is_success(result, ptr::null_mut())
    };
    assert_eq!(status, cose_status_t::COSE_ERR);
    unsafe { cose_sign1_validation_result_free(result) };
}

#[test]
fn result_is_success_true() {
    let result = Box::into_raw(Box::new(cose_sign1_validation_result_t {
        ok: true,
        failure_message: None,
    }));
    let mut out_ok = false;
    let status = unsafe {
        cose_sign1_validation_result_is_success(result, &mut out_ok)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(out_ok);
    unsafe { cose_sign1_validation_result_free(result) };
}

#[test]
fn result_is_success_false() {
    let result = Box::into_raw(Box::new(cose_sign1_validation_result_t {
        ok: false,
        failure_message: Some("validation failed".to_string()),
    }));
    let mut out_ok = true;
    let status = unsafe {
        cose_sign1_validation_result_is_success(result, &mut out_ok)
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!out_ok);
    unsafe { cose_sign1_validation_result_free(result) };
}

// ========== failure_message_utf8 ==========

#[test]
fn failure_message_null_result() {
    let msg = unsafe { cose_sign1_validation_result_failure_message_utf8(ptr::null()) };
    assert!(msg.is_null());
    // Should have set an error
    let err_ptr = unsafe { cose_last_error_message_utf8() };
    assert!(!err_ptr.is_null());
    unsafe { cose_string_free(err_ptr) };
}

#[test]
fn failure_message_on_success_result() {
    let result = Box::into_raw(Box::new(cose_sign1_validation_result_t {
        ok: true,
        failure_message: None,
    }));
    let msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
    assert!(msg.is_null()); // success has no failure message
    unsafe { cose_sign1_validation_result_free(result) };
}

#[test]
fn failure_message_on_failure_result() {
    let result = Box::into_raw(Box::new(cose_sign1_validation_result_t {
        ok: false,
        failure_message: Some("signature mismatch".to_string()),
    }));
    let msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
    assert!(!msg.is_null());
    let s = unsafe { CStr::from_ptr(msg) }.to_str().unwrap();
    assert_eq!(s, "signature mismatch");
    unsafe { cose_string_free(msg) };
    unsafe { cose_sign1_validation_result_free(result) };
}

// ========== validate_bytes null paths ==========

#[test]
fn validate_bytes_null_out_result() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };
    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let cose = vec![0xD2, 0x84, 0x40, 0xA0, 0x40, 0x40];
    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            cose.as_ptr(),
            cose.len(),
            ptr::null(),
            0,
            ptr::null_mut(), // null out_result
        )
    };
    assert_eq!(status, cose_status_t::COSE_ERR);
    unsafe { cose_sign1_validator_free(validator) };
}

#[test]
fn validate_bytes_null_cose_bytes() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };
    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            ptr::null(), // null cose bytes
            0,
            ptr::null(),
            0,
            &mut result,
        )
    };
    assert_eq!(status, cose_status_t::COSE_INVALID_ARG);
    unsafe { cose_sign1_validator_free(validator) };
}

// ========== validate_bytes with detached payload ==========

#[test]
fn validate_bytes_with_detached_payload() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_new(&mut builder) };
    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };

    // Minimal COSE_Sign1: Tag(18), [bstr(prot), map(unprot), bstr(payload), bstr(sig)]
    let cose = vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74,
        0x44, 0x73, 0x69, 0x67, 0x21,
    ];
    let payload = b"detached-content";
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();

    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            cose.as_ptr(),
            cose.len(),
            payload.as_ptr(),
            payload.len(),
            &mut result,
        )
    };

    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());

    // With no packs, validation should fail (no key resolver)
    let mut is_success = false;
    unsafe { cose_sign1_validation_result_is_success(result, &mut is_success) };
    // Whether success or failure, we exercise the path
    if !is_success {
        let msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
        if !msg.is_null() {
            unsafe { cose_string_free(msg) };
        }
    }

    unsafe {
        cose_sign1_validation_result_free(result);
        cose_sign1_validator_free(validator);
    };
}

// ========== builder lifecycle: build then use ==========

#[test]
fn builder_build_and_validate() {
    let mut builder: *mut cose_sign1_validator_builder_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_new(&mut builder) };
    assert_eq!(status, cose_status_t::COSE_OK);

    let mut validator: *mut cose_sign1_validator_t = ptr::null_mut();
    let status = unsafe { cose_sign1_validator_builder_build(builder, &mut validator) };
    assert_eq!(status, cose_status_t::COSE_OK);

    // Validate with minimal COSE_Sign1
    let cose = vec![
        0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44, 0x74, 0x65, 0x73, 0x74,
        0x44, 0x73, 0x69, 0x67, 0x21,
    ];
    let mut result: *mut cose_sign1_validation_result_t = ptr::null_mut();
    let status = unsafe {
        cose_sign1_validator_validate_bytes(
            validator,
            cose.as_ptr(),
            cose.len(),
            ptr::null(),
            0,
            &mut result,
        )
    };
    assert_eq!(status, cose_status_t::COSE_OK);
    assert!(!result.is_null());

    // Inspect result
    let mut ok = false;
    unsafe { cose_sign1_validation_result_is_success(result, &mut ok) };
    if !ok {
        let msg = unsafe { cose_sign1_validation_result_failure_message_utf8(result) };
        if !msg.is_null() {
            unsafe { cose_string_free(msg) };
        }
    }

    unsafe {
        cose_sign1_validation_result_free(result);
        cose_sign1_validator_free(validator);
    };
}
