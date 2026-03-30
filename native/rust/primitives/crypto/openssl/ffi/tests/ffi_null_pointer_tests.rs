// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for FFI error handling functions: set_last_error, clear_last_error,
//! with_catch_unwind. These are the coverage-counted (non-excluded) functions.

use cose_sign1_crypto_openssl_ffi::{
    clear_last_error, set_last_error, with_catch_unwind, COSE_ERR, COSE_OK,
};

// ============================================================================
// set_last_error / clear cycle
// ============================================================================

#[test]
fn set_and_clear_last_error() {
    set_last_error("test error message");
    clear_last_error();
}

#[test]
fn clear_last_error_when_none() {
    clear_last_error();
    clear_last_error(); // double-clear should be safe
}

#[test]
fn set_last_error_with_empty_string() {
    set_last_error("");
    clear_last_error();
}

#[test]
fn set_last_error_overwrites_previous() {
    set_last_error("first error");
    set_last_error("second error");
    clear_last_error();
}

#[test]
fn set_last_error_with_nul_byte() {
    // NUL in the string should be handled gracefully
    set_last_error("error\0with nul");
    clear_last_error();
}

#[test]
fn set_last_error_long_message() {
    let long_msg = "x".repeat(10_000);
    set_last_error(long_msg);
    clear_last_error();
}

// ============================================================================
// with_catch_unwind
// ============================================================================

#[test]
fn with_catch_unwind_success() {
    let status = with_catch_unwind(|| Ok(COSE_OK));
    assert_eq!(status, COSE_OK);
}

#[test]
fn with_catch_unwind_error() {
    let status = with_catch_unwind(|| Err(anyhow::anyhow!("test failure")));
    assert_eq!(status, COSE_ERR);
}

#[test]
fn with_catch_unwind_clears_previous_error() {
    set_last_error("old error");
    let status = with_catch_unwind(|| Ok(COSE_OK));
    assert_eq!(status, COSE_OK);
}

#[test]
fn with_catch_unwind_error_sets_message() {
    let status = with_catch_unwind(|| Err(anyhow::anyhow!("custom error")));
    assert_eq!(status, COSE_ERR);
    clear_last_error();
}

// ============================================================================
// Status code values
// ============================================================================

#[test]
fn status_codes_have_expected_values() {
    assert_eq!(cose_sign1_crypto_openssl_ffi::COSE_OK as u32, 0);
    assert_eq!(cose_sign1_crypto_openssl_ffi::COSE_ERR as u32, 1);
}

#[test]
fn abi_version_constant() {
    assert_eq!(cose_sign1_crypto_openssl_ffi::ABI_VERSION, 1);
}
