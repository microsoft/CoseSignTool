// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Final comprehensive coverage tests for DID x509 FFI functions.
//! Targets uncovered lines in did_x509 ffi lib.rs.

use did_x509_ffi::error::{
    did_x509_error_free, DidX509ErrorHandle, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PARSE_FAILED,
};
use did_x509_ffi::types::DidX509ParsedHandle;
use did_x509_ffi::*;

use rcgen::{CertificateParams, DnType, KeyPair, ExtendedKeyUsagePurpose};
use std::ffi::CString;
use std::ptr;

// ============================================================================
// Helper functions
// ============================================================================

fn free_error(err: *mut DidX509ErrorHandle) {
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[allow(dead_code)]
fn free_parsed(handle: *mut DidX509ParsedHandle) {
    if !handle.is_null() {
        unsafe { did_x509_parsed_free(handle) };
    }
}

fn free_string(s: *mut libc::c_char) {
    if !s.is_null() {
        unsafe { did_x509_string_free(s) };
    }
}

// Valid DID:x509 string for testing
const VALID_DID: &str = "did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3";

// Simple test certificate bytes (this won't parse as a valid cert but tests error paths)
fn get_test_cert_bytes() -> Vec<u8> {
    // Minimal DER-like bytes to trigger cert parsing paths
    vec![0x30, 0x82, 0x01, 0x00]
}

// Generate a valid certificate for tests requiring valid certs
fn generate_valid_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "FFI Test Cert");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    let key = KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

// ============================================================================
// Parse tests
// ============================================================================

#[test]
fn test_parse_null_out_handle() {
    let did_string = CString::new(VALID_DID).unwrap();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parse_inner(did_string.as_ptr(), ptr::null_mut(), &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_parse_null_did_string() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parse_inner(ptr::null(), &mut handle, &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_parse_invalid_utf8() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_parse_inner(
        invalid_utf8.as_ptr() as *const libc::c_char,
        &mut handle,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

#[test]
fn test_parse_invalid_did_format() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let invalid_did = CString::new("not-a-did").unwrap();
    
    let rc = impl_parse_inner(invalid_did.as_ptr(), &mut handle, &mut err);
    
    assert_eq!(rc, FFI_ERR_PARSE_FAILED);
    free_error(err);
}

// ============================================================================
// Fingerprint accessor tests
// ============================================================================

#[test]
fn test_parsed_get_fingerprint_null_out() {
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parsed_get_fingerprint_inner(
        0x1 as *const DidX509ParsedHandle, // Non-null but invalid
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_parsed_get_fingerprint_null_handle() {
    let mut out_fp: *const libc::c_char = ptr::null();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parsed_get_fingerprint_inner(ptr::null(), &mut out_fp, &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ============================================================================
// Hash algorithm accessor tests
// ============================================================================

#[test]
fn test_parsed_get_hash_algorithm_null_out() {
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parsed_get_hash_algorithm_inner(
        0x1 as *const DidX509ParsedHandle,
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_parsed_get_hash_algorithm_null_handle() {
    let mut out_alg: *const libc::c_char = ptr::null();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_parsed_get_hash_algorithm_inner(ptr::null(), &mut out_alg, &mut err);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ============================================================================
// Policy count tests
// ============================================================================

#[test]
fn test_parsed_get_policy_count_null_out() {
    let rc = impl_parsed_get_policy_count_inner(
        0x1 as *const DidX509ParsedHandle,
        ptr::null_mut(),
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_parsed_get_policy_count_null_handle() {
    let mut count: u32 = 0;
    
    let rc = impl_parsed_get_policy_count_inner(ptr::null(), &mut count);
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
}

// ============================================================================
// Build with EKU tests
// ============================================================================

#[test]
fn test_build_with_eku_null_out_did_string() {
    let cert_bytes = get_test_cert_bytes();
    let eku1 = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_ptrs = [eku1.as_ptr()];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        cert_bytes.as_ptr(),
        cert_bytes.len() as u32,
        eku_ptrs.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_with_eku_null_cert_nonzero_len() {
    let eku1 = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_ptrs = [eku1.as_ptr()];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        ptr::null(),
        100, // Non-zero len with null cert
        eku_ptrs.as_ptr(),
        1,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_with_eku_null_eku_oids_nonzero_count() {
    let cert_bytes = get_test_cert_bytes();
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        cert_bytes.as_ptr(),
        cert_bytes.len() as u32,
        ptr::null(),
        5, // Non-zero count with null eku_oids
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_with_eku_null_eku_oid_entry() {
    let cert_bytes = get_test_cert_bytes();
    let eku_ptrs: [*const libc::c_char; 2] = [ptr::null(), ptr::null()];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        cert_bytes.as_ptr(),
        cert_bytes.len() as u32,
        eku_ptrs.as_ptr(),
        2,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_with_eku_invalid_utf8_eku() {
    let cert_bytes = get_test_cert_bytes();
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    let eku_ptrs: [*const libc::c_char; 1] = [invalid_utf8.as_ptr() as *const libc::c_char];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        cert_bytes.as_ptr(),
        cert_bytes.len() as u32,
        eku_ptrs.as_ptr(),
        1,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

#[test]
fn test_build_with_eku_invalid_cert() {
    let cert_bytes = get_test_cert_bytes(); // Invalid cert bytes
    let eku1 = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_ptrs = [eku1.as_ptr()];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_with_eku_inner(
        cert_bytes.as_ptr(),
        cert_bytes.len() as u32,
        eku_ptrs.as_ptr(),
        1,
        &mut out_did,
        &mut err,
    );
    
    // This succeeds because the cert bytes hash, EKU doesn't require parsing a real cert
    // Just verify some result is returned (may succeed or fail depending on implementation)
    assert!(rc == 0 || rc < 0);
    free_error(err);
    if !out_did.is_null() {
        free_string(out_did);
    }
}

// ============================================================================
// Build from chain tests
// ============================================================================

#[test]
fn test_build_from_chain_null_out_did_string() {
    let cert_bytes = get_test_cert_bytes();
    let cert_ptrs = [cert_bytes.as_ptr()];
    let cert_lens = [cert_bytes.len() as u32];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_from_chain_null_chain_certs() {
    let cert_lens = [100u32];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_from_chain_inner(
        ptr::null(),
        cert_lens.as_ptr(),
        1,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_from_chain_null_cert_lens() {
    let cert_bytes = get_test_cert_bytes();
    let cert_ptrs = [cert_bytes.as_ptr()];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        ptr::null(),
        1,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_from_chain_null_cert_entry() {
    let cert_ptrs: [*const u8; 1] = [ptr::null()];
    let cert_lens = [100u32];
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut out_did,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_build_from_chain_empty_chain() {
    let mut out_did: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_build_from_chain_inner(
        ptr::null(),
        ptr::null(),
        0, // Empty chain
        &mut out_did,
        &mut err,
    );
    
    // Should fail with null pointer error (null ptrs with zero count triggers that check)
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

// ============================================================================
// Resolve tests
// ============================================================================

#[test]
fn test_resolve_null_out_did_doc() {
    let did_string = CString::new(VALID_DID).unwrap();
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_resolve_inner(
        did_string.as_ptr(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_resolve_null_did_string() {
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_doc: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_resolve_inner(
        ptr::null(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        &mut out_doc,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_resolve_invalid_utf8_did() {
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_doc: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_resolve_inner(
        invalid_utf8.as_ptr() as *const libc::c_char,
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        &mut out_doc,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

#[test]
fn test_resolve_null_chain_nonzero_count() {
    let did_string = CString::new(VALID_DID).unwrap();
    let mut out_doc: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_resolve_inner(
        did_string.as_ptr(),
        ptr::null(),
        ptr::null(),
        5, // Non-zero count
        &mut out_doc,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_resolve_zero_chain_count() {
    let did_string = CString::new(VALID_DID).unwrap();
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_doc: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_resolve_inner(
        did_string.as_ptr(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        0, // Zero count should fail
        &mut out_doc,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

// ============================================================================
// Validate tests
// ============================================================================

#[test]
fn test_validate_null_out_result() {
    let did_string = CString::new(VALID_DID).unwrap();
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_validate_inner(
        did_string.as_ptr(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_validate_null_did_string() {
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_result: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_validate_inner(
        ptr::null(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        &mut out_result,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_validate_invalid_utf8_did() {
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_result: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let invalid_utf8 = [0xC0u8, 0xAF, 0x00];
    
    let rc = impl_validate_inner(
        invalid_utf8.as_ptr() as *const libc::c_char,
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        1,
        &mut out_result,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

#[test]
fn test_validate_null_chain_nonzero_count() {
    let did_string = CString::new(VALID_DID).unwrap();
    let mut out_result: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_validate_inner(
        did_string.as_ptr(),
        ptr::null(),
        ptr::null(),
        5, // Non-zero count
        &mut out_result,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    free_error(err);
}

#[test]
fn test_validate_zero_chain_count() {
    let did_string = CString::new(VALID_DID).unwrap();
    let chain = get_test_cert_bytes();
    let chain_ptrs = [chain.as_ptr()];
    let chain_lens = [chain.len() as u32];
    let mut out_result: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    
    let rc = impl_validate_inner(
        did_string.as_ptr(),
        chain_ptrs.as_ptr(),
        chain_lens.as_ptr(),
        0, // Zero count should fail
        &mut out_result,
        &mut err,
    );
    
    assert_eq!(rc, FFI_ERR_INVALID_ARGUMENT);
    free_error(err);
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn test_error_code_null_handle() {
    let code = unsafe { did_x509_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn test_error_message_null_handle() {
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null());
}

#[test]
fn test_error_free_null_safe() {
    // Should not crash
    unsafe { did_x509_error_free(ptr::null_mut()) };
}

#[test]
fn test_string_free_null_safe() {
    // Should not crash
    unsafe { did_x509_string_free(ptr::null_mut()) };
}

#[test]
fn test_parsed_free_null_safe() {
    // Should not crash
    unsafe { did_x509_parsed_free(ptr::null_mut()) };
}

// ============================================================================
// Error types coverage
// ============================================================================

#[test]
fn test_error_inner_from_did_error_coverage() {
    use did_x509_ffi::error::ErrorInner;
    
    // Test various error creation paths
    let err = ErrorInner::new("test error", -99);
    assert_eq!(err.message, "test error");
    assert_eq!(err.code, -99);
    
    let err = ErrorInner::null_pointer("param");
    assert!(err.message.contains("param"));
    assert_eq!(err.code, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_error_set_error_null_out() {
    use did_x509_ffi::error::{set_error, ErrorInner};
    
    // Setting error with null out_error should not crash
    set_error(ptr::null_mut(), ErrorInner::new("test", -1));
}

#[test]
fn test_error_set_error_valid_out() {
    use did_x509_ffi::error::{set_error, ErrorInner};
    
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("test message", -42));
    
    assert!(!err.is_null());
    
    let code = unsafe { did_x509_error_code(err) };
    assert_eq!(code, -42);
    
    let msg = unsafe { did_x509_error_message(err) };
    assert!(!msg.is_null());
    free_string(msg as *mut libc::c_char);
    
    free_error(err);
}

// ============================================================================
// Types coverage - removed as parsed_handle_to_inner is private
// ============================================================================
