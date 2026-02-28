// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal FFI tests for certificates crate that focus on null safety and basic error handling.
//! These tests avoid OpenSSL dependencies by testing error paths and null pointer handling.

use cose_sign1_certificates_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use std::ptr;

#[test]
fn test_cose_certificates_key_from_cert_der_null_safety() {
    // Test null certificate pointer
    let mut key: *mut cose_sign1_primitives_ffi::types::CoseKeyHandle = ptr::null_mut();
    let result = cose_certificates_key_from_cert_der(ptr::null(), 0, &mut key);
    assert_ne!(result, cose_status_t::COSE_OK); // Should fail
    
    // Test null output pointer
    let test_data = b"test";
    let result = cose_certificates_key_from_cert_der(
        test_data.as_ptr(), 
        test_data.len(), 
        ptr::null_mut()
    );
    assert_ne!(result, cose_status_t::COSE_OK); // Should fail
    
    // Test zero length with valid pointer
    let mut key: *mut cose_sign1_primitives_ffi::types::CoseKeyHandle = ptr::null_mut();
    let result = cose_certificates_key_from_cert_der(
        test_data.as_ptr(), 
        0, 
        &mut key
    );
    assert_ne!(result, cose_status_t::COSE_OK); // Should fail
    
    // Test invalid certificate data (should fail gracefully)
    let invalid_cert = b"definitely not a certificate";
    let mut key: *mut cose_sign1_primitives_ffi::types::CoseKeyHandle = ptr::null_mut();
    let result = cose_certificates_key_from_cert_der(
        invalid_cert.as_ptr(),
        invalid_cert.len(),
        &mut key,
    );
    assert_ne!(result, cose_status_t::COSE_OK); // Should fail
    assert!(key.is_null()); // Output should remain null on failure
}

#[test]
fn test_trust_policy_builder_functions_null_safety() {
    // Test policy builder functions with null policy pointer
    // These should all fail safely without crashing
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_not_trusted(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_built(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_not_built(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_element_count_eq(ptr::null_mut(), 1);
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(ptr::null_mut(), 0);
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_present(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn test_trust_policy_builder_string_functions_null_safety() {
    // Test functions that take string parameters with null pointers
    
    // Null policy builder
    let result = cose_sign1_certificates_trust_policy_builder_require_leaf_subject_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_issuer_subject_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_subject_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn test_trust_policy_builder_time_functions_null_safety() {
    // Test functions that take time parameters with null policy builder
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_valid_at(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_before_le(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_after_le(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn test_trust_policy_builder_chain_element_functions_null_safety() {
    // Test chain element functions with null policy builder
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_subject_eq(
        ptr::null_mut(), 
        0, 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_issuer_eq(
        ptr::null_mut(), 
        0, 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
        ptr::null_mut(), 
        0, 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_thumbprint_present(
        ptr::null_mut(), 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_valid_at(
        ptr::null_mut(), 
        0, 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_not_before_le(
        ptr::null_mut(), 
        0, 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_not_before_ge(
        ptr::null_mut(), 
        0, 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_not_after_le(
        ptr::null_mut(), 
        0, 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_chain_element_not_after_ge(
        ptr::null_mut(), 
        0, 
        0
    );
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn test_trust_policy_builder_pqc_functions_null_safety() {
    // Test PQC-related functions with null policy builder
    
    let result = cose_sign1_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(
        ptr::null_mut()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(
        ptr::null_mut()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(
        ptr::null_mut()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
}

#[test]
fn test_validator_builder_with_certificates_pack_null_safety() {
    // Test the pack builder functions with null pointers
    
    let result = cose_sign1_validator_builder_with_certificates_pack(ptr::null_mut());
    assert_ne!(result, cose_status_t::COSE_OK);
    
    let result = cose_sign1_validator_builder_with_certificates_pack_ex(
        ptr::null_mut(), 
        ptr::null()
    );
    assert_ne!(result, cose_status_t::COSE_OK);
    
    // Test with null options but valid builder (would require actual builder creation)
    // This is tested in the integration test, but we can't do it here without OpenSSL
}