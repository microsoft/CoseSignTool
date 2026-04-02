// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive DID x509 FFI tests for maximum coverage.
//!
//! This test file specifically targets uncovered code paths in the FFI
//! implementation to boost coverage percentage.

use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{extension::*, X509Builder, X509NameBuilder};
use std::ffi::{CStr, CString};
use std::ptr;

/// Helper to get error message from an error handle.
fn error_message(err: *const DidX509ErrorHandle) -> Option<String> {
    if err.is_null() {
        return None;
    }
    let msg = unsafe { did_x509_error_message(err) };
    if msg.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(msg) }.to_string_lossy().to_string();
    Some(s)
}

/// Generate a test certificate for FFI testing.
fn generate_test_certificate() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(key).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Test Certificate").unwrap();
    let name = name.build();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    // Add EKU extension
    let context = builder.x509v3_context(None, None);
    let eku = ExtendedKeyUsage::new().code_signing().build().unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    cert.to_der().unwrap()
}

#[test]
fn test_did_x509_parsed_null_safety_comprehensive() {
    // Test accessor functions with null handles
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Test fingerprint accessor with null handle
    let rc = unsafe { did_x509_parsed_get_fingerprint(ptr::null(), &mut result, &mut err) };
    assert!(rc < 0);
    assert!(result.is_null());

    // Test hash algorithm accessor with null handle
    err = ptr::null_mut();
    let rc = unsafe { did_x509_parsed_get_hash_algorithm(ptr::null(), &mut result, &mut err) };
    assert!(rc < 0);
    assert!(result.is_null());
}

#[test]
fn test_did_x509_build_from_chain_comprehensive_errors() {
    // Test with null chain_certs
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let chain_lens = [100u32];

    let rc = unsafe {
        did_x509_build_from_chain(
            ptr::null(),
            chain_lens.as_ptr(),
            1,
            &mut did_string,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_string.is_null());
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with null chain_cert_lens
    let cert_data = generate_test_certificate();
    let chain_certs = [cert_data.as_ptr()];
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            ptr::null(),
            1,
            &mut did_string,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_string.is_null());
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with zero chain count
    err = ptr::null_mut();
    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            0,
            &mut did_string,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_string.is_null());

    // Test with null individual cert in chain
    let null_cert_ptr: *const u8 = ptr::null();
    let chain_with_null = [null_cert_ptr];
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_from_chain(
            chain_with_null.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut did_string,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_string.is_null());
}

#[test]
fn test_did_x509_build_from_chain_with_invalid_data() {
    // Test with invalid certificate data
    let invalid_cert_data = b"not a certificate";
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let chain_certs = [invalid_cert_data.as_ptr()];
    let chain_lens = [invalid_cert_data.len() as u32];

    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut did_string,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_string.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn test_did_x509_validate_comprehensive_errors() {
    // Test with null DID string
    let cert_data = generate_test_certificate();
    let chain_certs = [cert_data.as_ptr()];
    let chain_lens = [cert_data.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_validate(
            ptr::null(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut is_valid,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with invalid DID string
    let invalid_did = CString::new("not-a-did").unwrap();
    is_valid = 0;
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_validate(
            invalid_did.as_ptr(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut is_valid,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with null chain certs
    let valid_did = CString::new("did:x509:0:sha256:test::eku:1.3.6.1.5.5.7.3.3").unwrap();
    is_valid = 0;
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_validate(
            valid_did.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            &mut is_valid,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };
}

#[test]
fn test_did_x509_resolve_comprehensive_errors() {
    // Test with null DID string
    let cert_data = generate_test_certificate();
    let chain_certs = [cert_data.as_ptr()];
    let chain_lens = [cert_data.len() as u32];
    let mut did_document: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_resolve(
            ptr::null(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut did_document,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_document.is_null());
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with invalid DID string
    let invalid_did = CString::new("invalid-did-format").unwrap();
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_resolve(
            invalid_did.as_ptr(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut did_document,
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(did_document.is_null());
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };

    // Test with null output parameter
    let valid_did = CString::new("did:x509:0:sha256:test").unwrap();
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_resolve(
            valid_did.as_ptr(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            ptr::null_mut(),
            &mut err,
        )
    };
    assert!(rc < 0);
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };
}

#[test]
fn test_did_x509_error_handling_edge_cases() {
    // Test error_free with null
    unsafe { did_x509_error_free(ptr::null_mut()) };

    // Test error_message with null
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null());

    // Test string_free with null
    unsafe { did_x509_string_free(ptr::null_mut()) };

    // Test parsed_free with null
    unsafe { did_x509_parsed_free(ptr::null_mut()) };
}

#[test]
fn test_did_x509_build_with_eku_edge_cases() {
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Test with empty certificate data (zero length)
    let rc = unsafe {
        did_x509_build_with_eku(ptr::null(), 0, ptr::null(), 0, &mut did_string, &mut err)
    };
    assert_eq!(rc, 0); // Should succeed with empty data
    assert!(!did_string.is_null());
    unsafe { did_x509_string_free(did_string) };

    // Test with non-null cert data but zero length
    let dummy_data = [0u8; 1];
    did_string = ptr::null_mut();
    let rc = unsafe {
        did_x509_build_with_eku(
            dummy_data.as_ptr(),
            0,
            ptr::null(),
            0,
            &mut did_string,
            &mut err,
        )
    };
    assert_eq!(rc, 0); // Should succeed
    assert!(!did_string.is_null());
    unsafe { did_x509_string_free(did_string) };

    // Test with null out_did_string
    let rc = unsafe {
        did_x509_build_with_eku(ptr::null(), 0, ptr::null(), 0, ptr::null_mut(), &mut err)
    };
    assert!(rc < 0); // Should fail
    assert!(!err.is_null());
    unsafe { did_x509_error_free(err) };
}
