// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive coverage tests for DID:x509 FFI resolve, validate, and build functions.
//!
//! These tests target uncovered paths in impl_*_inner functions to achieve full coverage.

use did_x509_ffi::*;
use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use rcgen::{CertificateParams, DnType, SanType as RcgenSanType, KeyPair, ExtendedKeyUsagePurpose};
use rcgen::string::Ia5String;
use serde_json::Value;
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
    let s = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .to_string();
    unsafe { did_x509_string_free(msg) };
    Some(s)
}

/// Generate a self-signed X.509 certificate with code signing EKU using rcgen.
fn generate_code_signing_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test Certificate");
    
    // Add Extended Key Usage for Code Signing
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    
    // Add Subject Alternative Name
    params.subject_alt_names = vec![
        RcgenSanType::Rfc822Name(Ia5String::try_from("test@example.com").unwrap()),
    ];
    
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate invalid certificate data (garbage bytes).
fn generate_invalid_cert() -> Vec<u8> {
    vec![0x30, 0x82, 0x00, 0x04, 0xFF, 0xFF, 0xFF, 0xFF] // Invalid DER
}

#[test]
fn test_resolve_inner_happy_path() {
    // Generate a valid certificate and build proper DID
    let cert_der = generate_code_signing_cert();
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy])
        .expect("Should build DID");
    let did_cstring = CString::new(did_string.as_str()).unwrap();
    
    // Prepare certificate chain
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];
    
    let mut result_json: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    
    // Call the resolve function
    let status = unsafe {
        did_x509_resolve(
            did_cstring.as_ptr(),
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut result_json,
            &mut error,
        )
    };
    
    // Verify success
    assert_eq!(status, DID_X509_OK, "Expected success, got error: {:?}", error_message(error));
    assert!(!result_json.is_null());
    
    // Parse the JSON result
    let json_str = unsafe { CStr::from_ptr(result_json) }.to_str().unwrap();
    let doc: Value = serde_json::from_str(json_str).unwrap();
    
    // Verify the DID document structure
    assert_eq!(doc["id"], did_string);
    assert!(doc["verificationMethod"].is_array());
    assert_eq!(doc["verificationMethod"][0]["type"], "JsonWebKey2020");
    
    // Clean up
    unsafe { 
        did_x509_string_free(result_json);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_resolve_inner_invalid_did() {
    // Generate a valid certificate
    let cert_der = generate_code_signing_cert();
    
    // Use an invalid DID string (completely malformed)
    let invalid_did = CString::new("not-a-did-at-all").unwrap();
    
    // Prepare certificate chain
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];
    
    let mut result_json: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    
    // Call the resolve function
    let status = unsafe {
        did_x509_resolve(
            invalid_did.as_ptr(),
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut result_json,
            &mut error,
        )
    };
    
    // Verify failure
    assert_ne!(status, DID_X509_OK);
    assert!(result_json.is_null());
    assert!(!error.is_null());
    
    let err_msg = error_message(error).unwrap();
    assert!(err_msg.contains("must start with 'did:x509'"), "Error: {}", err_msg);
    
    // Clean up
    unsafe { 
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_validate_inner_matching_chain() {
    // Generate a valid certificate and build proper DID
    let cert_der = generate_code_signing_cert();
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy])
        .expect("Should build DID");
    let did_cstring = CString::new(did_string.as_str()).unwrap();
    
    // Prepare certificate chain
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];
    
    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    
    // Call the validate function
    let status = unsafe {
        did_x509_validate(
            did_cstring.as_ptr(),
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut is_valid,
            &mut error,
        )
    };
    
    // Verify success and validity
    assert_eq!(status, DID_X509_OK, "Expected success, got error: {:?}", error_message(error));
    assert_eq!(is_valid, 1, "Certificate should be valid for the DID");
    
    // Clean up
    unsafe { 
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_validate_inner_wrong_chain() {
    // Generate one certificate
    let cert_der1 = generate_code_signing_cert();
    
    // Calculate fingerprint for a different certificate
    let cert_der2 = generate_code_signing_cert();
    let policy = DidX509Policy::Eku(vec!["1.3.6.1.5.5.7.3.3".to_string()]);
    let did_string = DidX509Builder::build_sha256(&cert_der2, &[policy])
        .expect("Should build DID");
    
    // Build DID for cert2 but validate against cert1
    let did_cstring = CString::new(did_string.as_str()).unwrap();
    
    // Prepare certificate chain with cert1 (doesn't match DID fingerprint)
    let cert_ptr = cert_der1.as_ptr();
    let cert_len = cert_der1.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];
    
    let mut is_valid: i32 = -1;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    
    // Call the validate function
    let status = unsafe {
        did_x509_validate(
            did_cstring.as_ptr(),
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut is_valid,
            &mut error,
        )
    };
    
    // Verify the operation should fail because the fingerprint doesn't match
    assert_ne!(status, DID_X509_OK);
    assert_ne!(is_valid, 1, "Certificate should not be valid for the mismatched DID");
    
    let err_msg = error_message(error).unwrap();
    assert!(err_msg.contains("fingerprint"), "Should be a fingerprint mismatch error: {}", err_msg);
    
    // Clean up
    unsafe { 
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_build_from_chain_invalid_cert() {
    // Use invalid certificate data (garbage bytes)
    let invalid_cert = generate_invalid_cert();
    
    // Prepare certificate chain with invalid cert
    let cert_ptr = invalid_cert.as_ptr();
    let cert_len = invalid_cert.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];
    
    let mut result_did: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    
    // Call the build_from_chain function
    let status = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut result_did,
            &mut error,
        )
    };
    
    // Verify failure
    assert_ne!(status, DID_X509_OK);
    assert!(result_did.is_null());
    assert!(!error.is_null());
    
    let err_msg = error_message(error).unwrap();
    assert!(err_msg.contains("parse") || err_msg.contains("build") || err_msg.contains("invalid"), 
            "Error: {}", err_msg);
    
    // Clean up
    unsafe { 
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}
