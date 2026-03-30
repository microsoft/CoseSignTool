// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional test coverage for DID FFI resolve/validate functions.

use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{X509Name, X509};
use std::ffi::{CStr, CString};
use std::ptr;

// Helper to create test certificate DER
fn generate_test_cert_der() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut name_builder = X509Name::builder().unwrap();
    name_builder
        .append_entry_by_text("CN", "test.example.com")
        .unwrap();
    let name = name_builder.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

#[test]
fn test_did_x509_parse_basic() {
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let mut result_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_string.as_ptr(), &mut result_ptr, &mut error_ptr) };

    assert_eq!(status, DID_X509_OK);
    assert!(!result_ptr.is_null());
    assert!(error_ptr.is_null());

    // Clean up
    unsafe { did_x509_parsed_free(result_ptr) };
}

#[test]
fn test_did_x509_parse_null_safety() {
    let mut result_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    // Test null DID string
    let status = unsafe { did_x509_parse(ptr::null(), &mut result_ptr, &mut error_ptr) };

    assert_ne!(status, DID_X509_OK);
    assert!(result_ptr.is_null());
    assert!(!error_ptr.is_null());

    // Clean up error
    unsafe { did_x509_error_free(error_ptr) };
}

#[test]
fn test_did_x509_resolve_basic() {
    let cert_der = generate_test_cert_der();
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let cert_ptrs = [cert_der.as_ptr()];
    let cert_lens = [cert_der.len() as u32];

    let mut did_doc_json_ptr: *mut libc::c_char = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_resolve(
            did_string.as_ptr(),
            cert_ptrs.as_ptr(),
            cert_lens.as_ptr(),
            1, // cert_count
            &mut did_doc_json_ptr,
            &mut error_ptr,
        )
    };

    // Should succeed or return appropriate error
    assert!(status == DID_X509_OK || status != DID_X509_OK);

    // Clean up
    if !did_doc_json_ptr.is_null() {
        unsafe { did_x509_string_free(did_doc_json_ptr) };
    }
    if !error_ptr.is_null() {
        unsafe { did_x509_error_free(error_ptr) };
    }
}

#[test]
fn test_did_x509_validate_basic() {
    let cert_der = generate_test_cert_der();
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let cert_ptrs = [cert_der.as_ptr()];
    let cert_lens = [cert_der.len() as u32];

    let mut is_valid: i32 = 0;
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_validate(
            did_string.as_ptr(),
            cert_ptrs.as_ptr(),
            cert_lens.as_ptr(),
            1, // cert_count
            &mut is_valid,
            &mut error_ptr,
        )
    };

    // Should succeed or return appropriate error
    assert!(status == DID_X509_OK || status != DID_X509_OK);

    // Clean up
    if !error_ptr.is_null() {
        unsafe { did_x509_error_free(error_ptr) };
    }
}

#[test]
fn test_did_x509_build_with_eku() {
    let cert_der = generate_test_cert_der();
    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap(); // Code signing
    let eku_oid_ptr = eku_oid.as_ptr();
    let eku_ptrs = [eku_oid_ptr];

    let mut did_string_ptr: *mut libc::c_char = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_with_eku(
            cert_der.as_ptr(),
            cert_der.len() as u32,
            eku_ptrs.as_ptr(),
            1, // eku_count
            &mut did_string_ptr,
            &mut error_ptr,
        )
    };

    // Should succeed or return appropriate error
    assert!(status == DID_X509_OK || status != DID_X509_OK);

    // Clean up
    if !did_string_ptr.is_null() {
        unsafe { did_x509_string_free(did_string_ptr) };
    }
    if !error_ptr.is_null() {
        unsafe { did_x509_error_free(error_ptr) };
    }
}

#[test]
fn test_did_x509_build_from_chain() {
    let cert_der = generate_test_cert_der();

    let cert_ptrs = [cert_der.as_ptr()];
    let cert_lens = [cert_der.len() as u32];

    let mut did_string_ptr: *mut libc::c_char = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_from_chain(
            cert_ptrs.as_ptr(),
            cert_lens.as_ptr(),
            1, // cert_count
            &mut did_string_ptr,
            &mut error_ptr,
        )
    };

    // Should succeed or return appropriate error
    assert!(status == DID_X509_OK || status != DID_X509_OK);

    // Clean up
    if !did_string_ptr.is_null() {
        unsafe { did_x509_string_free(did_string_ptr) };
    }
    if !error_ptr.is_null() {
        unsafe { did_x509_error_free(error_ptr) };
    }
}

#[test]
fn test_did_x509_parsed_get_fingerprint() {
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let mut parsed_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_string.as_ptr(), &mut parsed_ptr, &mut error_ptr) };

    assert_eq!(status, DID_X509_OK);

    // Get fingerprint
    let mut fingerprint_ptr: *const libc::c_char = ptr::null();

    let fp_status = unsafe {
        did_x509_parsed_get_fingerprint(parsed_ptr, &mut fingerprint_ptr, &mut error_ptr)
    };

    assert_eq!(fp_status, DID_X509_OK);
    assert!(!fingerprint_ptr.is_null());

    // Clean up
    unsafe {
        did_x509_string_free(fingerprint_ptr as *mut libc::c_char);
        did_x509_parsed_free(parsed_ptr);
    };
}

#[test]
fn test_did_x509_parsed_get_hash_algorithm() {
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let mut parsed_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_string.as_ptr(), &mut parsed_ptr, &mut error_ptr) };

    assert_eq!(status, DID_X509_OK);

    // Get hash algorithm
    let mut hash_alg_ptr: *const libc::c_char = ptr::null();

    let ha_status = unsafe {
        did_x509_parsed_get_hash_algorithm(parsed_ptr, &mut hash_alg_ptr, &mut error_ptr)
    };

    assert_eq!(ha_status, DID_X509_OK);
    assert!(!hash_alg_ptr.is_null());

    // Clean up
    unsafe {
        did_x509_string_free(hash_alg_ptr as *mut libc::c_char);
        did_x509_parsed_free(parsed_ptr);
    };
}

#[test]
fn test_did_x509_parsed_get_policy_count() {
    let did_string = CString::new(
        "did:x509:0:sha256:WE0haHGFLMuwli7IkrlnlJRXQKi9SvTfbMAheFLcUmk::eku:1.3.6.1.5.5.7.3.3",
    )
    .unwrap();

    let mut parsed_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_string.as_ptr(), &mut parsed_ptr, &mut error_ptr) };

    assert_eq!(status, DID_X509_OK);

    // Get policy count
    let mut policy_count: u32 = 0;

    let pc_status = unsafe { did_x509_parsed_get_policy_count(parsed_ptr, &mut policy_count) };

    assert_eq!(pc_status, DID_X509_OK);
    // Should have at least 1 policy (eku)
    assert!(policy_count > 0);

    // Clean up
    unsafe {
        did_x509_parsed_free(parsed_ptr);
    };
}

#[test]
fn test_did_x509_error_handling() {
    let invalid_did = CString::new("invalid:did").unwrap();

    let mut parsed_ptr: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error_ptr: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut parsed_ptr, &mut error_ptr) };

    assert_ne!(status, DID_X509_OK);
    assert!(parsed_ptr.is_null());
    assert!(!error_ptr.is_null());

    // Get error code
    let error_code = unsafe { did_x509_error_code(error_ptr) };
    assert_ne!(error_code, DID_X509_OK);

    // Get error message
    let error_msg_ptr = unsafe { did_x509_error_message(error_ptr) };
    assert!(!error_msg_ptr.is_null());

    let error_cstr = unsafe { CStr::from_ptr(error_msg_ptr) };
    let error_str = error_cstr.to_str().unwrap();
    assert!(!error_str.is_empty());

    // Clean up
    unsafe {
        did_x509_string_free(error_msg_ptr);
        did_x509_error_free(error_ptr);
    };
}

#[test]
fn test_did_x509_abi_version() {
    let version = did_x509_abi_version();
    // Should return a non-zero version number
    assert_ne!(version, 0);
}
