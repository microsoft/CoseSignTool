// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for inner implementation functions in did_x509_ffi to improve coverage.
//!
//! These tests call the inner (non-extern-C) functions directly to ensure
//! coverage attribution for catch_unwind and error path logic.

use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{extension::*, X509Builder, X509NameBuilder};
use std::ffi::CString;
use std::ptr;

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
    let eku = ExtendedKeyUsage::new().code_signing().build().unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    cert.to_der().unwrap()
}

// Valid SHA-256 fingerprint: 32 bytes = 43 base64url chars (no padding)
const FP256: &str = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tk";

// ============================================================================
// Parse inner function tests
// ============================================================================

#[test]
fn inner_parse_valid_did() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, 0);
    assert!(!handle.is_null());
    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn inner_parse_null_out_handle() {
    let did = CString::new("did:x509:0:sha256:abc123").unwrap();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), ptr::null_mut(), &mut err);
    assert!(rc < 0);
}

#[test]
fn inner_parse_null_did_string() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(ptr::null(), &mut handle, &mut err);
    assert!(rc < 0);
    assert!(handle.is_null());
}

#[test]
fn inner_parse_invalid_did_format() {
    let did = CString::new("invalid-format").unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert!(rc < 0);
    assert!(handle.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Fingerprint inner function tests
// ============================================================================

#[test]
fn inner_fingerprint_null_out() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);

    err = ptr::null_mut();
    let rc = impl_parsed_get_fingerprint_inner(handle, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn inner_fingerprint_null_handle() {
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parsed_get_fingerprint_inner(ptr::null(), &mut out, &mut err);
    assert!(rc < 0);
    assert!(out.is_null());
}

#[test]
fn inner_fingerprint_success() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(err, ptr::null_mut());
    assert!(!handle.is_null());

    let mut out: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parsed_get_fingerprint_inner(handle, &mut out, &mut err);
    assert_eq!(rc, 0);
    assert!(!out.is_null());

    unsafe { did_x509_string_free(out) };
    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Hash algorithm inner function tests
// ============================================================================

#[test]
fn inner_hash_algorithm_null_out() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);

    err = ptr::null_mut();
    let rc = impl_parsed_get_hash_algorithm_inner(handle, ptr::null_mut(), &mut err);
    assert!(rc < 0);

    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn inner_hash_algorithm_null_handle() {
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parsed_get_hash_algorithm_inner(ptr::null(), &mut out, &mut err);
    assert!(rc < 0);
    assert!(out.is_null());
}

#[test]
fn inner_hash_algorithm_success() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert!(!handle.is_null());

    let mut out: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parsed_get_hash_algorithm_inner(handle, &mut out, &mut err);
    assert_eq!(rc, 0);
    assert!(!out.is_null());

    unsafe { did_x509_string_free(out) };
    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Policy count inner function tests
// ============================================================================

#[test]
fn inner_policy_count_null_out() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);

    let rc = impl_parsed_get_policy_count_inner(handle, ptr::null_mut());
    assert!(rc < 0);

    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn inner_policy_count_null_handle() {
    let mut count: u32 = 999;
    let rc = impl_parsed_get_policy_count_inner(ptr::null(), &mut count);
    assert!(rc < 0);
}

#[test]
fn inner_policy_count_success() {
    let did_str = format!("did:x509:0:sha256:{}::eku:1.3.6.1.5.5.7.3.3", FP256);
    let did = CString::new(did_str).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert!(!handle.is_null());

    let mut count: u32 = 0;
    let rc = impl_parsed_get_policy_count_inner(handle, &mut count);
    assert_eq!(rc, 0);
    assert!(count > 0); // Has at least one policy (EKU)

    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Build with EKU inner function tests
// ============================================================================

#[test]
fn inner_build_with_eku_null_out() {
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_with_eku_inner(ptr::null(), 0, ptr::null(), 0, ptr::null_mut(), &mut err);
    assert!(rc < 0);
}

#[test]
fn inner_build_with_eku_null_cert_nonzero_len() {
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_with_eku_inner(
        ptr::null(),
        100, // nonzero length but null pointer
        ptr::null(),
        0,
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    assert!(out.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_with_eku_null_eku_nonzero_count() {
    let cert = generate_test_certificate();
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_with_eku_inner(
        cert.as_ptr(),
        cert.len() as u32,
        ptr::null(), // null eku_oids
        3,           // nonzero count
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    assert!(out.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_with_eku_empty_inputs() {
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_with_eku_inner(ptr::null(), 0, ptr::null(), 0, &mut out, &mut err);
    // Should succeed with empty inputs
    assert_eq!(rc, 0);
    assert!(!out.is_null());
    unsafe { did_x509_string_free(out) };
}

#[test]
fn inner_build_with_eku_with_cert() {
    let cert = generate_test_certificate();
    let eku = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let ekus = [eku.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert.as_ptr(),
        cert.len() as u32,
        ekus.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, 0);
    assert!(!out.is_null());
    unsafe { did_x509_string_free(out) };
}

#[test]
fn inner_build_with_eku_null_eku_in_array() {
    let cert = generate_test_certificate();
    let eku_null: *const libc::c_char = ptr::null();
    let ekus = [eku_null];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert.as_ptr(),
        cert.len() as u32,
        ekus.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Build from chain inner function tests
// ============================================================================

#[test]
fn inner_build_from_chain_null_out() {
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_from_chain_inner(ptr::null(), ptr::null(), 0, ptr::null_mut(), &mut err);
    assert!(rc < 0);
}

#[test]
fn inner_build_from_chain_null_certs() {
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let lens = [100u32];
    let rc = impl_build_from_chain_inner(ptr::null(), lens.as_ptr(), 1, &mut out, &mut err);
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_from_chain_null_lens() {
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_from_chain_inner(certs.as_ptr(), ptr::null(), 1, &mut out, &mut err);
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_from_chain_zero_count() {
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_from_chain_inner(certs.as_ptr(), lens.as_ptr(), 0, &mut out, &mut err);
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_from_chain_null_cert_in_array() {
    let null_cert: *const u8 = ptr::null();
    let certs = [null_cert];
    let lens = [100u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_from_chain_inner(certs.as_ptr(), lens.as_ptr(), 1, &mut out, &mut err);
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_build_from_chain_with_valid_cert() {
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_build_from_chain_inner(certs.as_ptr(), lens.as_ptr(), 1, &mut out, &mut err);
    assert_eq!(rc, 0);
    assert!(!out.is_null());
    unsafe { did_x509_string_free(out) };
}

// ============================================================================
// Validate inner function tests
// ============================================================================

#[test]
fn inner_validate_null_is_valid() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_validate_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_validate_null_did() {
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_validate_inner(
        ptr::null(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_validate_null_chain() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_validate_inner(
        did.as_ptr(),
        ptr::null(),
        ptr::null(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_validate_zero_chain_count() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_validate_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        0, // zero count
        &mut is_valid,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Resolve inner function tests
// ============================================================================

#[test]
fn inner_resolve_null_out() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_resolve_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        ptr::null_mut(),
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_resolve_null_did() {
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_resolve_inner(
        ptr::null(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_resolve_null_chain() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_resolve_inner(
        did.as_ptr(),
        ptr::null(),
        ptr::null(),
        1,
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn inner_resolve_zero_chain_count() {
    let did = CString::new("did:x509:0:sha256:abc123::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let cert = generate_test_certificate();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_resolve_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        0, // zero count
        &mut out,
        &mut err,
    );
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn error_inner_construction() {
    use did_x509_ffi::error::ErrorInner;
    let err = ErrorInner::new("test error", -42);
    assert_eq!(err.message, "test error");
    assert_eq!(err.code, -42);
}

#[test]
fn error_inner_null_pointer() {
    use did_x509_ffi::error::ErrorInner;
    let err = ErrorInner::null_pointer("param_name");
    assert!(err.message.contains("param_name"));
    assert!(err.code < 0);
}

#[test]
fn set_error_null_out() {
    use did_x509_ffi::error::{set_error, ErrorInner};
    // Should not crash with null out_error
    set_error(ptr::null_mut(), ErrorInner::new("test", -1));
}

#[test]
fn set_error_valid_out() {
    use did_x509_ffi::error::{set_error, ErrorInner};
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    set_error(&mut err, ErrorInner::new("test message", -42));
    assert!(!err.is_null());

    let code = unsafe { did_x509_error_code(err) };
    assert_eq!(code, -42);

    let msg = unsafe { did_x509_error_message(err) };
    assert!(!msg.is_null());
    unsafe { did_x509_string_free(msg as *mut _) };
    unsafe { did_x509_error_free(err) };
}

#[test]
fn error_code_null_handle() {
    let code = unsafe { did_x509_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn error_message_null_handle() {
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null());
}
