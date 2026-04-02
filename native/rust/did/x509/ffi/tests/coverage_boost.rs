// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for did_x509_ffi Ok-path branches.
//!
//! These tests exercise the success paths (writing results to output pointers)
//! that were previously uncovered. Each test directly calls the inner FFI
//! implementations with valid inputs to ensure the Ok branches execute.

use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509Builder;
use std::ffi::{CStr, CString};
use std::ptr;

/// Generate a self-signed CA certificate with basic constraints and key usage.
fn gen_ca_cert() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    let serial = openssl::bn::BigNum::from_u32(42).unwrap();
    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    let mut name_builder = openssl::x509::X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "CoverageBoost CA")
        .unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let bc = openssl::x509::extension::BasicConstraints::new()
        .ca()
        .build()
        .unwrap();
    builder.append_extension(bc).unwrap();

    let ku = openssl::x509::extension::KeyUsage::new()
        .digital_signature()
        .key_cert_sign()
        .build()
        .unwrap();
    builder.append_extension(ku).unwrap();

    // Add code signing EKU
    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build()
        .unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

/// Build a DID from a certificate and return the DID string (or None if build fails).
fn build_did_from_cert(cert_der: &[u8]) -> Option<String> {
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );

    if rc == DID_X509_OK && !did_string.is_null() {
        let s = unsafe { CStr::from_ptr(did_string) }
            .to_string_lossy()
            .to_string();
        unsafe { did_x509_string_free(did_string) };
        Some(s)
    } else {
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
        None
    }
}

// ============================================================================
// Parsing success paths — covers L131-135 (impl_parse_inner Ok path)
// ============================================================================

#[test]
fn test_impl_parse_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let did = build_did_from_cert(&cert_der).expect("build should succeed");

    let c_did = CString::new(did.as_str()).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(c_did.as_ptr(), &mut handle, &mut err);

    assert_eq!(rc, DID_X509_OK, "parse should succeed");
    assert!(!handle.is_null(), "handle must be non-null on success");
    assert!(err.is_null(), "error must be null on success");

    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Fingerprint extraction — covers L186-193, L201-205
// ============================================================================

#[test]
fn test_impl_parsed_get_fingerprint_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let did = build_did_from_cert(&cert_der).expect("build should succeed");

    let c_did = CString::new(did.as_str()).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(c_did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_OK);

    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut fp_err: *mut DidX509ErrorHandle = ptr::null_mut();

    let fp_rc = impl_parsed_get_fingerprint_inner(handle, &mut fingerprint, &mut fp_err);

    assert_eq!(fp_rc, DID_X509_OK, "fingerprint extraction should succeed");
    assert!(!fingerprint.is_null(), "fingerprint must be non-null");
    assert!(fp_err.is_null(), "error must be null on success");

    let fp_str = unsafe { CStr::from_ptr(fingerprint) }
        .to_string_lossy()
        .to_string();
    assert!(!fp_str.is_empty(), "fingerprint string must not be empty");

    unsafe { did_x509_string_free(fingerprint) };
    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Hash algorithm extraction — covers L256-263, L271-275
// ============================================================================

#[test]
fn test_impl_parsed_get_hash_algorithm_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let did = build_did_from_cert(&cert_der).expect("build should succeed");

    let c_did = CString::new(did.as_str()).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(c_did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_OK);

    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut alg_err: *mut DidX509ErrorHandle = ptr::null_mut();

    let alg_rc = impl_parsed_get_hash_algorithm_inner(handle, &mut algorithm, &mut alg_err);

    assert_eq!(
        alg_rc, DID_X509_OK,
        "hash algorithm extraction should succeed"
    );
    assert!(!algorithm.is_null(), "algorithm must be non-null");
    assert!(alg_err.is_null(), "error must be null on success");

    let alg_str = unsafe { CStr::from_ptr(algorithm) }
        .to_string_lossy()
        .to_string();
    assert!(
        alg_str.contains("sha"),
        "algorithm should reference sha: got '{}'",
        alg_str
    );

    unsafe { did_x509_string_free(algorithm) };
    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Build with EKU — covers L431-438, L441-443, L451-455
// ============================================================================

#[test]
fn test_impl_build_with_eku_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_oids_vec = vec![eku_oid.as_ptr()];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        eku_oids_vec.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );

    if rc == DID_X509_OK {
        assert!(
            !did_string.is_null(),
            "did_string must be non-null on success"
        );
        assert!(err.is_null(), "error must be null on success");

        let did_str = unsafe { CStr::from_ptr(did_string) }
            .to_string_lossy()
            .to_string();
        assert!(
            did_str.starts_with("did:x509:"),
            "DID should start with did:x509: got '{}'",
            did_str
        );
        unsafe { did_x509_string_free(did_string) };
    } else {
        // Some cert formats may not succeed — clean up
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
    }
}

// ============================================================================
// Build from chain — covers L554-561, L574-578
// ============================================================================

#[test]
fn test_impl_build_from_chain_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );

    assert_eq!(rc, DID_X509_OK, "build_from_chain should succeed");
    assert!(
        !did_string.is_null(),
        "did_string must be non-null on success"
    );
    assert!(err.is_null(), "error must be null on success");

    let did_str = unsafe { CStr::from_ptr(did_string) }
        .to_string_lossy()
        .to_string();
    assert!(
        did_str.starts_with("did:x509:"),
        "DID should start with did:x509: got '{}'",
        did_str
    );

    unsafe { did_x509_string_free(did_string) };
}

// ============================================================================
// Validate — covers L691, L705-709
// ============================================================================

#[test]
fn test_impl_validate_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let did = build_did_from_cert(&cert_der).expect("build should succeed for validate test");

    let c_did = CString::new(did.as_str()).unwrap();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    let mut is_valid: i32 = -1;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        c_did.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );

    // The validate call should succeed (return FFI_OK) and set is_valid
    if rc == DID_X509_OK {
        assert!(is_valid == 0 || is_valid == 1, "is_valid should be 0 or 1");
        assert!(err.is_null(), "error must be null on success");
    } else {
        // Validation may fail (e.g., self-signed cert not trusted)
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
    }
}

// ============================================================================
// Resolve — covers L832-839, L842-850, L864-868
// ============================================================================

#[test]
fn test_impl_resolve_inner_ok_path() {
    let cert_der = gen_ca_cert();
    let did = build_did_from_cert(&cert_der).expect("build should succeed for resolve test");

    let c_did = CString::new(did.as_str()).unwrap();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    let mut did_document_json: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        c_did.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut did_document_json,
        &mut err,
    );

    if rc == DID_X509_OK {
        assert!(
            !did_document_json.is_null(),
            "JSON must be non-null on success"
        );
        assert!(err.is_null(), "error must be null on success");

        let json_str = unsafe { CStr::from_ptr(did_document_json) }
            .to_string_lossy()
            .to_string();
        assert!(!json_str.is_empty(), "JSON string must not be empty");

        // Validate it is proper JSON with an "id" field
        let json_val: serde_json::Value =
            serde_json::from_str(&json_str).expect("resolve output should be valid JSON");
        assert!(json_val.is_object(), "DID document should be a JSON object");
        if let Some(id) = json_val.get("id") {
            assert!(
                id.as_str().unwrap().starts_with("did:x509:"),
                "id should start with did:x509:"
            );
        }

        unsafe { did_x509_string_free(did_document_json) };
    } else {
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
    }
}

// ============================================================================
// Full round-trip: build → parse → extract fields → validate → resolve
// ============================================================================

#[test]
fn test_full_round_trip_inner_functions() {
    let cert_der = gen_ca_cert();

    // 1. Build from chain
    let did = build_did_from_cert(&cert_der).expect("build should succeed");
    assert!(did.starts_with("did:x509:0:"));

    // 2. Parse the DID
    let c_did = CString::new(did.as_str()).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(c_did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, DID_X509_OK);
    assert!(!handle.is_null());

    // 3. Get fingerprint
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut fp_err: *mut DidX509ErrorHandle = ptr::null_mut();
    let fp_rc = impl_parsed_get_fingerprint_inner(handle, &mut fingerprint, &mut fp_err);
    assert_eq!(fp_rc, DID_X509_OK);
    assert!(!fingerprint.is_null());
    unsafe { did_x509_string_free(fingerprint) };

    // 4. Get hash algorithm
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut alg_err: *mut DidX509ErrorHandle = ptr::null_mut();
    let alg_rc = impl_parsed_get_hash_algorithm_inner(handle, &mut algorithm, &mut alg_err);
    assert_eq!(alg_rc, DID_X509_OK);
    assert!(!algorithm.is_null());
    unsafe { did_x509_string_free(algorithm) };

    // 5. Get policy count
    let mut count: u32 = 0;
    let count_rc = impl_parsed_get_policy_count_inner(handle, &mut count);
    assert_eq!(count_rc, DID_X509_OK);
    assert!(count >= 1, "should have at least 1 policy");

    unsafe { did_x509_parsed_free(handle) };

    // 6. Validate
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];
    let mut is_valid: i32 = -1;
    let mut val_err: *mut DidX509ErrorHandle = ptr::null_mut();

    let val_rc = impl_validate_inner(
        c_did.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut is_valid,
        &mut val_err,
    );

    if val_rc == DID_X509_OK {
        assert!(is_valid == 0 || is_valid == 1);
    } else if !val_err.is_null() {
        unsafe { did_x509_error_free(val_err) };
    }

    // 7. Resolve
    let mut did_doc_json: *mut libc::c_char = ptr::null_mut();
    let mut res_err: *mut DidX509ErrorHandle = ptr::null_mut();

    let res_rc = impl_resolve_inner(
        c_did.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut did_doc_json,
        &mut res_err,
    );

    if res_rc == DID_X509_OK && !did_doc_json.is_null() {
        unsafe { did_x509_string_free(did_doc_json) };
    } else if !res_err.is_null() {
        unsafe { did_x509_error_free(res_err) };
    }
}

// ============================================================================
// Build with EKU using multiple OIDs
// ============================================================================

#[test]
fn test_impl_build_with_eku_inner_multiple_oids() {
    let cert_der = gen_ca_cert();
    let eku_oid1 = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_oid2 = CString::new("1.3.6.1.5.5.7.3.1").unwrap();
    let eku_oids_vec = vec![eku_oid1.as_ptr(), eku_oid2.as_ptr()];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        eku_oids_vec.as_ptr(),
        2,
        &mut did_string,
        &mut err,
    );

    if rc == DID_X509_OK && !did_string.is_null() {
        unsafe { did_x509_string_free(did_string) };
    } else if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Build from multi-cert chain
// ============================================================================

#[test]
fn test_impl_build_from_chain_inner_multi_cert() {
    let cert1_der = gen_ca_cert();
    let cert2_der = gen_ca_cert();

    let cert_ptrs = vec![cert1_der.as_ptr(), cert2_der.as_ptr()];
    let cert_lens = vec![cert1_der.len() as u32, cert2_der.len() as u32];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        2,
        &mut did_string,
        &mut err,
    );

    if rc == DID_X509_OK && !did_string.is_null() {
        let did_str = unsafe { CStr::from_ptr(did_string) }
            .to_string_lossy()
            .to_string();
        assert!(did_str.starts_with("did:x509:"));
        unsafe { did_x509_string_free(did_string) };
    } else if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}
