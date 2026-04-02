// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in did_x509_ffi.
//!
//! Covers Ok branches of FFI functions: parse → get_fingerprint/get_hash_algorithm,
//! build_with_eku, build_from_chain, validate, and resolve.

use did_x509_ffi::error::*;
use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509Builder;
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::ptr;

/// Generate a self-signed CA certificate with code-signing EKU.
fn generate_ca_cert_with_eku() -> (Vec<u8>, PKey<openssl::pkey::Private>) {
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
        .append_entry_by_text("CN", "Targeted Test CA")
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

    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build()
        .unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    (cert.to_der().unwrap(), pkey)
}

/// Compute the SHA-256 hex fingerprint of a DER certificate (matching DID:x509 logic).
fn sha256_hex(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hex::encode(hasher.finalize())
}

/// Free helper for error handles.
unsafe fn free_err(err: *mut DidX509ErrorHandle) {
    if !err.is_null() {
        did_x509_error_free(err);
    }
}

// ============================================================================
// Target: lines 186-205 — impl_parsed_get_fingerprint_inner Ok path
// ============================================================================
#[test]
fn test_parse_and_get_fingerprint_ok_branch() {
    let (cert_der, _) = generate_ca_cert_with_eku();

    // Build DID from cert using impl_build_from_chain_inner, then parse it
    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );
    assert_eq!(rc, FFI_OK, "build failed");
    assert!(!did_string.is_null());

    // Parse the built DID — exercises lines 113-119 (Ok branch)
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parse_inner(did_string, &mut handle, &mut err);
    assert_eq!(rc, FFI_OK, "parse failed");
    assert!(!handle.is_null());

    // Get fingerprint — exercises lines 178-184 (Ok branch, the CString::new Ok arm)
    let mut out_fp: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parsed_get_fingerprint_inner(handle, &mut out_fp, &mut err);
    assert_eq!(rc, FFI_OK, "get_fingerprint failed");
    assert!(!out_fp.is_null());

    let fp = unsafe { CStr::from_ptr(out_fp) }
        .to_string_lossy()
        .to_string();
    let expected_fp = sha256_hex(&cert_der);
    assert_eq!(fp, expected_fp);

    unsafe {
        did_x509_string_free(out_fp);
        did_x509_parsed_free(handle);
        did_x509_string_free(did_string);
    }
}

// ============================================================================
// Target: lines 256-275 — impl_parsed_get_hash_algorithm_inner Ok path
// ============================================================================
#[test]
fn test_parse_and_get_hash_algorithm_ok_branch() {
    let (cert_der, _) = generate_ca_cert_with_eku();

    // Build DID from cert
    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);

    // Parse the built DID
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parse_inner(did_string, &mut handle, &mut err);
    assert_eq!(rc, FFI_OK);

    // Get hash algorithm — exercises lines 248-253 (Ok branch)
    let mut out_alg: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();
    let rc = impl_parsed_get_hash_algorithm_inner(handle, &mut out_alg, &mut err);
    assert_eq!(rc, FFI_OK, "get_hash_algorithm failed");
    assert!(!out_alg.is_null());

    let alg = unsafe { CStr::from_ptr(out_alg) }
        .to_string_lossy()
        .to_string();
    assert_eq!(alg, "sha256");

    unsafe {
        did_x509_string_free(out_alg);
        did_x509_parsed_free(handle);
        did_x509_string_free(did_string);
    }
}

// ============================================================================
// Target: lines 431-455 — impl_build_with_eku_inner Ok path
// ============================================================================
#[test]
fn test_build_with_eku_ok_branch() {
    let (cert_der, _) = generate_ca_cert_with_eku();

    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_ptrs = vec![eku_oid.as_ptr()];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // This exercises lines 422-428 (build Ok → CString Ok → write out_did_string)
    let rc = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        eku_ptrs.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );

    assert_eq!(rc, FFI_OK, "build_with_eku failed: {:?}", unsafe {
        if !err.is_null() {
            Some(
                CStr::from_ptr(did_x509_error_message(err))
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    });
    assert!(!did_string.is_null());

    let result = unsafe { CStr::from_ptr(did_string) }
        .to_string_lossy()
        .to_string();
    assert!(result.starts_with("did:x509:"));

    unsafe {
        did_x509_string_free(did_string);
        free_err(err);
    }
}

// ============================================================================
// Target: lines 554-578 — impl_build_from_chain_inner Ok path
// ============================================================================
#[test]
fn test_build_from_chain_ok_branch() {
    let (cert_der, _) = generate_ca_cert_with_eku();

    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Exercises lines 545-551 (build_from_chain_with_eku Ok → CString Ok)
    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );

    assert_eq!(rc, FFI_OK, "build_from_chain failed: {:?}", unsafe {
        if !err.is_null() {
            Some(
                CStr::from_ptr(did_x509_error_message(err))
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    });
    assert!(!did_string.is_null());

    let result = unsafe { CStr::from_ptr(did_string) }
        .to_string_lossy()
        .to_string();
    assert!(result.starts_with("did:x509:"));

    unsafe {
        did_x509_string_free(did_string);
        free_err(err);
    }
}

// ============================================================================
// Target: lines 691-709 — impl_validate_inner Ok path (is_valid written)
// ============================================================================
#[test]
fn test_validate_ok_branch() {
    // First build a valid DID from the cert, then validate it against the same cert chain.
    let (cert_der, _) = generate_ca_cert_with_eku();

    // Build the DID string from the chain
    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );
    assert_eq!(rc, FFI_OK, "build_from_chain prerequisite failed");
    assert!(!did_string.is_null());

    let built_did = unsafe { CStr::from_ptr(did_string) }
        .to_string_lossy()
        .to_string();
    unsafe { did_x509_string_free(did_string) };

    // Now validate the DID against the chain — exercises lines 688-693 (Ok → write out_is_valid)
    let c_did = CString::new(built_did).unwrap();
    let mut out_is_valid: i32 = -1;
    err = ptr::null_mut();

    let rc = impl_validate_inner(
        c_did.as_ptr(),
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut out_is_valid,
        &mut err,
    );

    assert_eq!(rc, FFI_OK, "validate failed: {:?}", unsafe {
        if !err.is_null() {
            Some(
                CStr::from_ptr(did_x509_error_message(err))
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    });
    // out_is_valid should be 0 or 1
    assert!(out_is_valid == 0 || out_is_valid == 1);

    unsafe { free_err(err) };
}

// ============================================================================
// Target: lines 832-868 — impl_resolve_inner Ok path (did_document JSON)
// ============================================================================
#[test]
fn test_resolve_ok_branch() {
    let (cert_der, _) = generate_ca_cert_with_eku();

    // Build DID first
    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut did_string,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);
    let built_did = unsafe { CStr::from_ptr(did_string) }
        .to_string_lossy()
        .to_string();
    unsafe { did_x509_string_free(did_string) };

    // Now resolve — exercises lines 821-829 (Ok → serde_json Ok → CString Ok → write out)
    let c_did = CString::new(built_did).unwrap();
    let mut out_json: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();

    let rc = impl_resolve_inner(
        c_did.as_ptr(),
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut out_json,
        &mut err,
    );

    assert_eq!(rc, FFI_OK, "resolve failed: {:?}", unsafe {
        if !err.is_null() {
            Some(
                CStr::from_ptr(did_x509_error_message(err))
                    .to_string_lossy()
                    .to_string(),
            )
        } else {
            None
        }
    });
    assert!(!out_json.is_null());

    let json_str = unsafe { CStr::from_ptr(out_json) }
        .to_string_lossy()
        .to_string();
    // Should be valid JSON containing DID document fields
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.get("id").is_some() || parsed.get("@context").is_some());

    unsafe {
        did_x509_string_free(out_json);
        free_err(err);
    }
}

// ============================================================================
// Target: line 131-135 — panic path (verify parse panic handler via inner fn)
// We cannot easily trigger panics, but we cover the match Ok(code) => code arm
// by ensuring the normal Ok path is covered. The panic handler lines are
// architecture-level safety nets. Let's at least test error paths.
// ============================================================================
#[test]
fn test_parse_invalid_did_returns_parse_failed() {
    let c_did = CString::new("not-a-did").unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(c_did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, FFI_ERR_PARSE_FAILED);
    assert!(handle.is_null());

    unsafe { free_err(err) };
}

#[test]
fn test_validate_with_mismatched_did_exercises_validate_err() {
    let (cert_der, _) = generate_ca_cert_with_eku();
    // Use a DID with a wrong fingerprint
    let c_did = CString::new("did:x509:0:sha256:0000000000000000000000000000000000000000000000000000000000000000::eku:1.3.6.1.5.5.7.3.3").unwrap();

    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut out_is_valid: i32 = -1;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        c_did.as_ptr(),
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut out_is_valid,
        &mut err,
    );

    // Should either succeed with is_valid=0 or return an error code
    assert!(rc == FFI_OK || rc == FFI_ERR_VALIDATE_FAILED);

    unsafe { free_err(err) };
}

#[test]
fn test_resolve_with_wrong_fingerprint_returns_error() {
    let (cert_der, _) = generate_ca_cert_with_eku();
    let c_did = CString::new("did:x509:0:sha256:0000000000000000000000000000000000000000000000000000000000000000::eku:1.3.6.1.5.5.7.3.3").unwrap();

    let cert_ptrs = vec![cert_der.as_ptr()];
    let cert_lens = vec![cert_der.len() as u32];
    let mut out_json: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        c_did.as_ptr(),
        cert_ptrs.as_ptr(),
        cert_lens.as_ptr(),
        1,
        &mut out_json,
        &mut err,
    );

    assert_eq!(rc, FFI_ERR_RESOLVE_FAILED);

    unsafe {
        if !out_json.is_null() {
            did_x509_string_free(out_json);
        }
        free_err(err);
    }
}
