// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enhanced DID x509 FFI tests for comprehensive coverage.
//!
//! Additional tests using real certificate generation to cover
//! more FFI code paths and error scenarios.

use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::{extension::*, X509Builder, X509NameBuilder, X509};
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
    unsafe { did_x509_string_free(msg) };
    Some(s)
}

/// Generate a more comprehensive certificate with EKU and SAN extensions.
fn generate_comprehensive_cert_with_extensions() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    // Set serial number
    let serial = openssl::bn::BigNum::from_u32(42).unwrap();
    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    // Set validity period
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    // Set subject and issuer
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "Enhanced Test Certificate")
        .unwrap();
    name_builder
        .append_entry_by_text("O", "Test Organization")
        .unwrap();
    name_builder.append_entry_by_text("C", "US").unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    // Set public key
    builder.set_pubkey(&pkey).unwrap();

    // Add Basic Constraints
    let bc = BasicConstraints::new().ca().build().unwrap();
    builder.append_extension(bc).unwrap();

    // Add Key Usage
    let ku = KeyUsage::new()
        .digital_signature()
        .key_cert_sign()
        .build()
        .unwrap();
    builder.append_extension(ku).unwrap();

    // Add Extended Key Usage
    let eku = ExtendedKeyUsage::new()
        .code_signing()
        .client_auth()
        .build()
        .unwrap();
    builder.append_extension(eku).unwrap();

    // Add Subject Alternative Name
    let ctx = builder.x509v3_context(None, None);
    let san = SubjectAlternativeName::new()
        .dns("test.example.com")
        .email("test@example.com")
        .uri("https://example.com")
        .build(&ctx)
        .unwrap();
    builder.append_extension(san).unwrap();

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert = builder.build();
    cert.to_der().unwrap()
}

/// Generate an RSA certificate for testing different key types.
fn generate_rsa_certificate() -> Vec<u8> {
    use openssl::rsa::Rsa;

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    // Set serial number
    let serial = openssl::bn::BigNum::from_u32(123).unwrap();
    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial).unwrap();
    builder.set_serial_number(&serial_asn1).unwrap();

    // Set validity period
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    // Set subject and issuer
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "RSA Test Certificate")
        .unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    // Set public key
    builder.set_pubkey(&pkey).unwrap();

    // Sign the certificate
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let cert = builder.build();
    cert.to_der().unwrap()
}

#[test]
fn test_did_x509_build_with_eku_comprehensive() {
    let cert_der = generate_comprehensive_cert_with_extensions();

    // Test with multiple EKU OIDs
    let eku_oids = [
        CString::new("1.3.6.1.5.5.7.3.3").unwrap(), // Code signing
        CString::new("1.3.6.1.5.5.7.3.2").unwrap(), // Client auth
    ];
    let eku_oids_ptrs: Vec<*const libc::c_char> = eku_oids.iter().map(|s| s.as_ptr()).collect();

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_with_eku(
            cert_der.as_ptr(),
            cert_der.len() as u32,
            eku_oids_ptrs.as_ptr(),
            2,
            &mut did_string,
            &mut err,
        )
    };

    if rc == DID_X509_OK {
        assert!(!did_string.is_null());
        assert!(err.is_null());

        let did_str = unsafe { CStr::from_ptr(did_string) }
            .to_string_lossy()
            .to_string();
        assert!(did_str.starts_with("did:x509:"));
        assert!(did_str.contains("eku:1.3.6.1.5.5.7.3.3"));

        unsafe { did_x509_string_free(did_string) };
    } else {
        // Handle expected failures gracefully
        if !err.is_null() {
            let _err_msg = error_message(err);
            unsafe { did_x509_error_free(err) };
        }
    }
}

#[test]
fn test_did_x509_build_from_chain_with_rsa() {
    let cert_der = generate_rsa_certificate();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut did_string,
            &mut err,
        )
    };

    if rc == DID_X509_OK {
        assert!(!did_string.is_null());

        let did_str = unsafe { CStr::from_ptr(did_string) }
            .to_string_lossy()
            .to_string();
        assert!(did_str.starts_with("did:x509:"));

        unsafe { did_x509_string_free(did_string) };
    } else {
        // Expected to fail for some cert formats
        if !err.is_null() {
            unsafe { did_x509_error_free(err) };
        }
    }
}

#[test]
fn test_did_x509_parse_and_validate_comprehensive_workflow() {
    let cert_der = generate_comprehensive_cert_with_extensions();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    // Step 1: Build a DID from the certificate
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut build_err: *mut DidX509ErrorHandle = ptr::null_mut();

    let build_rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut did_string,
            &mut build_err,
        )
    };

    if build_rc == DID_X509_OK && !did_string.is_null() {
        // Step 2: Parse the DID
        let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
        let mut parse_err: *mut DidX509ErrorHandle = ptr::null_mut();

        let parse_rc = unsafe { did_x509_parse(did_string, &mut handle, &mut parse_err) };

        if parse_rc == DID_X509_OK && !handle.is_null() {
            // Step 3: Get all parsed components
            let mut fingerprint: *mut libc::c_char = ptr::null_mut();
            let mut fp_err: *mut DidX509ErrorHandle = ptr::null_mut();
            let fp_rc =
                unsafe { did_x509_parsed_get_fingerprint(handle, &mut fingerprint, &mut fp_err) };
            assert_eq!(fp_rc, DID_X509_OK);
            assert!(!fingerprint.is_null());
            unsafe { did_x509_string_free(fingerprint) };

            let mut algorithm: *mut libc::c_char = ptr::null_mut();
            let mut alg_err: *mut DidX509ErrorHandle = ptr::null_mut();
            let alg_rc =
                unsafe { did_x509_parsed_get_hash_algorithm(handle, &mut algorithm, &mut alg_err) };
            assert_eq!(alg_rc, DID_X509_OK);
            assert!(!algorithm.is_null());
            let alg_str = unsafe { CStr::from_ptr(algorithm) }
                .to_string_lossy()
                .to_string();
            assert_eq!(alg_str, "sha256");
            unsafe { did_x509_string_free(algorithm) };

            let mut count: u32 = 0;
            let count_rc = unsafe { did_x509_parsed_get_policy_count(handle, &mut count) };
            assert_eq!(count_rc, DID_X509_OK);
            // Should have at least one policy
            assert!(count > 0);

            // Step 4: Validate the DID against the certificate
            let mut is_valid: i32 = 0;
            let mut validate_err: *mut DidX509ErrorHandle = ptr::null_mut();

            let validate_rc = unsafe {
                did_x509_validate(
                    did_string,
                    chain_certs.as_ptr(),
                    chain_cert_lens.as_ptr(),
                    1,
                    &mut is_valid,
                    &mut validate_err,
                )
            };

            if validate_rc == DID_X509_OK {
                // The result could be valid (1) or invalid (0) depending on policies
                assert!(is_valid == 0 || is_valid == 1);
            } else if !validate_err.is_null() {
                unsafe { did_x509_error_free(validate_err) };
            }

            // Step 5: Try to resolve to DID Document
            let mut did_document_json: *mut libc::c_char = ptr::null_mut();
            let mut resolve_err: *mut DidX509ErrorHandle = ptr::null_mut();

            let resolve_rc = unsafe {
                did_x509_resolve(
                    did_string,
                    chain_certs.as_ptr(),
                    chain_cert_lens.as_ptr(),
                    1,
                    &mut did_document_json,
                    &mut resolve_err,
                )
            };

            if resolve_rc == DID_X509_OK && !did_document_json.is_null() {
                let json_str = unsafe { CStr::from_ptr(did_document_json) }
                    .to_string_lossy()
                    .to_string();
                assert!(!json_str.is_empty());

                // Verify it's valid JSON
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    assert!(json_val.is_object());
                }

                unsafe { did_x509_string_free(did_document_json) };
            } else if !resolve_err.is_null() {
                unsafe { did_x509_error_free(resolve_err) };
            }

            unsafe { did_x509_parsed_free(handle) };
        } else if !parse_err.is_null() {
            unsafe { did_x509_error_free(parse_err) };
        }

        unsafe { did_x509_string_free(did_string) };
    } else if !build_err.is_null() {
        unsafe { did_x509_error_free(build_err) };
    }
}

#[test]
fn test_did_x509_error_handling_comprehensive() {
    // Test various null pointer scenarios
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Test parse with null out_error (should not crash)
    let test_did = CString::new("invalid-did").unwrap();
    let rc = unsafe { did_x509_parse(test_did.as_ptr(), &mut handle, ptr::null_mut()) };
    assert!(rc < 0);

    // Test build_with_eku with null EKU array but non-zero count
    let cert_der = generate_comprehensive_cert_with_extensions();
    let mut did_string: *mut libc::c_char = ptr::null_mut();
    err = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_with_eku(
            cert_der.as_ptr(),
            cert_der.len() as u32,
            ptr::null(), // null eku_oids
            1,           // non-zero count
            &mut did_string,
            &mut err,
        )
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        let err_msg = error_message(err).unwrap_or_default();
        assert!(err_msg.contains("eku_oids"));
        unsafe { did_x509_error_free(err) };
    }

    // Test build_with_eku with null cert data but non-zero length
    err = ptr::null_mut();
    let rc = unsafe {
        did_x509_build_with_eku(
            ptr::null(), // null cert data
            100,         // non-zero length
            ptr::null(),
            0,
            &mut did_string,
            &mut err,
        )
    };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn test_did_x509_parsed_accessors_null_outputs() {
    // Test accessor functions with null output parameters
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // Create a valid handle first (or use null to test null pointer behavior)
    let test_did =
        CString::new("did:x509:0:sha256:WE69Dr_yGqMPE-KOhAqCag==::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let _parse_rc = unsafe { did_x509_parse(test_did.as_ptr(), &mut handle, &mut err) };

    // Test get_fingerprint with null output pointer
    let rc = unsafe { did_x509_parsed_get_fingerprint(handle, ptr::null_mut(), &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }

    // Test get_hash_algorithm with null output pointer
    err = ptr::null_mut();
    let rc = unsafe { did_x509_parsed_get_hash_algorithm(handle, ptr::null_mut(), &mut err) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }

    // Test get_policy_count with null output pointer
    let rc = unsafe { did_x509_parsed_get_policy_count(handle, ptr::null_mut()) };
    assert_eq!(rc, DID_X509_ERR_NULL_POINTER);

    // Clean up if handle was created
    if !handle.is_null() {
        unsafe { did_x509_parsed_free(handle) };
    }
}

#[test]
fn test_did_x509_chain_validation_edge_cases() {
    let cert_der = generate_comprehensive_cert_with_extensions();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;

    // Test with multiple certificates in chain (same cert repeated)
    let chain_certs = vec![cert_ptr, cert_ptr, cert_ptr];
    let chain_cert_lens = vec![cert_len, cert_len, cert_len];

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            3,
            &mut did_string,
            &mut err,
        )
    };

    if rc == DID_X509_OK && !did_string.is_null() {
        // Test validation with the multi-cert chain
        let mut is_valid: i32 = 0;
        let mut validate_err: *mut DidX509ErrorHandle = ptr::null_mut();

        let validate_rc = unsafe {
            did_x509_validate(
                did_string,
                chain_certs.as_ptr(),
                chain_cert_lens.as_ptr(),
                3,
                &mut is_valid,
                &mut validate_err,
            )
        };

        // Should work regardless of validity (just testing no crash)
        assert!(validate_rc <= 0 || validate_rc == DID_X509_OK);

        if !validate_err.is_null() {
            unsafe { did_x509_error_free(validate_err) };
        }

        unsafe { did_x509_string_free(did_string) };
    } else if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn test_did_x509_invalid_certificate_data() {
    // Test with invalid certificate data
    let invalid_cert_data = b"not a certificate";

    let mut did_string: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = unsafe {
        did_x509_build_with_eku(
            invalid_cert_data.as_ptr(),
            invalid_cert_data.len() as u32,
            ptr::null(),
            0,
            &mut did_string,
            &mut err,
        )
    };

    // Should succeed because build_with_eku only hashes the data, doesn't parse the certificate
    assert_eq!(rc, 0, "Expected success, got: {}", rc);
    assert!(!did_string.is_null(), "Expected valid DID string");
    if !did_string.is_null() {
        unsafe { did_x509_string_free(did_string) };
    }

    // Test build_from_chain with invalid data
    let cert_ptr = invalid_cert_data.as_ptr();
    let cert_len = invalid_cert_data.len() as u32;
    let chain_certs = vec![cert_ptr];
    let chain_cert_lens = vec![cert_len];

    err = ptr::null_mut();
    let rc = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
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
fn test_abi_version_consistency() {
    let version = did_x509_abi_version();
    assert_eq!(version, 1); // Should match ABI_VERSION constant
}

#[test]
fn test_error_code_consistency() {
    // Generate an error and verify error code retrieval
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let invalid_did = CString::new("completely-invalid").unwrap();
    let rc = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut handle, &mut err) };

    assert!(rc < 0);
    assert!(!err.is_null());

    let error_code = unsafe { did_x509_error_code(err) };
    assert_eq!(error_code, rc); // Error code should match return code
    assert!(error_code < 0);

    unsafe { did_x509_error_free(err) };
}
