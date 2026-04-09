// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI coverage tests to improve coverage on resolve, validate, and build paths.

use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
use std::borrow::Cow;
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

/// Generate an RSA certificate using openssl.
fn generate_rsa_cert() -> Vec<u8> {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();

    let serial = BigNum::from_u32(1).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder
        .append_entry_by_text("CN", "RSA Test Certificate")
        .unwrap();
    let name = name_builder.build();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    builder.set_not_before(&not_before).unwrap();
    builder.set_not_after(&not_after).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let eku = openssl::x509::extension::ExtendedKeyUsage::new()
        .code_signing()
        .build()
        .unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

/// Generate an EC certificate using cose_sign1_certificates_local.
fn generate_ec_cert() -> Vec<u8> {
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory.create_certificate(
        CertificateOptions::new()
            .with_subject_name("CN=EC Test Certificate")
            .with_enhanced_key_usages(vec!["1.3.6.1.5.5.7.3.3".to_string()])
    ).unwrap();
    cert.cert_der
}

#[test]
fn test_ffi_resolve_rsa_certificate() {
    let cert_der = generate_rsa_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];

    let mut result_json: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

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

    assert_eq!(
        status,
        DID_X509_OK,
        "Expected success, got error: {:?}",
        error_message(error)
    );
    assert!(!result_json.is_null());

    // Verify RSA key type in result
    let json_str = unsafe { CStr::from_ptr(result_json) }.to_str().unwrap();
    assert!(json_str.contains("RSA"), "Should contain RSA key type");

    unsafe {
        did_x509_string_free(result_json);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_rsa_certificate() {
    let cert_der = generate_rsa_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];

    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

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

    assert_eq!(
        status,
        DID_X509_OK,
        "Expected success, got error: {:?}",
        error_message(error)
    );
    assert_eq!(is_valid, 1, "RSA certificate should be valid");

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_from_chain_ec_certificate() {
    let cert_der = generate_ec_cert();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];

    let mut result_did: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_cert_lens.as_ptr(),
            1,
            &mut result_did,
            &mut error,
        )
    };

    assert_eq!(
        status,
        DID_X509_OK,
        "Expected success, got error: {:?}",
        error_message(error)
    );
    assert!(!result_did.is_null());

    let did_str = unsafe { CStr::from_ptr(result_did) }.to_str().unwrap();
    assert!(
        did_str.starts_with("did:x509:"),
        "Should be a valid DID:x509"
    );

    unsafe {
        did_x509_string_free(result_did);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_with_eku_ec_certificate() {
    let cert_der = generate_ec_cert();

    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_oids = [eku_oid.as_ptr()];

    let mut result_did: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_with_eku(
            cert_der.as_ptr(),
            cert_der.len() as u32,
            eku_oids.as_ptr(),
            1,
            &mut result_did,
            &mut error,
        )
    };

    assert_eq!(
        status,
        DID_X509_OK,
        "Expected success, got error: {:?}",
        error_message(error)
    );
    assert!(!result_did.is_null());

    let did_str = unsafe { CStr::from_ptr(result_did) }.to_str().unwrap();
    assert!(
        did_str.starts_with("did:x509:"),
        "Should be a valid DID:x509"
    );
    assert!(did_str.contains("eku"), "Should contain EKU policy");

    unsafe {
        did_x509_string_free(result_did);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parse_and_get_fields() {
    let cert_der = generate_ec_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    // Parse
    let status = impl_parse_inner(did_cstring.as_ptr(), &mut handle, &mut error);

    assert_eq!(status, DID_X509_OK, "Parse should succeed");
    assert!(!handle.is_null());

    // Get fingerprint
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let status = impl_parsed_get_fingerprint_inner(handle, &mut fingerprint, &mut error);
    assert_eq!(status, DID_X509_OK, "Get fingerprint should succeed");
    assert!(!fingerprint.is_null());

    let fp_str = unsafe { CStr::from_ptr(fingerprint) }.to_str().unwrap();
    assert_eq!(
        fp_str.len(),
        64,
        "SHA256 fingerprint should be 64 hex chars"
    );

    // Get hash algorithm
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let status = impl_parsed_get_hash_algorithm_inner(handle, &mut algorithm, &mut error);
    assert_eq!(status, DID_X509_OK, "Get algorithm should succeed");
    assert!(!algorithm.is_null());

    let alg_str = unsafe { CStr::from_ptr(algorithm) }.to_str().unwrap();
    assert_eq!(alg_str, "sha256", "Should be sha256");

    // Get policy count
    let mut count: u32 = 0;
    let status = impl_parsed_get_policy_count_inner(handle, &mut count);
    assert_eq!(status, DID_X509_OK, "Get policy count should succeed");
    assert_eq!(count, 1, "Should have 1 policy");

    // Clean up
    unsafe {
        did_x509_string_free(fingerprint);
        did_x509_string_free(algorithm);
        did_x509_parsed_free(handle);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_ec_verify_document_structure() {
    let cert_der = generate_ec_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_cert_lens = [cert_len];

    let mut result_json: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

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

    assert_eq!(status, DID_X509_OK);
    assert!(!result_json.is_null());

    let json_str = unsafe { CStr::from_ptr(result_json) }.to_str().unwrap();

    // Verify EC key in result
    assert!(json_str.contains("EC"), "Should contain EC key type");
    assert!(json_str.contains("P-256"), "Should contain P-256 curve");
    assert!(
        json_str.contains("JsonWebKey2020"),
        "Should contain JsonWebKey2020"
    );

    unsafe {
        did_x509_string_free(result_json);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_error_code_accessor() {
    // Create an error by passing invalid arguments
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    // Parse with null string should create an error
    let status = impl_parse_inner(ptr::null(), &mut handle, &mut error);

    assert_ne!(status, DID_X509_OK);
    assert!(!error.is_null());

    // Test error code accessor
    let code = unsafe { did_x509_error_code(error) };
    assert!(code != 0, "Error code should be non-zero");

    // Clean up
    unsafe {
        did_x509_error_free(error);
    }
}

#[test]
fn test_ffi_build_with_eku_null_output_pointer() {
    let cert_der = generate_ec_cert();
    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_oids = [eku_oid.as_ptr()];
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    // Pass null for out_did_string
    let status = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        eku_oids.as_ptr(),
        1,
        ptr::null_mut(),
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_with_eku_null_cert() {
    let eku_oid = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku_oids = [eku_oid.as_ptr()];
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    // Pass null cert with non-zero len
    let status = impl_build_with_eku_inner(
        ptr::null(),
        10, // non-zero length but null pointer
        eku_oids.as_ptr(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_with_eku_null_oids() {
    let cert_der = generate_ec_cert();
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    // Pass null eku_oids with non-zero count
    let status = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        ptr::null(),
        1, // non-zero count but null pointer
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_with_eku_null_oid_entry() {
    let cert_der = generate_ec_cert();
    let eku_oids: [*const libc::c_char; 1] = [ptr::null()]; // Null entry
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        eku_oids.as_ptr(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_from_chain_null_output() {
    let cert_der = generate_ec_cert();
    let chain_certs = [cert_der.as_ptr()];
    let chain_cert_lens = [cert_der.len() as u32];
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_build_from_chain_inner(
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        ptr::null_mut(), // null output
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_from_chain_null_certs() {
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_build_from_chain_inner(
        ptr::null(), // null certs
        ptr::null(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_from_chain_zero_count() {
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();
    let certs: [*const u8; 0] = [];
    let lens: [u32; 0] = [];

    let status = impl_build_from_chain_inner(
        certs.as_ptr(),
        lens.as_ptr(),
        0, // zero count
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_INVALID_ARGUMENT);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_build_from_chain_null_cert_entry() {
    let chain_certs: [*const u8; 1] = [ptr::null()];
    let chain_cert_lens: [u32; 1] = [10]; // non-zero len but null pointer
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_build_from_chain_inner(
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_null_is_valid() {
    let cert_der = generate_ec_cert();
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let chain_certs = [cert_der.as_ptr()];
    let chain_cert_lens = [cert_der.len() as u32];
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_validate_inner(
        did_cstring.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        ptr::null_mut(), // null out_is_valid
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_null_did() {
    let cert_der = generate_ec_cert();
    let chain_certs = [cert_der.as_ptr()];
    let chain_cert_lens = [cert_der.len() as u32];
    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_validate_inner(
        ptr::null(), // null DID
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut is_valid,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_null_chain() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_validate_inner(
        did_cstring.as_ptr(),
        ptr::null(), // null chain
        ptr::null(),
        1,
        &mut is_valid,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_zero_chain_count() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let certs: [*const u8; 0] = [];
    let lens: [u32; 0] = [];
    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_validate_inner(
        did_cstring.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        0, // zero count
        &mut is_valid,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_INVALID_ARGUMENT);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_validate_null_chain_entry() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let chain_certs: [*const u8; 1] = [ptr::null()];
    let chain_cert_lens: [u32; 1] = [10];
    let mut is_valid: i32 = 0;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_validate_inner(
        did_cstring.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut is_valid,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_null_output() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let cert_der = generate_ec_cert();
    let chain_certs = [cert_der.as_ptr()];
    let chain_cert_lens = [cert_der.len() as u32];
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_resolve_inner(
        did_cstring.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        ptr::null_mut(), // null output
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_null_did() {
    let cert_der = generate_ec_cert();
    let chain_certs = [cert_der.as_ptr()];
    let chain_cert_lens = [cert_der.len() as u32];
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_resolve_inner(
        ptr::null(), // null DID
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_null_chain() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_resolve_inner(
        did_cstring.as_ptr(),
        ptr::null(), // null chain
        ptr::null(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_zero_chain_count() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let certs: [*const u8; 0] = [];
    let lens: [u32; 0] = [];
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_resolve_inner(
        did_cstring.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        0, // zero count
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_INVALID_ARGUMENT);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_resolve_null_chain_entry() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let chain_certs: [*const u8; 1] = [ptr::null()];
    let chain_cert_lens: [u32; 1] = [10];
    let mut result: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_resolve_inner(
        did_cstring.as_ptr(),
        chain_certs.as_ptr(),
        chain_cert_lens.as_ptr(),
        1,
        &mut result,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_fingerprint_null_output() {
    let cert_der = generate_ec_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let _ = impl_parse_inner(did_cstring.as_ptr(), &mut handle, &mut error);

    // Test null output
    let status = impl_parsed_get_fingerprint_inner(handle, ptr::null_mut(), &mut error);

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !handle.is_null() {
            did_x509_parsed_free(handle);
        }
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_fingerprint_null_handle() {
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_parsed_get_fingerprint_inner(
        ptr::null(), // null handle
        &mut fingerprint,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_algorithm_null_output() {
    let cert_der = generate_ec_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let _ = impl_parse_inner(did_cstring.as_ptr(), &mut handle, &mut error);

    let status = impl_parsed_get_hash_algorithm_inner(
        handle,
        ptr::null_mut(), // null output
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !handle.is_null() {
            did_x509_parsed_free(handle);
        }
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_algorithm_null_handle() {
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_parsed_get_hash_algorithm_inner(
        ptr::null(), // null handle
        &mut algorithm,
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_policy_count_null_output() {
    let cert_der = generate_ec_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let _ = impl_parse_inner(did_cstring.as_ptr(), &mut handle, &mut error);

    let status = impl_parsed_get_policy_count_inner(
        handle,
        ptr::null_mut(), // null output
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !handle.is_null() {
            did_x509_parsed_free(handle);
        }
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_ffi_parsed_get_policy_count_null_handle() {
    let mut count: u32 = 0;

    let status = impl_parsed_get_policy_count_inner(
        ptr::null(), // null handle
        &mut count,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
}

#[test]
fn test_ffi_parse_null_output_handle() {
    let did_cstring = CString::new("did:x509:0:sha256::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = impl_parse_inner(
        did_cstring.as_ptr(),
        ptr::null_mut(), // null output handle
        &mut error,
    );

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}
