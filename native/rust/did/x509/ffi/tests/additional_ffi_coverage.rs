// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional FFI coverage tests to achieve 90% line coverage.
//!
//! These tests focus on uncovered paths in the FFI layer.

use std::borrow::Cow;
use did_x509::builder::DidX509Builder;
use did_x509::models::policy::DidX509Policy;
use did_x509_ffi::*;
use rcgen::string::Ia5String;
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, SanType as RcgenSanType};
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

/// Generate a certificate for testing
fn generate_test_cert() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Certificate");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with specific subject attributes
fn generate_cert_with_subject() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "Test Subject CN");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Test Org");
    params.distinguished_name.push(DnType::CountryName, "US");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

/// Generate certificate with SAN
fn generate_cert_with_san() -> Vec<u8> {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "SAN Test Certificate");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    params.subject_alt_names = vec![
        RcgenSanType::DnsName(Ia5String::try_from("example.com").unwrap()),
        RcgenSanType::Rfc822Name(Ia5String::try_from("test@example.com").unwrap()),
    ];

    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    cert.der().to_vec()
}

// ============================================================================
// Parse function null safety tests
// ============================================================================

#[test]
fn test_parse_null_did_string() {
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(ptr::null(), &mut handle, &mut error) };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    assert!(handle.is_null());
    assert!(!error.is_null());

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_parse_null_out_handle() {
    let did = CString::new("did:x509:0:sha256:AAAA::eku:1.2.3").unwrap();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did.as_ptr(), ptr::null_mut(), &mut error) };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);
    assert!(!error.is_null());

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_parse_valid_did() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_cstring.as_ptr(), &mut handle, &mut error) };

    assert_eq!(
        status,
        DID_X509_OK,
        "Parse error: {:?}",
        error_message(error)
    );
    assert!(!handle.is_null());

    unsafe {
        did_x509_parsed_free(handle);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_parse_invalid_did() {
    let invalid_did = CString::new("not-a-valid-did").unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut handle, &mut error) };

    assert_ne!(status, DID_X509_OK);
    assert!(handle.is_null());
    assert!(!error.is_null());

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

// ============================================================================
// Validate function tests
// ============================================================================

#[test]
fn test_validate_null_did() {
    let cert_der = generate_test_cert();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut is_valid: i32 = -1;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_validate(
            ptr::null(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut is_valid,
            &mut error,
        )
    };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_validate_null_chain() {
    let did = CString::new("did:x509:0:sha256:AAAA::eku:1.2.3").unwrap();

    let mut is_valid: i32 = -1;
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_validate(
            did.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            &mut is_valid,
            &mut error,
        )
    };

    // Should fail with null chain
    assert_ne!(status, DID_X509_OK);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_validate_null_out_valid() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_validate(
            did_cstring.as_ptr(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            ptr::null_mut(),
            &mut error,
        )
    };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

// ============================================================================
// Resolve function tests
// ============================================================================

#[test]
fn test_resolve_null_did() {
    let cert_der = generate_test_cert();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut result_json: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_resolve(
            ptr::null(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut result_json,
            &mut error,
        )
    };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_resolve_null_out_json() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_resolve(
            did_cstring.as_ptr(),
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            ptr::null_mut(),
            &mut error,
        )
    };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

// ============================================================================
// Build function tests
// ============================================================================

#[test]
fn test_build_from_chain_null_certs() {
    let mut result_did: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_from_chain(ptr::null(), ptr::null(), 0, &mut result_did, &mut error)
    };

    assert_ne!(status, DID_X509_OK);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_build_from_chain_null_out_did() {
    let cert_der = generate_test_cert();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            ptr::null_mut(),
            &mut error,
        )
    };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_build_from_chain_success() {
    let cert_der = generate_test_cert();
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let chain_certs = [cert_ptr];
    let chain_lens = [cert_len];

    let mut result_did: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe {
        did_x509_build_from_chain(
            chain_certs.as_ptr(),
            chain_lens.as_ptr(),
            1,
            &mut result_did,
            &mut error,
        )
    };

    assert_eq!(
        status,
        DID_X509_OK,
        "Build error: {:?}",
        error_message(error)
    );
    assert!(!result_did.is_null());

    let did_str = unsafe { CStr::from_ptr(result_did) }.to_str().unwrap();
    assert!(did_str.starts_with("did:x509:"));

    unsafe {
        did_x509_string_free(result_did);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

// ============================================================================
// Error handling tests
// ============================================================================

#[test]
fn test_error_code() {
    let invalid_did = CString::new("not-a-valid-did").unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    unsafe {
        did_x509_parse(invalid_did.as_ptr(), &mut handle, &mut error);
    }

    assert!(!error.is_null());

    let code = unsafe { did_x509_error_code(error) };
    assert_ne!(code, 0, "Error code should be non-zero for parse failure");

    unsafe {
        did_x509_error_free(error);
    }
}

#[test]
fn test_error_message_null() {
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null(), "Should return null for null error handle");
}

#[test]
fn test_string_free_null() {
    // Should not crash when freeing null
    unsafe { did_x509_string_free(ptr::null_mut()) };
}

#[test]
fn test_parsed_free_null() {
    // Should not crash when freeing null
    unsafe { did_x509_parsed_free(ptr::null_mut()) };
}

#[test]
fn test_error_free_null() {
    // Should not crash when freeing null
    unsafe { did_x509_error_free(ptr::null_mut()) };
}

// ============================================================================
// Parsed identifier accessors
// ============================================================================

#[test]
fn test_parsed_get_fingerprint() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_cstring.as_ptr(), &mut handle, &mut error) };

    assert_eq!(status, DID_X509_OK);
    assert!(!handle.is_null());

    // Test get_fingerprint
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut fp_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let fp_status =
        unsafe { did_x509_parsed_get_fingerprint(handle, &mut fingerprint, &mut fp_error) };

    assert_eq!(fp_status, DID_X509_OK, "Should get fingerprint");
    assert!(!fingerprint.is_null());

    let fp_str = unsafe { CStr::from_ptr(fingerprint) }.to_str().unwrap();
    assert!(!fp_str.is_empty());

    unsafe {
        did_x509_string_free(fingerprint);
        did_x509_parsed_free(handle);
        if !error.is_null() {
            did_x509_error_free(error);
        }
        if !fp_error.is_null() {
            did_x509_error_free(fp_error);
        }
    }
}

#[test]
fn test_parsed_get_hash_algorithm() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_cstring.as_ptr(), &mut handle, &mut error) };

    assert_eq!(status, DID_X509_OK);

    // Test get_hash_algorithm
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut alg_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let alg_status =
        unsafe { did_x509_parsed_get_hash_algorithm(handle, &mut algorithm, &mut alg_error) };

    assert_eq!(alg_status, DID_X509_OK, "Should get hash algorithm");
    assert!(!algorithm.is_null());

    let alg_str = unsafe { CStr::from_ptr(algorithm) }.to_str().unwrap();
    assert_eq!(alg_str, "sha256");

    unsafe {
        did_x509_string_free(algorithm);
        did_x509_parsed_free(handle);
        if !error.is_null() {
            did_x509_error_free(error);
        }
        if !alg_error.is_null() {
            did_x509_error_free(alg_error);
        }
    }
}

#[test]
fn test_parsed_get_policy_count() {
    let cert_der = generate_test_cert();
    let policy = DidX509Policy::Eku(vec![Cow::Borrowed("1.3.6.1.5.5.7.3.3")]);
    let did_string = DidX509Builder::build_sha256(&cert_der, &[policy]).unwrap();
    let did_cstring = CString::new(did_string.as_str()).unwrap();

    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status = unsafe { did_x509_parse(did_cstring.as_ptr(), &mut handle, &mut error) };

    assert_eq!(status, DID_X509_OK);

    // Test get_policy_count
    let mut count: u32 = 0;
    let count_status = unsafe { did_x509_parsed_get_policy_count(handle, &mut count) };
    assert_eq!(count_status, DID_X509_OK, "Should get policy count");
    assert!(count >= 1, "Should have at least one policy");

    unsafe {
        did_x509_parsed_free(handle);
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }
}

#[test]
fn test_parsed_accessors_null_handle() {
    // Test get_fingerprint with null handle
    let mut fingerprint: *mut libc::c_char = ptr::null_mut();
    let mut error: *mut DidX509ErrorHandle = ptr::null_mut();

    let status =
        unsafe { did_x509_parsed_get_fingerprint(ptr::null(), &mut fingerprint, &mut error) };

    assert_eq!(status, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error.is_null() {
            did_x509_error_free(error);
        }
    }

    // Test get_hash_algorithm with null handle
    let mut algorithm: *mut libc::c_char = ptr::null_mut();
    let mut error2: *mut DidX509ErrorHandle = ptr::null_mut();

    let status2 =
        unsafe { did_x509_parsed_get_hash_algorithm(ptr::null(), &mut algorithm, &mut error2) };

    assert_eq!(status2, DID_X509_ERR_NULL_POINTER);

    unsafe {
        if !error2.is_null() {
            did_x509_error_free(error2);
        }
    }

    // Test get_policy_count with null handle
    let mut dummy_count: u32 = 0;
    let count_status = unsafe { did_x509_parsed_get_policy_count(ptr::null(), &mut dummy_count) };
    assert_eq!(
        count_status, DID_X509_ERR_NULL_POINTER,
        "Should return error for null handle"
    );
}
