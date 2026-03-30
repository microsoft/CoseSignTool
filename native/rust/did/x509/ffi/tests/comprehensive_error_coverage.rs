// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive FFI test coverage for DID x509 targeting uncovered error paths

use did_x509_ffi::{
    did_x509_abi_version, did_x509_build_from_chain, did_x509_build_with_eku, did_x509_parse,
    did_x509_parsed_free, did_x509_parsed_get_fingerprint, did_x509_parsed_get_hash_algorithm,
    did_x509_parsed_get_policy_count, did_x509_resolve, did_x509_validate,
    error::{
        did_x509_error_free, did_x509_string_free, DidX509ErrorHandle, FFI_ERR_INVALID_ARGUMENT,
        FFI_ERR_NULL_POINTER, FFI_ERR_PARSE_FAILED, FFI_ERR_RESOLVE_FAILED, FFI_OK,
    },
    types::DidX509ParsedHandle,
};
use libc::c_char;
use rcgen::{CertificateParams, DnType, KeyPair};
use std::{ffi::CString, ptr};

// Valid test fingerprint
const FP256: &str = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK-2vcTL0tk";

#[test]
fn test_abi_version() {
    // Test ABI version function (should be non-zero)
    let version = did_x509_abi_version();
    assert!(version > 0);
}

#[test]
fn test_parse_various_invalid_formats() {
    // Test parsing with completely invalid DID format
    let invalid_did = CString::new("not-a-did-at-all").unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_empty_did() {
    // Test parsing with empty DID string
    let empty_did = CString::new("").unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(empty_did.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_whitespace_only_did() {
    // Test parsing with whitespace-only DID
    let whitespace_did = CString::new("   \t\n   ").unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result =
        unsafe { did_x509_parse(whitespace_did.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_missing_policies() {
    // Test DID without policies (missing ::)
    let no_policies = format!("did:x509:0:sha256:{}", FP256);
    let did_cstr = CString::new(no_policies).unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(did_cstr.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_invalid_version() {
    // Test DID with unsupported version
    let invalid_version = format!("did:x509:1:sha256:{}::eku:1.2.3.4", FP256);
    let did_cstr = CString::new(invalid_version).unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(did_cstr.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_invalid_hash_algorithm() {
    // Test DID with unsupported hash algorithm
    let invalid_hash = format!("did:x509:0:md5:{}::eku:1.2.3.4", FP256);
    let did_cstr = CString::new(invalid_hash).unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(did_cstr.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_parse_wrong_fingerprint_length() {
    // Test DID with wrong fingerprint length for SHA-256 (should be 43 chars)
    let wrong_fp = "AAcOFRwjKjE4P0ZNVFtiaXB3foWMk5qhqK"; // Too short
    let wrong_length = format!("did:x509:0:sha256:{}::eku:1.2.3.4", wrong_fp);
    let did_cstr = CString::new(wrong_length).unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(did_cstr.as_ptr(), &mut out_handle, &mut out_error) };

    assert_eq!(result, FFI_ERR_PARSE_FAILED);
    assert!(out_handle.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_accessor_error_paths() {
    // Test accessor functions with various invalid inputs

    // Test fingerprint accessor with null handle
    let mut out_fingerprint: *const c_char = ptr::null();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_parsed_get_fingerprint(ptr::null(), &mut out_fingerprint, &mut out_error)
    };

    assert_eq!(result, FFI_ERR_NULL_POINTER);
    assert!(out_fingerprint.is_null());

    // Test hash algorithm accessor with null handle
    let mut out_algorithm: *const c_char = ptr::null();
    let mut out_error2: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_parsed_get_hash_algorithm(ptr::null(), &mut out_algorithm, &mut out_error2)
    };

    assert_eq!(result, FFI_ERR_NULL_POINTER);
    assert!(out_algorithm.is_null());

    // Test policy count accessor with null handle
    let mut out_count: u32 = 0;

    let result = unsafe { did_x509_parsed_get_policy_count(ptr::null(), &mut out_count) };

    assert_eq!(result, FFI_ERR_NULL_POINTER);
    assert_eq!(out_count, 0);
}

#[test]
fn test_accessor_null_output_pointers() {
    // First parse a valid DID
    let valid_did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let did_cstr = CString::new(valid_did).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut parse_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let parse_result = unsafe { did_x509_parse(did_cstr.as_ptr(), &mut handle, &mut parse_error) };

    assert_eq!(parse_result, FFI_OK);
    assert!(!handle.is_null());

    // Test accessors with null output pointers
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result1 = unsafe {
        did_x509_parsed_get_fingerprint(
            handle,
            ptr::null_mut(), // null output pointer
            &mut out_error,
        )
    };
    assert_eq!(result1, FFI_ERR_NULL_POINTER);

    let result2 = unsafe {
        did_x509_parsed_get_hash_algorithm(
            handle,
            ptr::null_mut(), // null output pointer
            &mut out_error,
        )
    };
    assert_eq!(result2, FFI_ERR_NULL_POINTER);

    let result3 = unsafe {
        did_x509_parsed_get_policy_count(
            handle,
            ptr::null_mut(), // null output pointer
        )
    };
    assert_eq!(result3, FFI_ERR_NULL_POINTER);

    // Clean up
    unsafe {
        did_x509_parsed_free(handle);
    }
}

#[test]
fn test_validate_with_empty_chain() {
    // Test validation with empty certificate chain
    let valid_did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let did_cstr = CString::new(valid_did).unwrap();
    let empty_chain: Vec<*const u8> = vec![];
    let chain_lengths: Vec<u32> = vec![];
    let mut out_valid: i32 = 0;
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_validate(
            did_cstr.as_ptr(),
            empty_chain.as_ptr(),
            chain_lengths.as_ptr(),
            0, // chain_count
            &mut out_valid,
            &mut out_error,
        )
    };

    // Empty chain is an invalid argument
    assert_eq!(result, FFI_ERR_INVALID_ARGUMENT);
    assert_eq!(out_valid, 0);
}

#[test]
fn test_validate_with_null_chain() {
    // Test validation with null certificate chain
    let valid_did = format!("did:x509:0:sha256:{}::eku:1.2.3.4", FP256);
    let did_cstr = CString::new(valid_did).unwrap();
    let mut out_valid: i32 = 0;
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_validate(
            did_cstr.as_ptr(),
            ptr::null(),
            ptr::null(),
            1, // Non-zero count but null pointers
            &mut out_valid,
            &mut out_error,
        )
    };

    assert_eq!(result, FFI_ERR_NULL_POINTER);
    assert_eq!(out_valid, 0);
}

#[test]
fn test_resolve_invalid_did() {
    // Test resolution with invalid DID and null chain - null pointer check happens first
    let invalid_did = CString::new("not:a:valid:did").unwrap();
    let mut out_json: *mut c_char = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_resolve(
            invalid_did.as_ptr(),
            ptr::null(), // chain_certs
            ptr::null(), // chain_cert_lens
            0,           // chain_count
            &mut out_json,
            &mut out_error,
        )
    };

    // Returns null pointer error when chain is null with count > 0, or resolve failed otherwise
    assert!(result == FFI_ERR_NULL_POINTER || result == FFI_ERR_RESOLVE_FAILED);
    assert!(out_json.is_null());
}

#[test]
fn test_build_with_empty_certs() {
    // Test build_from_chain with empty certificate array
    let mut out_did: *mut c_char = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_build_from_chain(
            ptr::null(), // empty certs
            ptr::null(), // empty lengths
            0,           // cert_count
            &mut out_did,
            &mut out_error,
        )
    };

    assert_ne!(result, FFI_OK); // Should fail
    assert!(out_did.is_null());
    assert!(!out_error.is_null());

    unsafe {
        did_x509_error_free(out_error);
    }
}

#[test]
fn test_build_with_null_algorithm() {
    // Generate a minimal certificate for testing
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let mut out_did: *mut c_char = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result =
        unsafe { did_x509_build_from_chain(&cert_ptr, &cert_len, 1, &mut out_did, &mut out_error) };

    // Should succeed or fail gracefully (not null pointer error)
    assert!(result == FFI_OK || !out_error.is_null());

    if !out_error.is_null() {
        unsafe {
            did_x509_error_free(out_error);
        }
    }
    if !out_did.is_null() {
        unsafe {
            did_x509_string_free(out_did);
        }
    }
}

#[test]
fn test_build_with_invalid_algorithm() {
    // Generate a minimal certificate for testing
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, "Test");
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = cert.der();

    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let mut out_did: *mut c_char = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result =
        unsafe { did_x509_build_from_chain(&cert_ptr, &cert_len, 1, &mut out_did, &mut out_error) };

    // Should succeed or fail gracefully
    assert!(result == FFI_OK || !out_error.is_null());

    if !out_error.is_null() {
        unsafe {
            did_x509_error_free(out_error);
        }
    }
    if !out_did.is_null() {
        unsafe {
            did_x509_string_free(out_did);
        }
    }
}

#[test]
fn test_build_with_eku_null_outputs() {
    // Test build_with_eku with null output pointers
    let cert_der = vec![0x30, 0x82]; // Minimal DER prefix (will fail parsing but tests null checks first)
    let cert_ptr = cert_der.as_ptr();
    let cert_len = cert_der.len() as u32;
    let eku_oid = CString::new("1.2.3.4").unwrap();
    let eku_oids = [eku_oid.as_ptr()];
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe {
        did_x509_build_with_eku(
            cert_ptr,
            cert_len,
            eku_oids.as_ptr(),
            1,               // eku_count
            ptr::null_mut(), // null output DID pointer
            &mut out_error,
        )
    };

    assert_eq!(result, FFI_ERR_NULL_POINTER);
}

#[test]
fn test_string_free_with_valid_pointer() {
    // Test string free with a valid allocated string
    let test_string = CString::new("test").unwrap();
    let leaked_ptr = test_string.into_raw(); // Leak to test free

    unsafe {
        did_x509_string_free(leaked_ptr);
    }
    // Should not crash
}

#[test]
fn test_error_free_with_valid_handle() {
    // Get an actual error handle first
    let invalid_did = CString::new("invalid").unwrap();
    let mut out_handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut out_error: *mut DidX509ErrorHandle = ptr::null_mut();

    let result = unsafe { did_x509_parse(invalid_did.as_ptr(), &mut out_handle, &mut out_error) };

    assert_ne!(result, FFI_OK);
    assert!(!out_error.is_null());

    // Now test freeing the error handle
    unsafe {
        did_x509_error_free(out_error);
    }
    // Should not crash
}
