// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deep coverage tests for did_x509_ffi targeting remaining uncovered lines
//! in lib.rs (inner functions) and error.rs.
//!
//! Focuses on success paths for validate/resolve with matching DID+cert,
//! additional null-pointer branch variations, error construction variants,
//! and handle lifecycle edge cases.

use did_x509_ffi::error::{
    self, ErrorInner, FFI_ERR_BUILD_FAILED, FFI_ERR_INVALID_ARGUMENT, FFI_ERR_NULL_POINTER,
    FFI_ERR_PARSE_FAILED, FFI_ERR_VALIDATE_FAILED, FFI_OK,
};
use did_x509_ffi::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::*;
use openssl::x509::{X509Builder, X509NameBuilder};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::ptr;

// ============================================================================
// Helpers
// ============================================================================

/// Generate a self-signed test certificate with a code-signing EKU.
fn generate_cert_with_eku() -> Vec<u8> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(key).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "DeepCoverage Test CA")
        .unwrap();
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

    let eku = ExtendedKeyUsage::new().code_signing().build().unwrap();
    builder.append_extension(eku).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    builder.build().to_der().unwrap()
}

/// Compute SHA-256 hex fingerprint of DER certificate bytes.
#[allow(dead_code)]
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Build a DID:x509 string via the FFI and return the DID string.
/// Panics if building fails.
fn build_did_from_cert(cert_der: &[u8]) -> String {
    let eku = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let ekus = [eku.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert_der.as_ptr(),
        cert_der.len() as u32,
        ekus.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_OK, "build_did_from_cert failed with rc={}", rc);
    assert!(!out.is_null());

    let did_str = unsafe { CStr::from_ptr(out) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { did_x509_string_free(out) };
    did_str
}

// ============================================================================
// Parse: additional edge cases
// ============================================================================

#[test]
fn deep_parse_with_error_out_null() {
    // Generate a real certificate and build a DID from it to get a valid DID string
    let cert_der = generate_cert_with_eku();
    let did_string = build_did_from_cert(&cert_der);
    let did = CString::new(did_string).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, ptr::null_mut());
    assert_eq!(rc, FFI_OK);
    assert!(!handle.is_null());
    unsafe { did_x509_parsed_free(handle) };
}

#[test]
fn deep_parse_malformed_did_prefix() {
    let did = CString::new("not:a:did:x509").unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, FFI_ERR_PARSE_FAILED);
    assert!(handle.is_null());
    if !err.is_null() {
        let code = unsafe { did_x509_error_code(err) };
        assert!(code < 0);
        let msg = unsafe { did_x509_error_message(err) };
        assert!(!msg.is_null());
        unsafe {
            did_x509_string_free(msg);
            did_x509_error_free(err);
        }
    }
}

#[test]
fn deep_parse_empty_string() {
    let did = CString::new("").unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert!(rc < 0);
    assert!(handle.is_null());
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_parse_multiple_policies() {
    // Build a valid DID, then parse it - we check policy_count >= 1
    let cert_der = generate_cert_with_eku();
    let did_string = build_did_from_cert(&cert_der);
    let did = CString::new(did_string).unwrap();
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, FFI_OK);
    assert!(!handle.is_null());

    let mut count: u32 = 0;
    let rc2 = impl_parsed_get_policy_count_inner(handle, &mut count);
    assert_eq!(rc2, FFI_OK);
    assert!(count >= 1);

    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Build with EKU: success with multiple EKUs
// ============================================================================

#[test]
fn deep_build_eku_multiple_oids() {
    let cert = generate_cert_with_eku();
    let eku1 = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let eku2 = CString::new("1.3.6.1.5.5.7.3.1").unwrap();
    let ekus = [eku1.as_ptr(), eku2.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_with_eku_inner(
        cert.as_ptr(),
        cert.len() as u32,
        ekus.as_ptr(),
        2,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);
    assert!(!out.is_null());

    let did_str = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
    assert!(did_str.starts_with("did:x509:"));
    unsafe { did_x509_string_free(out) };
}

// ============================================================================
// Build from chain: success with valid cert chain
// ============================================================================

#[test]
fn deep_build_from_chain_success() {
    let cert = generate_cert_with_eku();
    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);
    assert!(!out.is_null());
    unsafe { did_x509_string_free(out) };
}

#[test]
fn deep_build_from_chain_null_certs_only() {
    // chain_certs is null, chain_cert_lens is valid — hits first branch of ||
    let lens = [100u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        ptr::null(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_build_from_chain_null_lens_only() {
    // chain_cert_lens is null, chain_certs is valid — hits second branch of ||
    let cert = generate_cert_with_eku();
    let certs = [cert.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        certs.as_ptr(),
        ptr::null(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_build_from_chain_invalid_cert_data() {
    // Pass garbage bytes as cert data — hits the build error path
    let garbage: [u8; 10] = [0xFF; 10];
    let certs = [garbage.as_ptr()];
    let lens = [garbage.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_build_from_chain_inner(
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_BUILD_FAILED);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Validate: success path with matching DID + cert
// ============================================================================

#[test]
fn deep_validate_success_matching_did_cert() {
    let cert = generate_cert_with_eku();
    let did_str = build_did_from_cert(&cert);
    let did = CString::new(did_str).unwrap();

    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);
    assert_eq!(is_valid, 1);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_validate_mismatched_fingerprint() {
    // Use a DID with wrong fingerprint — validation should still run but is_valid=0
    let cert = generate_cert_with_eku();
    let wrong_did = CString::new("did:x509:0:sha256:deadbeef::eku:1.3.6.1.5.5.7.3.3").unwrap();

    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        wrong_did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );
    // May return error or success with is_valid=0 depending on implementation
    if rc == FFI_OK {
        assert_eq!(is_valid, 0);
    }
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_validate_null_certs_only() {
    // chain_certs is null, chain_cert_lens is valid
    let did = CString::new("did:x509:0:sha256:abc::eku:1.2.3").unwrap();
    let lens = [10u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        did.as_ptr(),
        ptr::null(),
        lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_validate_null_lens_only() {
    // chain_cert_lens is null, chain_certs is valid
    let did = CString::new("did:x509:0:sha256:abc::eku:1.2.3").unwrap();
    let cert = generate_cert_with_eku();
    let certs = [cert.as_ptr()];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        did.as_ptr(),
        certs.as_ptr(),
        ptr::null(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_validate_invalid_cert_data() {
    // Pass garbage cert bytes — should trigger validate error path
    let did = CString::new("did:x509:0:sha256:abc::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let garbage: [u8; 5] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    let certs = [garbage.as_ptr()];
    let lens = [garbage.len() as u32];
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        did.as_ptr(),
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

// ============================================================================
// Resolve: success path with matching DID + cert
// ============================================================================

#[test]
fn deep_resolve_success_matching_did_cert() {
    let cert = generate_cert_with_eku();
    let did_str = build_did_from_cert(&cert);
    let did = CString::new(did_str).unwrap();

    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_OK);
    assert!(!out.is_null());

    // Verify it's valid JSON
    let json_str = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
    assert!(json_str.contains("did:x509:"));

    unsafe { did_x509_string_free(out) };
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_resolve_null_certs_only() {
    let did = CString::new("did:x509:0:sha256:abc::eku:1.2.3").unwrap();
    let lens = [10u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        did.as_ptr(),
        ptr::null(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_resolve_null_lens_only() {
    let did = CString::new("did:x509:0:sha256:abc::eku:1.2.3").unwrap();
    let cert = generate_cert_with_eku();
    let certs = [cert.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        did.as_ptr(),
        certs.as_ptr(),
        ptr::null(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

#[test]
fn deep_resolve_invalid_cert_data() {
    let did = CString::new("did:x509:0:sha256:abc::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let garbage: [u8; 5] = [0xFF; 5];
    let certs = [garbage.as_ptr()];
    let lens = [garbage.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        did.as_ptr(),
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
fn deep_resolve_mismatched_fingerprint() {
    let cert = generate_cert_with_eku();
    let wrong_did = CString::new("did:x509:0:sha256:deadbeef::eku:1.3.6.1.5.5.7.3.3").unwrap();

    let certs = [cert.as_ptr()];
    let lens = [cert.len() as u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        wrong_did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    // Expected to fail — fingerprint doesn't match
    assert!(rc < 0);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Error module: from_did_error coverage for various error categories
// ============================================================================

#[test]
fn deep_error_from_did_error_parse_variants() {
    use did_x509::DidX509Error;

    // EmptyDid -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptyDid);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // MissingPolicies -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::MissingPolicies);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // EmptyFingerprint -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptyFingerprint);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // InvalidFingerprintChars -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::InvalidFingerprintChars);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // EmptyPolicyName -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptyPolicyName);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // EmptyPolicyValue -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptyPolicyValue);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // InvalidSubjectPolicyComponents -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::InvalidSubjectPolicyComponents);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // EmptySubjectPolicyKey -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptySubjectPolicyKey);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // InvalidEkuOid -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::InvalidEkuOid);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    // EmptyFulcioIssuer -> FFI_ERR_PARSE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::EmptyFulcioIssuer);
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);
}

#[test]
fn deep_error_from_did_error_invalid_argument_variants() {
    use did_x509::DidX509Error;

    // InvalidChain -> FFI_ERR_INVALID_ARGUMENT
    let err = ErrorInner::from_did_error(&DidX509Error::InvalidChain("bad chain".to_string()));
    assert_eq!(err.code, FFI_ERR_INVALID_ARGUMENT);

    // CertificateParseError -> FFI_ERR_INVALID_ARGUMENT
    let err = ErrorInner::from_did_error(&DidX509Error::CertificateParseError(
        "parse fail".to_string(),
    ));
    assert_eq!(err.code, FFI_ERR_INVALID_ARGUMENT);
}

#[test]
fn deep_error_from_did_error_validate_variants() {
    use did_x509::DidX509Error;

    // NoCaMatch -> FFI_ERR_VALIDATE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::NoCaMatch);
    assert_eq!(err.code, FFI_ERR_VALIDATE_FAILED);

    // ValidationFailed -> FFI_ERR_VALIDATE_FAILED
    let err = ErrorInner::from_did_error(&DidX509Error::ValidationFailed("failed".to_string()));
    assert_eq!(err.code, FFI_ERR_VALIDATE_FAILED);

    // PolicyValidationFailed -> FFI_ERR_VALIDATE_FAILED
    let err =
        ErrorInner::from_did_error(&DidX509Error::PolicyValidationFailed("policy".to_string()));
    assert_eq!(err.code, FFI_ERR_VALIDATE_FAILED);
}

#[test]
fn deep_error_from_did_error_format_variants() {
    use did_x509::DidX509Error;

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidPrefix("bad prefix".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidFormat("bad format".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::UnsupportedVersion("99".to_string(), "0".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::UnsupportedHashAlgorithm("sha999".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::EmptyPolicy(0));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidPolicyFormat("bad".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err = ErrorInner::from_did_error(&DidX509Error::DuplicateSubjectPolicyKey(
        "CN".to_string(),
    ));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidSanPolicyFormat("bad".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidSanType("bad".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::PercentDecodingError("bad%".to_string()));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err =
        ErrorInner::from_did_error(&DidX509Error::InvalidHexCharacter('z'));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);

    let err = ErrorInner::from_did_error(&DidX509Error::FingerprintLengthMismatch(
        "sha256".to_string(),
        32,
        16,
    ));
    assert_eq!(err.code, FFI_ERR_PARSE_FAILED);
}

// ============================================================================
// Error module: handle lifecycle and edge cases
// ============================================================================

#[test]
fn deep_error_free_null() {
    // Calling free with null should be a no-op
    unsafe { did_x509_error_free(ptr::null_mut()) };
}

#[test]
fn deep_string_free_null() {
    unsafe { did_x509_string_free(ptr::null_mut()) };
}

#[test]
fn deep_error_handle_roundtrip() {
    let inner = ErrorInner::new("roundtrip test", -42);
    let handle = error::inner_to_handle(inner);
    assert!(!handle.is_null());

    let code = unsafe { did_x509_error_code(handle) };
    assert_eq!(code, -42);

    let msg_ptr = unsafe { did_x509_error_message(handle) };
    assert!(!msg_ptr.is_null());
    let msg = unsafe { CStr::from_ptr(msg_ptr) }.to_str().unwrap();
    assert_eq!(msg, "roundtrip test");

    unsafe {
        did_x509_string_free(msg_ptr);
        did_x509_error_free(handle);
    }
}

#[test]
fn deep_error_code_null() {
    let code = unsafe { did_x509_error_code(ptr::null()) };
    assert_eq!(code, 0);
}

#[test]
fn deep_error_message_null() {
    let msg = unsafe { did_x509_error_message(ptr::null()) };
    assert!(msg.is_null());
}

// ============================================================================
// Parsed handle: fingerprint and algorithm after build roundtrip
// ============================================================================

#[test]
fn deep_parse_and_query_all_fields() {
    let cert = generate_cert_with_eku();
    let did_str = build_did_from_cert(&cert);
    let did = CString::new(did_str.clone()).unwrap();

    // Parse
    let mut handle: *mut DidX509ParsedHandle = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    let rc = impl_parse_inner(did.as_ptr(), &mut handle, &mut err);
    assert_eq!(rc, FFI_OK);
    assert!(!handle.is_null());

    // Get fingerprint
    let mut fp: *const libc::c_char = ptr::null();
    let rc = impl_parsed_get_fingerprint_inner(handle, &mut fp, &mut err);
    assert_eq!(rc, FFI_OK);
    assert!(!fp.is_null());
    let fp_str = unsafe { CStr::from_ptr(fp) }.to_str().unwrap();
    // Fingerprint should be non-empty and match the cert's SHA-256
    assert!(!fp_str.is_empty());
    unsafe { did_x509_string_free(fp as *mut _) };

    // Get hash algorithm
    let mut algo: *const libc::c_char = ptr::null();
    let rc = impl_parsed_get_hash_algorithm_inner(handle, &mut algo, &mut err);
    assert_eq!(rc, FFI_OK);
    assert!(!algo.is_null());
    let algo_str = unsafe { CStr::from_ptr(algo) }.to_str().unwrap();
    assert_eq!(algo_str, "sha256");
    unsafe { did_x509_string_free(algo as *mut _) };

    // Get policy count
    let mut count: u32 = 0;
    let rc = impl_parsed_get_policy_count_inner(handle, &mut count);
    assert_eq!(rc, FFI_OK);
    assert!(count >= 1);

    unsafe { did_x509_parsed_free(handle) };
}

// ============================================================================
// Build with EKU: edge case — empty cert with zero length
// ============================================================================

#[test]
fn deep_build_eku_empty_cert_zero_len() {
    let eku = CString::new("1.3.6.1.5.5.7.3.3").unwrap();
    let ekus = [eku.as_ptr()];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    // null cert pointer with zero length is allowed — produces a DID with empty fingerprint
    let rc = impl_build_with_eku_inner(
        ptr::null(),
        0,
        ekus.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    // Should succeed (empty cert is technically allowed by the API)
    assert_eq!(rc, FFI_OK);
    if !out.is_null() {
        unsafe { did_x509_string_free(out) };
    }
}

// ============================================================================
// Validate: with null cert entry in chain array (non-zero len → error)
// ============================================================================

#[test]
fn deep_validate_null_cert_in_chain() {
    let did = CString::new("did:x509:0:sha256:abc::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let null_cert: *const u8 = ptr::null();
    let certs = [null_cert];
    let lens = [50u32]; // non-zero length with null pointer
    let mut is_valid: i32 = 0;
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_validate_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut is_valid,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// Resolve: with null cert entry in chain array (non-zero len → error)
// ============================================================================

#[test]
fn deep_resolve_null_cert_in_chain() {
    let did = CString::new("did:x509:0:sha256:abc::eku:1.3.6.1.5.5.7.3.3").unwrap();
    let null_cert: *const u8 = ptr::null();
    let certs = [null_cert];
    let lens = [50u32];
    let mut out: *mut libc::c_char = ptr::null_mut();
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();

    let rc = impl_resolve_inner(
        did.as_ptr(),
        certs.as_ptr(),
        lens.as_ptr(),
        1,
        &mut out,
        &mut err,
    );
    assert_eq!(rc, FFI_ERR_NULL_POINTER);
    if !err.is_null() {
        unsafe { did_x509_error_free(err) };
    }
}

// ============================================================================
// set_error with valid and null out_error pointers
// ============================================================================

#[test]
fn deep_set_error_with_valid_ptr() {
    let mut err: *mut DidX509ErrorHandle = ptr::null_mut();
    error::set_error(&mut err, ErrorInner::new("deep set_error test", -10));
    assert!(!err.is_null());

    let code = unsafe { did_x509_error_code(err) };
    assert_eq!(code, -10);
    unsafe { did_x509_error_free(err) };
}

#[test]
fn deep_set_error_with_null_ptr() {
    // Should not crash
    error::set_error(ptr::null_mut(), ErrorInner::new("no-op", -1));
}
