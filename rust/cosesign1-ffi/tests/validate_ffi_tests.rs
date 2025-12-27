// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_validation::*;
use std::ffi::{c_char, CStr, CString};

fn encode_minimal_cose_sign1(payload: Option<&[u8]>) -> Vec<u8> {
    let mut protected_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected_map);
        enc.map(0).unwrap();
    }

    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_map).unwrap();
    enc.map(0).unwrap();
    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    }
    enc.bytes(&[0u8; 64]).unwrap();
    out
}

unsafe fn cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[test]
fn verify_signature_covers_null_args_parse_error_and_invalid() {
    unsafe {
        // Null cose.
        let res = cosesign1_validation_verify_signature(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        assert_eq!(cstr(cosesign1_validation_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        cosesign1_validation_result_free(res);

        // Parse error.
        let bad = [0x01u8, 0x02u8, 0x03u8];
        let res = cosesign1_validation_verify_signature(bad.as_ptr(), bad.len(), std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        assert_eq!(cstr(cosesign1_validation_result_failure_at(res, 0).error_code), "CBOR_PARSE_ERROR");
        cosesign1_validation_result_free(res);

        // Embedded invalid: no key headers / signature etc.
        let cose_embedded = encode_minimal_cose_sign1(Some(b"hello"));
        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        assert!(cosesign1_validation_result_failure_count(res) >= 1);
        cosesign1_validation_result_free(res);
    }
}

#[test]
fn options_allow_null_string_pointers() {
    unsafe {
        // Just ensure the API tolerates null payload and key pointers.
        let cose = encode_minimal_cose_sign1(Some(b"p"));
        let res = cosesign1_validation_verify_signature(cose.as_ptr(), cose.len(), std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}

#[test]
fn options_accept_strings_and_bad_headers_json() {
    unsafe {
        let audience = CString::new("aud").unwrap();
        let issuer = CString::new("iss").unwrap();
        let subject = CString::new("sub").unwrap();
        let kid = CString::new("kid").unwrap();
        let ct = CString::new("application/cose").unwrap();
        let headers_json = CString::new("not-json").unwrap();

        // Not used by this FFI surface; keep alive for basic smoke coverage.
        let _keep_alive = [audience, issuer, subject, kid, ct, headers_json];

        let cose = encode_minimal_cose_sign1(Some(b"p"));
        let res = cosesign1_validation_verify_signature(cose.as_ptr(), cose.len(), std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}

#[test]
fn free_is_safe_on_null() {
    unsafe {
        cosesign1_validation_result_free(std::ptr::null_mut());
    }
}

#[test]
fn verify_signature_with_payload_reader_missing_callbacks_fails_cleanly() {
    unsafe {
        let cose_detached = encode_minimal_cose_sign1(None);

        let reader = cosesign1_reader {
            ctx: std::ptr::null_mut(),
            read: None,
            seek: None,
        };

        let res = cosesign1_validation_verify_signature_with_payload_reader(
            cose_detached.as_ptr(),
            cose_detached.len(),
            reader,
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        assert!(cosesign1_validation_result_failure_count(res) >= 1);
        cosesign1_validation_result_free(res);
    }
}

#[test]
fn verify_signature_exercises_non_null_payload_and_public_key_branches() {
    unsafe {
        let cose_embedded = encode_minimal_cose_sign1(Some(b"hello"));
        let payload = b"hello";
        let public_key = b"not-a-real-public-key";

        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            payload.as_ptr(),
            payload.len(),
            public_key.as_ptr(),
            public_key.len(),
        );
        assert!(!res.is_null());
        assert!(!cosesign1_validation_result_validator_name(res).is_null());
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}

#[test]
fn verify_signature_with_payload_reader_exercises_parse_error_and_non_null_public_key() {
    unsafe {
        let bad = [0x01u8, 0x02u8, 0x03u8];
        let res = cosesign1_validation_verify_signature_with_payload_reader(
            bad.as_ptr(),
            bad.len(),
            cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: None,
                seek: None,
            },
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        assert_eq!(cstr(cosesign1_validation_result_failure_at(res, 0).error_code), "CBOR_PARSE_ERROR");
        cosesign1_validation_result_free(res);

        // Non-null public key branch.
        let cose_detached = encode_minimal_cose_sign1(None);
        let pk = b"pk";
        let res = cosesign1_validation_verify_signature_with_payload_reader(
            cose_detached.as_ptr(),
            cose_detached.len(),
            cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: None,
                seek: None,
            },
            pk.as_ptr(),
            pk.len(),
        );
        assert!(!res.is_null());
        assert!(!cosesign1_validation_result_validator_name(res).is_null());
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}
