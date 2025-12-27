// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_mst::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use std::ffi::{c_char, CStr, CString};

unsafe fn cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

fn find_metadata_value(res: *const cosesign1_mst_result, key: &str) -> Option<String> {
    unsafe {
        let n = cosesign1_mst_result_metadata_count(res);
        for i in 0..n {
            let kv = cosesign1_mst_result_metadata_at(res, i);
            if cstr(kv.key) == key {
                return Some(cstr(kv.value));
            }
        }
        None
    }
}

#[test]
fn mst_keystore_and_jwks_paths_are_exercised() {
    unsafe {
        // Cover null-result getter behavior.
        assert!(!cosesign1_mst_result_is_valid(std::ptr::null()));
        assert!(cosesign1_mst_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_mst_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_mst_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_mst_result_metadata_count(std::ptr::null()), 0);
        let kv = cosesign1_mst_result_metadata_at(std::ptr::null(), 0);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());

        let store = cosesign1_mst_keystore_new();
        assert!(!store.is_null());

        let issuer = CString::new("example.com").unwrap();
        // Provide a valid EC key so the "success" path can add at least one key.
        let sk = p256::ecdsa::SigningKey::from_bytes(&[14u8; 32].into()).expect("sk");
        let vk = sk.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = point.x().expect("x");
        let y = point.y().expect("y");

        let x_b64 = URL_SAFE_NO_PAD.encode(x);
        let y_b64 = URL_SAFE_NO_PAD.encode(y);
        let jwks_json = format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","x":"{x_b64}","y":"{y_b64}","kid":"kid1"}}]}}"#
        );
        let jwks = jwks_json.as_bytes();

        // Null store.
        let res = cosesign1_mst_keystore_add_issuer_jwks(std::ptr::null_mut(), issuer.as_ptr(), jwks.as_ptr(), jwks.len());
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        assert!(!cosesign1_mst_result_validator_name(res).is_null());
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // Null issuer_host.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, std::ptr::null(), jwks.as_ptr(), jwks.len());
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // Null jwks.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), std::ptr::null(), 0);
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // Invalid UTF-8 issuer_host.
        let bad = [0xFFu8, 0x00u8];
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, bad.as_ptr().cast(), jwks.as_ptr(), jwks.len());
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "INVALID_ARGUMENT");
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // Parse error.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), b"not-json".as_ptr(), 8);
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "MST_JWKS_PARSE_ERROR");
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // add_issuer_keys error (JWKS parses but contains invalid base64 key material).
        let bad_jwks = br#"{"keys":[{"kty":"EC","crv":"P-256","x":"!!!!","y":"AAAA","kid":"kid-bad"}]}"#;
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), bad_jwks.as_ptr(), bad_jwks.len());
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "MST_JWKS_ERROR");
        assert_eq!(cosesign1_mst_result_failure_count(res), 1);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        cosesign1_mst_result_free(res);

        // Success.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), jwks.as_ptr(), jwks.len());
        assert!(cosesign1_mst_result_is_valid(res));
        assert!(!cosesign1_mst_result_validator_name(res).is_null());
        assert_eq!(cosesign1_mst_result_failure_count(res), 0);
        let fv = cosesign1_mst_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(find_metadata_value(res, "keysAdded"), Some("1".to_string()));
        let kv = cosesign1_mst_result_metadata_at(res, usize::MAX);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());
        cosesign1_mst_result_free(res);

        cosesign1_mst_keystore_free(store);
    }
}

#[test]
fn mst_verify_transparent_statement_exercises_option_mapping_and_domain_parsing() {
    unsafe {
        let store = cosesign1_mst_keystore_new();

        // Null store.
        let res = cosesign1_mst_verify_transparent_statement(
            std::ptr::null(),
            b"x".as_ptr(),
            1,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        cosesign1_mst_result_free(res);

        // Null statement.
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        cosesign1_mst_result_free(res);

        // Invalid authorized behavior.
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"x".as_ptr(),
            1,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 999,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "INVALID_ARGUMENT");
        cosesign1_mst_result_free(res);

        // Invalid unauthorized behavior.
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"x".as_ptr(),
            1,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 999,
            },
        );
        assert_eq!(cstr(cosesign1_mst_result_failure_at(res, 0).error_code), "INVALID_ARGUMENT");
        cosesign1_mst_result_free(res);

        // Domain parsing path.
        let d1 = CString::new("example.com").unwrap();
        let domains = [
            cosesign1_string_view { data: std::ptr::null() },
            cosesign1_string_view { data: d1.as_ptr() },
        ];
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"not-a-cose".as_ptr(),
            10,
            domains.as_ptr(),
            domains.len(),
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert!(!res.is_null());
        assert!(!cosesign1_mst_result_validator_name(res).is_null());
        cosesign1_mst_result_free(res);

        cosesign1_mst_keystore_free(store);
    }
}
