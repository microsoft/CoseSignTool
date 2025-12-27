// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

#[test]
fn mst_ffi_functions_are_exercised_for_coverage() {
    unsafe {
        // Null-result getters.
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

        // Null free is ok.
        cosesign1_mst_result_free(std::ptr::null_mut());
        cosesign1_mst_keystore_free(std::ptr::null_mut());

        // Keystore lifecycle.
        let store = cosesign1_mst_keystore_new();
        assert!(!store.is_null());

        // add_issuer_jwks NULL_ARGUMENT.
        let issuer = std::ffi::CString::new("issuer.example").unwrap();
        let jwks = b"{}";
        let res = cosesign1_mst_keystore_add_issuer_jwks(std::ptr::null_mut(), issuer.as_ptr(), jwks.as_ptr(), jwks.len());
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        let res = cosesign1_mst_keystore_add_issuer_jwks(store, std::ptr::null(), jwks.as_ptr(), jwks.len());
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), std::ptr::null(), 0);
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // invalid UTF-8 issuer.
        let bad_issuer = [0xffu8, 0x00u8];
        let res = cosesign1_mst_keystore_add_issuer_jwks(
            store,
            bad_issuer.as_ptr().cast(),
            b"{\"keys\":[]}".as_ptr(),
            11,
        );
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // add_issuer_jwks parse error.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), b"not-json".as_ptr(), 8);
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // add_issuer_jwks success path + metadata access.
        let res = cosesign1_mst_keystore_add_issuer_jwks(store, issuer.as_ptr(), b"{\"keys\":[]}".as_ptr(), 11);
        assert!(cosesign1_mst_result_is_valid(res));
        assert!(!cosesign1_mst_result_validator_name(res).is_null());
        assert_eq!(cosesign1_mst_result_failure_count(res), 0);
        assert_eq!(cosesign1_mst_result_metadata_count(res), 1);
        let kv = cosesign1_mst_result_metadata_at(res, 0);
        assert!(!kv.key.is_null());
        assert!(!kv.value.is_null());
        let fv = cosesign1_mst_result_failure_at(res, 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        let kv = cosesign1_mst_result_metadata_at(res, 999);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());
        cosesign1_mst_result_free(res);

        // Store null path.
        let res = cosesign1_mst_verify_transparent_statement(
            std::ptr::null(),
            b"".as_ptr(),
            0,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // Transparent statement pointer null.
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
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // Invalid behaviors.
        let opt_bad = cosesign1_mst_verification_options {
            authorized_receipt_behavior: 999,
            unauthorized_receipt_behavior: 0,
        };
        let res = cosesign1_mst_verify_transparent_statement(store, b"".as_ptr(), 0, std::ptr::null(), 0, opt_bad);
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        let opt_bad = cosesign1_mst_verification_options {
            authorized_receipt_behavior: 0,
            unauthorized_receipt_behavior: 999,
        };
        let res = cosesign1_mst_verify_transparent_statement(store, b"".as_ptr(), 0, std::ptr::null(), 0, opt_bad);
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // Authorized domains parsing loop (null entry + valid string).
        let domain = std::ffi::CString::new("example.com").unwrap();
        let domains = [
            cosesign1_string_view {
                data: std::ptr::null(),
            },
            cosesign1_string_view {
                data: domain.as_ptr(),
            },
        ];
        let opt = cosesign1_mst_verification_options {
            authorized_receipt_behavior: 0,
            unauthorized_receipt_behavior: 0,
        };
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"garbage".as_ptr(),
            7,
            domains.as_ptr(),
            domains.len(),
            opt,
        );
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // authorized_domains pointer is null (skips the loop).
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"garbage".as_ptr(),
            7,
            std::ptr::null(),
            0,
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        // Invalid UTF-8 domain entry (to_str() fails, entry is skipped).
        let bad_domain = [0xffu8, 0x00u8];
        let domains = [cosesign1_string_view {
            data: bad_domain.as_ptr().cast(),
        }];
        let res = cosesign1_mst_verify_transparent_statement(
            store,
            b"garbage".as_ptr(),
            7,
            domains.as_ptr(),
            domains.len(),
            cosesign1_mst_verification_options {
                authorized_receipt_behavior: 0,
                unauthorized_receipt_behavior: 0,
            },
        );
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        cosesign1_mst_keystore_free(store);
    }
}
