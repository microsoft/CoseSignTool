// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_mst::*;

#[test]
fn mst_ffi_smoke_covers_result_helpers_and_argument_checks() {
    unsafe {
        // Null-result getters.
        assert!(!cosesign1_mst_result_is_valid(std::ptr::null()));
        assert!(cosesign1_mst_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_mst_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_mst_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_mst_result_metadata_count(std::ptr::null()), 0);

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
        assert_eq!(cosesign1_mst_result_metadata_count(res), 1);
        let kv = cosesign1_mst_result_metadata_at(res, 0);
        assert!(!kv.key.is_null());
        assert!(!kv.value.is_null());
        let kv = cosesign1_mst_result_metadata_at(res, 999);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());
        cosesign1_mst_result_free(res);

        // Store null path.
        let opt = cosesign1_mst_verification_options {
            authorized_receipt_behavior: 0,
            unauthorized_receipt_behavior: 0,
        };
        let res = cosesign1_mst_verify_transparent_statement(std::ptr::null(), b"".as_ptr(), 0, std::ptr::null(), 0, opt);
        assert!(!cosesign1_mst_result_is_valid(res));
        cosesign1_mst_result_free(res);

        cosesign1_mst_keystore_free(store);
    }
}
