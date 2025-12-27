// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_x509::*;
use std::ffi::{c_char, CStr};

unsafe fn cstr(ptr: *const c_char) -> String {
    if ptr.is_null() {
        return String::new();
    }
    CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

#[test]
fn x509_validate_x5c_chain_exercises_error_paths() {
    unsafe {
        // Cover test helper null handling.
        assert_eq!(cstr(std::ptr::null()), "");

        // Null certs.
        let res = cosesign1_x509_validate_x5c_chain(
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            cosesign1_x509_chain_options {
                trust_mode: 0,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        assert_eq!(cstr(cosesign1_x509_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");

        // Cover getters on a real result (including out-of-range).
        assert!(!cosesign1_x509_result_validator_name(res).is_null());
        assert!(cosesign1_x509_result_failure_count(res) >= 1);
        assert_eq!(cosesign1_x509_result_metadata_count(res), 0);
        let fv = cosesign1_x509_result_failure_at(res, usize::MAX);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        let kv = cosesign1_x509_result_metadata_at(res, usize::MAX);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());

        // Cover null getter behavior.
        assert!(!cosesign1_x509_result_is_valid(std::ptr::null()));
        assert!(cosesign1_x509_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_x509_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_x509_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_x509_result_metadata_count(std::ptr::null()), 0);
        let kv = cosesign1_x509_result_metadata_at(std::ptr::null(), 0);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());

        cosesign1_x509_result_free(res);

        // Cert entry pointer null.
        let certs = [cosesign1_byte_view {
            data: std::ptr::null(),
            len: 1,
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            std::ptr::null(),
            0,
            cosesign1_x509_chain_options {
                trust_mode: 0,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        assert_eq!(cstr(cosesign1_x509_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        cosesign1_x509_result_free(res);

        // Trusted roots: exercise non-null roots slice and root entry null.
        let cert_bytes = vec![0u8];
        let certs = [cosesign1_byte_view {
            data: cert_bytes.as_ptr(),
            len: cert_bytes.len(),
        }];
        let roots = [cosesign1_byte_view {
            data: std::ptr::null(),
            len: 1,
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            roots.as_ptr(),
            roots.len(),
            cosesign1_x509_chain_options {
                trust_mode: 0,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert_eq!(cstr(cosesign1_x509_result_failure_at(res, 0).error_code), "NULL_ARGUMENT");
        cosesign1_x509_result_free(res);

        // Trusted roots: exercise root parsing + options assignment + call into validator.
        let root_bytes = vec![0u8];
        let roots = [cosesign1_byte_view {
            data: root_bytes.as_ptr(),
            len: root_bytes.len(),
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            roots.as_ptr(),
            roots.len(),
            cosesign1_x509_chain_options {
                trust_mode: 1,
                revocation_mode: 0,
                allow_untrusted_roots: true,
            },
        );
        assert!(!res.is_null());
        // Expect invalid because cert/root are not real DER, but the path is exercised.
        assert!(!cosesign1_x509_result_is_valid(res));
        cosesign1_x509_result_free(res);

        // Invalid trust mode.
        let cert_bytes = vec![0u8];
        let certs = [cosesign1_byte_view {
            data: cert_bytes.as_ptr(),
            len: cert_bytes.len(),
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            std::ptr::null(),
            0,
            cosesign1_x509_chain_options {
                trust_mode: 123,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        assert_eq!(cstr(cosesign1_x509_result_failure_at(res, 0).error_code), "INVALID_ARGUMENT");
        cosesign1_x509_result_free(res);

        // Invalid revocation mode.
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            std::ptr::null(),
            0,
            cosesign1_x509_chain_options {
                trust_mode: 0,
                revocation_mode: 999,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        assert_eq!(cstr(cosesign1_x509_result_failure_at(res, 0).error_code), "INVALID_ARGUMENT");
        cosesign1_x509_result_free(res);

        // Null getters.
        assert!(!cosesign1_x509_result_is_valid(std::ptr::null()));
        assert!(cosesign1_x509_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_x509_result_failure_count(std::ptr::null()), 0);
        assert_eq!(cosesign1_x509_result_metadata_count(std::ptr::null()), 0);
        let f = cosesign1_x509_result_failure_at(std::ptr::null(), 0);
        assert!(f.message.is_null());
        let kv = cosesign1_x509_result_metadata_at(std::ptr::null(), 0);
        assert!(kv.key.is_null());
    }
}
