// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;

use cosesign1_x509::*;

#[test]
fn x509_ffi_smoke_covers_result_helpers_and_argument_checks() {
    unsafe {
        // Null-result getters.
        assert!(!cosesign1_x509_result_is_valid(std::ptr::null()));
        assert!(cosesign1_x509_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_x509_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_x509_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_x509_result_metadata_count(std::ptr::null()), 0);

        cosesign1_x509_result_free(std::ptr::null_mut());

        // Non-null result getters + in-range and out-of-range.
        let mut vr = ValidationResult::failure_message("x5c_chain", "oops", Some("SOME_CODE".to_string()));
        vr.metadata.insert("k".to_string(), "v".to_string());
        let res = Box::into_raw(Box::new(base_result::from_validation_result(vr)));
        assert!(!cosesign1_x509_result_validator_name(res).is_null());
        assert_eq!(cosesign1_x509_result_failure_count(res), 1);
        assert!(!cosesign1_x509_result_failure_at(res, 0).message.is_null());
        assert!(cosesign1_x509_result_failure_at(res, 999).message.is_null());
        assert_eq!(cosesign1_x509_result_metadata_count(res), 1);
        assert!(!cosesign1_x509_result_metadata_at(res, 0).key.is_null());
        assert!(cosesign1_x509_result_metadata_at(res, 999).key.is_null());
        cosesign1_x509_result_free(res);

        // NULL_ARGUMENT for certs.
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
        cosesign1_x509_result_free(res);

        // INVALID_ARGUMENT for trust_mode.
        let certs = [cosesign1_byte_view {
            data: b"x".as_ptr(),
            len: 1,
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            std::ptr::null(),
            0,
            cosesign1_x509_chain_options {
                trust_mode: 999,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        cosesign1_x509_result_free(res);

        // cert entry pointer null.
        let certs = [cosesign1_byte_view {
            data: std::ptr::null(),
            len: 0,
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
        cosesign1_x509_result_free(res);

        // trusted root entry pointer null.
        let certs = [cosesign1_byte_view {
            data: b"x".as_ptr(),
            len: 1,
        }];
        let roots = [cosesign1_byte_view {
            data: std::ptr::null(),
            len: 0,
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            roots.as_ptr(),
            roots.len(),
            cosesign1_x509_chain_options {
                trust_mode: 1,
                revocation_mode: 0,
                allow_untrusted_roots: false,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        cosesign1_x509_result_free(res);

        // INVALID_ARGUMENT for revocation_mode.
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
        cosesign1_x509_result_free(res);

        // Drive the core verification call (expected to fail for dummy DER), but executes the happy-path mapping.
        let roots = [cosesign1_byte_view {
            data: b"r".as_ptr(),
            len: 1,
        }];
        let res = cosesign1_x509_validate_x5c_chain(
            certs.as_ptr(),
            certs.len(),
            roots.as_ptr(),
            roots.len(),
            cosesign1_x509_chain_options {
                trust_mode: 1,
                revocation_mode: 2,
                allow_untrusted_roots: true,
            },
        );
        assert!(!cosesign1_x509_result_is_valid(res));
        cosesign1_x509_result_free(res);
    }
}
