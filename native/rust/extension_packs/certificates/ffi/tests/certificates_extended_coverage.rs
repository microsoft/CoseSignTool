// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extended comprehensive test coverage for certificates FFI.
//!
//! Targets remaining uncovered lines (45 uncov) by extending existing coverage with:
//! - Additional FFI function paths
//! - Error condition testing
//! - Null safety validation
//! - Trust pack option combinations
//! - Policy builder edge cases

use cose_sign1_certificates_ffi::*;
use cose_sign1_validation_ffi::cose_status_t;
use cose_sign1_validation_primitives_ffi::*;
use std::ffi::CString;
use std::ptr;

fn create_mock_trust_options() -> cose_certificate_trust_options_t {
    let thumb1 = CString::new("11:22:33:44:55").unwrap();
    let thumb2 = CString::new("AA:BB:CC:DD:EE").unwrap();
    let thumbprints: [*const i8; 3] = [thumb1.as_ptr(), thumb2.as_ptr(), ptr::null()];

    let oid1 = CString::new("1.2.840.10045.4.3.2").unwrap(); // ECDSA with SHA-256
    let oid2 = CString::new("1.3.101.112").unwrap(); // Ed25519
    let oids: [*const i8; 3] = [oid1.as_ptr(), oid2.as_ptr(), ptr::null()];

    cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: true,
        allowed_thumbprints: thumbprints.as_ptr(),
        pqc_algorithm_oids: oids.as_ptr(),
    }
}

#[test]
fn test_certificate_trust_options_combinations() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );
    assert!(!builder.is_null());

    // Test with trust_embedded_chain_as_trusted = false
    let thumb = CString::new("11:22:33").unwrap();
    let thumbprints: [*const i8; 2] = [thumb.as_ptr(), ptr::null()];
    let oid = CString::new("1.2.3").unwrap();
    let oids: [*const i8; 2] = [oid.as_ptr(), ptr::null()];

    let opts_no_trust = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: false, // Test false path
        identity_pinning_enabled: true,
        allowed_thumbprints: thumbprints.as_ptr(),
        pqc_algorithm_oids: oids.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts_no_trust),
        cose_status_t::COSE_OK
    );

    // Test with identity_pinning_enabled = false
    let opts_no_pinning = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: false, // Test false path
        allowed_thumbprints: thumbprints.as_ptr(),
        pqc_algorithm_oids: oids.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts_no_pinning),
        cose_status_t::COSE_OK
    );

    // Test with empty arrays
    let empty_thumbprints: [*const i8; 1] = [ptr::null()];
    let empty_oids: [*const i8; 1] = [ptr::null()];

    let opts_empty = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: true,
        allowed_thumbprints: empty_thumbprints.as_ptr(),
        pqc_algorithm_oids: empty_oids.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts_empty),
        cose_status_t::COSE_OK
    );

    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_certificate_trust_options_null_arrays() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    // Test with null arrays
    let opts_null_arrays = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: true,
        allowed_thumbprints: ptr::null(), // Test null array
        pqc_algorithm_oids: ptr::null(),  // Test null array
    };

    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts_null_arrays),
        cose_status_t::COSE_OK
    );

    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_policy_builder_null_safety() {
    // Test policy builder functions with null policy pointer
    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(ptr::null_mut()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_chain_not_trusted(ptr::null_mut()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_chain_built(ptr::null_mut()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_chain_not_built(ptr::null_mut()),
        cose_status_t::COSE_OK
    );

    let test_str = CString::new("test").unwrap();
    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_leaf_subject_eq(
            ptr::null_mut(),
            test_str.as_ptr()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_issuer_subject_eq(
            ptr::null_mut(),
            test_str.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
}

#[test]
fn test_policy_builder_null_string_parameters() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test policy functions with null string parameters
    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_leaf_subject_eq(policy, ptr::null()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_issuer_subject_eq(policy, ptr::null()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(
            policy,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_signing_certificate_subject_eq(
            policy,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(
            policy,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(
            policy,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_chain_element_policy_functions() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=Test Chain Element").unwrap();
    let thumb = CString::new("FEDCBA9876543210").unwrap();

    // Test chain element functions with various indices
    for index in [0, 1, 5, 10] {
        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_chain_element_subject_eq(
                policy,
                index,
                subject.as_ptr()
            ),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_chain_element_issuer_eq(
                policy,
                index,
                subject.as_ptr()
            ),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
                policy,
                index,
                thumb.as_ptr()
            ),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_chain_element_thumbprint_present(
                policy, index
            ),
            cose_status_t::COSE_OK
        );

        // Test with various timestamps
        for timestamp in [0, 1640995200, 2000000000] {
            assert_eq!(
                cose_sign1_certificates_trust_policy_builder_require_chain_element_valid_at(
                    policy, index, timestamp
                ),
                cose_status_t::COSE_OK
            );

            assert_eq!(
                cose_sign1_certificates_trust_policy_builder_require_chain_element_not_before_le(
                    policy, index, timestamp
                ),
                cose_status_t::COSE_OK
            );

            assert_eq!(
                cose_sign1_certificates_trust_policy_builder_require_chain_element_not_before_ge(
                    policy, index, timestamp
                ),
                cose_status_t::COSE_OK
            );

            assert_eq!(
                cose_sign1_certificates_trust_policy_builder_require_chain_element_not_after_le(
                    policy, index, timestamp
                ),
                cose_status_t::COSE_OK
            );

            assert_eq!(
                cose_sign1_certificates_trust_policy_builder_require_chain_element_not_after_ge(
                    policy, index, timestamp
                ),
                cose_status_t::COSE_OK
            );
        }
    }

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_chain_element_policy_null_strings() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test chain element functions with null string parameters
    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_chain_element_subject_eq(
            policy,
            0,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_chain_element_issuer_eq(
            policy,
            0,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
            policy,
            0,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_x509_public_key_algorithm_functions() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    let thumb = CString::new("1234567890ABCDEF").unwrap();
    let oid = CString::new("1.2.840.10045.2.1").unwrap(); // EC public key

    // Test all public key algorithm functions
    assert_eq!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(policy, thumb.as_ptr()),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
            policy,
            oid.as_ptr()
        ),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(
            policy
        ),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(
            policy
        ),
        cose_status_t::COSE_OK
    );

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_x509_public_key_algorithm_null_params() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test with null string parameters
    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(policy, ptr::null()),
        cose_status_t::COSE_OK
    );

    assert_ne!(
        cose_sign1_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
            policy,
            ptr::null()
        ),
        cose_status_t::COSE_OK
    );

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_multiple_pack_additions() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    // Add certificates pack multiple times with different options
    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack(builder),
        cose_status_t::COSE_OK
    );

    let opts1 = create_mock_trust_options();
    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts1),
        cose_status_t::COSE_OK
    );

    let opts2 = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: false,
        identity_pinning_enabled: false,
        allowed_thumbprints: ptr::null(),
        pqc_algorithm_oids: ptr::null(),
    };
    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &opts2),
        cose_status_t::COSE_OK
    );

    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_cose_sign1_certificates_key_from_cert_der_zero_length() {
    let test_cert = b"test";
    let mut key: *mut cose_sign1_primitives_ffi::types::CoseKeyHandle = ptr::null_mut();

    // Test with zero length
    let status = cose_sign1_certificates_key_from_cert_der(
        test_cert.as_ptr(),
        0, // Zero length
        &mut key,
    );

    // Should fail with zero length
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn test_timestamp_edge_cases() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test with edge case timestamps
    let edge_timestamps = [
        i64::MIN,
        -1,
        0,
        1,
        1640995200, // Jan 1, 2022
        i64::MAX,
    ];

    for timestamp in edge_timestamps {
        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_signing_certificate_valid_at(
                policy, timestamp
            ),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(policy, timestamp),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_before_le(
                policy, timestamp
            ),
            cose_status_t::COSE_OK
        );

        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(
                policy, timestamp
            ),
            cose_status_t::COSE_OK
        );
    }

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_chain_element_count_edge_cases() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test with various chain element counts
    let counts = [0, 1, 2, 5, 10, 100, usize::MAX];

    for count in counts {
        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_x509_chain_element_count_eq(
                policy, count
            ),
            cose_status_t::COSE_OK
        );
    }

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_status_flags_edge_cases() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );

    // Test with various status flag values
    let flags = [0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF, u32::MAX];

    for flag_value in flags {
        assert_eq!(
            cose_sign1_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(
                policy, flag_value
            ),
            cose_status_t::COSE_OK
        );
    }

    cose_sign1_trust_policy_builder_free(policy);
    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}

#[test]
fn test_comprehensive_string_array_parsing() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_sign1_validator_builder_t =
        ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_sign1_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );

    // Test with long string arrays
    let thumbs: Vec<CString> = (0..10)
        .map(|i| CString::new(format!("thumb_{:02X}:{:02X}:{:02X}", i, i + 1, i + 2)).unwrap())
        .collect();
    let thumb_ptrs: Vec<*const i8> = thumbs
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();

    let oids: Vec<CString> = (0..5)
        .map(|i| CString::new(format!("1.2.3.4.{}", i)).unwrap())
        .collect();
    let oid_ptrs: Vec<*const i8> = oids
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(ptr::null()))
        .collect();

    let comprehensive_opts = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: true,
        allowed_thumbprints: thumb_ptrs.as_ptr(),
        pqc_algorithm_oids: oid_ptrs.as_ptr(),
    };

    assert_eq!(
        cose_sign1_validator_builder_with_certificates_pack_ex(builder, &comprehensive_opts),
        cose_status_t::COSE_OK
    );

    cose_sign1_validation_ffi::cose_sign1_validator_builder_free(builder);
}
