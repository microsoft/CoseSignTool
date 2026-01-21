use cose_sign1_validation_ffi::cose_status_t;
use cose_sign1_validation_ffi_certificates::*;
use cose_sign1_validation_ffi_trust::*;
use std::ffi::CString;
use std::ptr;

fn minimal_cose_sign1() -> Vec<u8> {
    vec![0x84, 0x41, 0xA0, 0xA0, 0xF6, 0x43, b's', b'i', b'g']
}

#[test]
fn certificates_ffi_end_to_end_calls() {
    let mut builder: *mut cose_sign1_validation_ffi::cose_validator_builder_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_builder_new(&mut builder),
        cose_status_t::COSE_OK
    );
    assert!(!builder.is_null());

    // Pack add: default.
    assert_eq!(
        cose_validator_builder_with_certificates_pack(builder),
        cose_status_t::COSE_OK
    );

    // Pack add: custom options (exercise string-array parsing).
    let thumb1 = CString::new("AA:BB:CC").unwrap();
    let thumbprints: [*const i8; 2] = [thumb1.as_ptr(), ptr::null()];
    let oid1 = CString::new("1.2.3.4.5").unwrap();
    let oids: [*const i8; 2] = [oid1.as_ptr(), ptr::null()];
    let opts = cose_certificate_trust_options_t {
        trust_embedded_chain_as_trusted: true,
        identity_pinning_enabled: true,
        allowed_thumbprints: thumbprints.as_ptr(),
        pqc_algorithm_oids: oids.as_ptr(),
    };
    assert_eq!(
        cose_validator_builder_with_certificates_pack_ex(builder, &opts),
        cose_status_t::COSE_OK
    );

    // Pack add: null options => default branch.
    assert_eq!(
        cose_validator_builder_with_certificates_pack_ex(builder, ptr::null()),
        cose_status_t::COSE_OK
    );

    // Create policy builder.
    let mut policy: *mut cose_sign1_validation_ffi::cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // Policy helpers (exercise all exports once).
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_not_trusted(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_built(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_not_built(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_element_count_eq(policy, 1),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_present(policy),
        cose_status_t::COSE_OK
    );

    let subject = CString::new("CN=Subject").unwrap();
    assert_eq!(
        cose_certificates_trust_policy_builder_require_leaf_subject_eq(policy, subject.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_issuer_subject_eq(policy, subject.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_subject_issuer_matches_leaf_chain_element(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_leaf_issuer_is_next_chain_subject_optional(policy),
        cose_status_t::COSE_OK
    );

    let thumb = CString::new("AABBCC").unwrap();
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(policy, thumb.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_subject_eq(policy, subject.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(policy, subject.as_ptr()),
        cose_status_t::COSE_OK
    );

    let serial = CString::new("01").unwrap();
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(policy, serial.as_ptr()),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_valid_at(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_not_before_le(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_not_after_le(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(policy, 0),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_subject_eq(policy, 0, subject.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_issuer_eq(policy, 0, subject.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(policy, 0, thumb.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_thumbprint_present(policy, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_valid_at(policy, 0, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_not_before_le(policy, 0, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_not_before_ge(policy, 0, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_not_after_le(policy, 0, 0),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_chain_element_not_after_ge(policy, 0, 0),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(policy),
        cose_status_t::COSE_OK
    );

    let oid = CString::new("1.2.840.10045.2.1").unwrap();
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(policy, thumb.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(policy, oid.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(policy),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(policy),
        cose_status_t::COSE_OK
    );

    // Compile and attach.
    let mut plan: *mut cose_compiled_trust_plan_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_compile(policy, &mut plan),
        cose_status_t::COSE_OK
    );
    assert!(!plan.is_null());
    cose_trust_policy_builder_free(policy);

    assert_eq!(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        cose_status_t::COSE_OK
    );
    cose_compiled_trust_plan_free(plan);

    // Validate once.
    let mut validator: *mut cose_sign1_validation_ffi::cose_validator_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    let bytes = minimal_cose_sign1();
    let mut result: *mut cose_sign1_validation_ffi::cose_validation_result_t = ptr::null_mut();
    assert_eq!(
        cose_sign1_validation_ffi::cose_validator_validate_bytes(
            validator,
            bytes.as_ptr(),
            bytes.len(),
            ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK
    );
    assert!(!result.is_null());
    cose_sign1_validation_ffi::cose_validation_result_free(result);

    cose_sign1_validation_ffi::cose_validator_free(validator);
    cose_sign1_validation_ffi::cose_validator_builder_free(builder);
}
