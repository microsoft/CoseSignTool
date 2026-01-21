use cose_sign1_validation_ffi::*;
use cose_sign1_validation_ffi_mst::*;
use cose_sign1_validation_ffi_trust::*;
use std::ffi::CString;
use std::ptr;

fn cose_sign1_with_dummy_mst_receipt() -> Vec<u8> {
    // COSE_Sign1: [ bstr(a0), { 394: [ bstr("receipt") ] }, null, bstr("sig") ]
    // 394 encodes as uint16: 0x19 0x01 0x8A.
    let mut out = Vec::new();

    out.extend_from_slice(&[0x84]); // array(4)
    out.extend_from_slice(&[0x41, 0xA0]); // bstr(len=1, a0) => protected header bytes = empty map

    out.extend_from_slice(&[0xA1]); // map(1)
    out.extend_from_slice(&[0x19, 0x01, 0x8A]); // key = 394

    out.extend_from_slice(&[0x81]); // array(1)
    out.extend_from_slice(&[0x47]); // bstr(len=7)
    out.extend_from_slice(b"receipt");

    out.extend_from_slice(&[0xF6]); // null payload
    out.extend_from_slice(&[0x43, b's', b'i', b'g']); // bstr("sig")

    out
}

fn run_with_policy(configure: impl FnOnce(*mut cose_trust_policy_builder_t)) {
    let statement_bytes = cose_sign1_with_dummy_mst_receipt();

    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Add MST pack in offline mode (no network); verification should still run and return a fact.
    let opts = cose_mst_trust_options_t {
        allow_network: false,
        offline_jwks_json: ptr::null(),
        jwks_api_version: ptr::null(),
    };
    assert_eq!(cose_validator_builder_with_mst_pack_ex(builder, &opts), cose_status_t::COSE_OK);

    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    configure(policy);

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

    // Validate. The result is expected to be a policy failure (COSE_OK + ok=false), but not an error.
    let mut validator: *mut cose_validator_t = ptr::null_mut();
    assert_eq!(
        cose_validator_builder_build(builder, &mut validator),
        cose_status_t::COSE_OK
    );
    assert!(!validator.is_null());

    let mut result: *mut cose_validation_result_t = ptr::null_mut();
    assert_eq!(
        cose_validator_validate_bytes(
            validator,
            statement_bytes.as_ptr(),
            statement_bytes.len(),
            ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK
    );
    assert!(!result.is_null());

    cose_validation_result_free(result);
    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}

#[test]
fn mst_policy_helpers_are_exercised_during_validation() {
    let issuer = CString::new("example.com").unwrap();
    let kid = CString::new("kid").unwrap();
    let needle = CString::new("needle").unwrap();
    let sha256_hex = CString::new("00".repeat(32)).unwrap();
    let coverage = CString::new("coverage").unwrap();

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_present(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_not_present(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_signature_verified(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_signature_not_verified(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy, needle.as_ptr()),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy, issuer.as_ptr()),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_kid_eq(policy, kid.as_ptr()),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_kid_contains(policy, needle.as_ptr()),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_trusted(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_not_trusted(policy),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
                policy,
                issuer.as_ptr()
            ),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
                policy,
                sha256_hex.as_ptr()
            ),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(
                policy,
                coverage.as_ptr()
            ),
            cose_status_t::COSE_OK
        );
    });

    run_with_policy(|policy| {
        assert_eq!(
            cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(
                policy,
                needle.as_ptr()
            ),
            cose_status_t::COSE_OK
        );
    });
}
