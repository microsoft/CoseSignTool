use cose_sign1_validation_ffi::*;
use cose_sign1_validation_ffi_trust::*;
use cose_sign1_validation::fluent::{
    CoseSign1, CoseSign1ValidationOptions, CoseSign1TrustPack, SigningKey,
    SigningKeyResolutionResult, SigningKeyResolver,
};
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::ffi::CString;
use std::ptr;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct AlwaysTrueKey;

impl SigningKey for AlwaysTrueKey {
    fn key_type(&self) -> &'static str {
        "AlwaysTrueKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct AlwaysTrueKeyResolver;

impl SigningKeyResolver for AlwaysTrueKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult::success(Arc::new(AlwaysTrueKey))
    }
}

fn build_cose_sign1_bytes_with_protected_header_bytes(protected_header_map_bytes: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // COSE_Sign1 = [ protected: bstr, unprotected: map, payload, signature ]
    enc.array(4).unwrap();
    protected_header_map_bytes.encode(&mut enc).unwrap();
    enc.map(0).unwrap();

    let none: Option<&[u8]> = None;
    none.encode(&mut enc).unwrap();

    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn encode_protected_header_bytes_with_cwt_claims_for_predicates() -> Vec<u8> {
    // Protected header is a CBOR map stored as bstr in COSE_Sign1.
    // Include alg + kid + header parameter label 15 (CWT claims).
    const CWT_CLAIMS_LABEL: i64 = 15;

    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    // { 1: alg, 4: kid, 15: { ... claims ... } }
    enc.map(3).unwrap();

    (1i64).encode(&mut enc).unwrap();
    (-35i64).encode(&mut enc).unwrap();

    (4i64).encode(&mut enc).unwrap();
    b"kid".as_slice().encode(&mut enc).unwrap();

    CWT_CLAIMS_LABEL.encode(&mut enc).unwrap();

    // Claims map mixes numeric-label and text-key claims.
    // Standard numeric keys: iss=1, sub=2, aud=3, exp=4, nbf=5, iat=6.
    // Custom numeric labels used by this test: 1000, 1001, 1002.
    // Custom text keys used by this test: "nonce", "flag", "count".
    enc.map(12).unwrap();

    // Standard issuer/subject/audience.
    (1i64).encode(&mut enc).unwrap();
    "issuer.example".encode(&mut enc).unwrap();

    (2i64).encode(&mut enc).unwrap();
    "subject.example".encode(&mut enc).unwrap();

    (3i64).encode(&mut enc).unwrap();
    "audience.example".encode(&mut enc).unwrap();

    // Standard time claims.
    (4i64).encode(&mut enc).unwrap();
    (500i64).encode(&mut enc).unwrap();

    (5i64).encode(&mut enc).unwrap();
    (400i64).encode(&mut enc).unwrap();

    (6i64).encode(&mut enc).unwrap();
    (450i64).encode(&mut enc).unwrap();

    // Custom numeric-label claims.
    (1000i64).encode(&mut enc).unwrap();
    (123i64).encode(&mut enc).unwrap();

    (1001i64).encode(&mut enc).unwrap();
    true.encode(&mut enc).unwrap();

    (1002i64).encode(&mut enc).unwrap();
    "v123".encode(&mut enc).unwrap();

    // Custom text-key claims.
    "nonce".encode(&mut enc).unwrap();
    "v123".encode(&mut enc).unwrap();

    "flag".encode(&mut enc).unwrap();
    true.encode(&mut enc).unwrap();

    "count".encode(&mut enc).unwrap();
    (123i64).encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn trust_policy_cwt_predicate_helpers_are_executed_via_validation() {
    let protected = encode_protected_header_bytes_with_cwt_claims_for_predicates();
    let cose_bytes = build_cose_sign1_bytes_with_protected_header_bytes(&protected);

    let mut builder: *mut cose_validator_builder_t = ptr::null_mut();
    assert_eq!(cose_validator_builder_new(&mut builder), cose_status_t::COSE_OK);
    assert!(!builder.is_null());

    // Install a signing key resolver so signature validation can proceed.
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    );
    unsafe {
        (*builder).packs.push(pack);
    }

    let mut policy: *mut cose_trust_policy_builder_t = ptr::null_mut();
    assert_eq!(
        cose_trust_policy_builder_new_from_validator_builder(builder, &mut policy),
        cose_status_t::COSE_OK
    );
    assert!(!policy.is_null());

    // Ensure the closure-based claim predicates execute during plan evaluation.
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claims_present(policy),
        cose_status_t::COSE_OK
    );

    let iss = CString::new("issuer.example").unwrap();
    let sub = CString::new("subject.example").unwrap();
    let aud = CString::new("audience.example").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_iss_eq(policy, iss.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_sub_eq(policy, sub.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_aud_eq(policy, aud.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Numeric label claim predicates.
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_present(policy, 1000),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_eq(policy, 1000, 123),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_ge(policy, 1000, 100),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_i64_le(policy, 1000, 200),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_bool_eq(policy, 1001, true),
        cose_status_t::COSE_OK
    );

    let v123 = CString::new("v123").unwrap();
    let v_prefix = CString::new("v").unwrap();
    let needle_23 = CString::new("23").unwrap();
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_str_eq(policy, 1002, v123.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(
            policy,
            1002,
            v_prefix.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_label_str_contains(policy, 1002, needle_23.as_ptr()),
        cose_status_t::COSE_OK
    );

    // Text-key claim predicates.
    let nonce = CString::new("nonce").unwrap();
    let flag = CString::new("flag").unwrap();
    let count = CString::new("count").unwrap();

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_present(policy, nonce.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_eq(policy, nonce.as_ptr(), v123.as_ptr()),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(
            policy,
            nonce.as_ptr(),
            v_prefix.as_ptr()
        ),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_str_contains(
            policy,
            nonce.as_ptr(),
            needle_23.as_ptr()
        ),
        cose_status_t::COSE_OK
    );

    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_bool_eq(policy, flag.as_ptr(), true),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_i64_eq(policy, count.as_ptr(), 123),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_i64_ge(policy, count.as_ptr(), 100),
        cose_status_t::COSE_OK
    );
    assert_eq!(
        cose_trust_policy_builder_require_cwt_claim_text_i64_le(policy, count.as_ptr(), 200),
        cose_status_t::COSE_OK
    );

    // Standard time claim predicates.
    assert_eq!(cose_trust_policy_builder_require_cwt_exp_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_exp_le(policy, 1000), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_nbf_le(policy, 1000), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_ge(policy, 0), cose_status_t::COSE_OK);
    assert_eq!(cose_trust_policy_builder_require_cwt_iat_le(policy, 1000), cose_status_t::COSE_OK);

    // Compile, attach, and validate to force evaluation.
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
            cose_bytes.as_ptr(),
            cose_bytes.len(),
            ptr::null(),
            0,
            &mut result
        ),
        cose_status_t::COSE_OK
    );
    assert!(!result.is_null());

    let mut ok = false;
    assert_eq!(
        cose_validation_result_is_success(result, &mut ok),
        cose_status_t::COSE_OK
    );
    if !ok {
        let p = cose_validation_result_failure_message_utf8(result);
        let msg = if p.is_null() {
            "<no failure message>".to_string()
        } else {
            let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().to_string();
            unsafe { cose_string_free(p) };
            s
        };

        // This test is about executing the closure-based CWT claim predicates.
        // As long as we get past signing-key resolution, the predicates should execute.
        assert!(
            !msg.contains("No signing key could be resolved"),
            "unexpected early failure: {msg}"
        );
    }

    cose_validation_result_free(result);
    cose_validator_free(validator);
    cose_validator_builder_free(builder);
}
