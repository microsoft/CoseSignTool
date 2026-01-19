// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::{
    CoseSign1MessageFactProducer, CoseSign1MessagePartsFact, CoseSign1TrustPack,
    CoseSign1ValidationOptions, CoseSign1Validator, SigningKey, SigningKeyResolutionResult,
    SigningKeyResolver, SimpleTrustPack, TrustPlanBuilder,
};
use cose_sign1_validation_transparent_mst::fluent_ext::MstCounterSignatureScopeRulesExt;
use cose_sign1_validation_transparent_mst::pack::{MstTrustPack, MST_RECEIPT_HEADER_LABEL};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct TestSigningKey;

impl SigningKey for TestSigningKey {
    fn key_type(&self) -> &'static str {
        "TestSigningKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct TestSigningKeyResolver;

impl SigningKeyResolver for TestSigningKeyResolver {
    fn resolve(
        &self,
        _message: &cose_sign1_validation::CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult {
            is_success: true,
            signing_key: Some(Arc::new(TestSigningKey)),
            candidate_keys: Vec::new(),
            key_id: None,
            thumbprint: None,
            diagnostics: Vec::new(),
            error_code: None,
            error_message: None,
        }
    }
}

fn build_cose_sign1_with_unprotected_receipts(receipts: Option<&[&[u8]]>) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: map
    match receipts {
        None => {
            enc.map(0).unwrap();
        }
        Some(receipts) => {
            enc.map(1).unwrap();
            MST_RECEIPT_HEADER_LABEL.encode(&mut enc).unwrap();
            enc.array(receipts.len()).unwrap();
            for r in receipts {
                r.encode(&mut enc).unwrap();
            }
        }
    }

    // payload: embedded bstr
    b"payload".as_slice().encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn message_fact_producer_produces_parts_fact() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");
    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();

    match parts {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].protected_header.is_empty());
            assert!(!v[0].unprotected_header.is_empty());
            assert_eq!(b"sig".as_slice(), v[0].signature.as_slice());
        }
        _ => panic!("expected Available"),
    }
}

#[test]
fn validator_orchestrates_trust_plan_over_primary_signing_key() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(
            SimpleTrustPack::no_facts("test_signing_key_resolver")
                .with_signing_key_resolver(Arc::new(TestSigningKeyResolver)),
        ),
        Arc::new(MstTrustPack {
            offline_jwks_json: None,
            allow_network: false,
            jwks_api_version: None,
        }),
    ];

    let bundled_plan = TrustPlanBuilder::new(trust_packs)
        .for_counter_signature(|cs| cs.require_mst_receipt_present())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled_plan);

    let result = validator
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
    assert!(result.overall.is_valid());
}
