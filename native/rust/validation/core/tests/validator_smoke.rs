// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_transparent_mst::validation::fluent_ext::MstCounterSignatureScopeRulesExt;
use cose_sign1_transparent_mst::validation::pack::{MstTrustPack, MST_RECEIPT_HEADER_LABEL};
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::CoseSign1Message;
use std::sync::Arc;

struct TestVerifier;

impl CryptoVerifier for TestVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct TestCoseKeyResolver;

impl CoseKeyResolver for TestCoseKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult {
            is_success: true,
            cose_key: Some(Arc::new(TestVerifier)),
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
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: map
    match receipts {
        None => {
            enc.encode_map(0).unwrap();
        }
        Some(receipts) => {
            enc.encode_map(1).unwrap();
            enc.encode_i64(MST_RECEIPT_HEADER_LABEL).unwrap();
            enc.encode_array(receipts.len()).unwrap();
            for r in receipts {
                enc.encode_bstr(r).unwrap();
            }
        }
    }

    // payload: embedded bstr
    enc.encode_bstr(b"payload").unwrap();

    // signature: b"sig"
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

#[test]
fn message_fact_producer_produces_parts_fact() {
    let receipts: [&[u8]; 1] = [b"r1".as_slice()];
    let cose = build_cose_sign1_with_unprotected_receipts(Some(&receipts));

    let parsed = cose_sign1_primitives::CoseSign1Message::parse(&cose).unwrap();

    let producer = Arc::new(CoseSign1MessageFactProducer::new());
    let engine = TrustFactEngine::new(vec![producer])
        .with_cose_sign1_bytes(Arc::from(cose.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();

    match parts {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].protected_headers().is_empty());
            assert!(!v[0].unprotected().is_empty());
            assert_eq!(b"sig".as_slice(), v[0].signature());
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
                .with_cose_key_resolver(Arc::new(TestCoseKeyResolver)),
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
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
    assert!(result.overall.is_valid());
}
