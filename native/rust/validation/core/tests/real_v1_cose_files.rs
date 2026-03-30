// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::CoseSign1Message;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn v1_testdata_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1")
        .join(file_name)
}

struct AlwaysTrueVerifier;

impl CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysTrueKeyResolver;

impl CoseKeyResolver for AlwaysTrueKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(Arc::new(AlwaysTrueVerifier))
    }
}

#[test]
fn real_v1_cose_file_produces_parts_fact() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();

    let parsed = cose_sign1_primitives::CoseSign1Message::parse(&cose_bytes).unwrap();

    let engine = TrustFactEngine::new(vec![Arc::new(CoseSign1MessageFactProducer::new())])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(parsed));

    let subject = TrustSubject::message(b"seed");
    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();

    match parts {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].protected_headers().is_empty());
            // Note: unprotected headers may or may not be empty depending on the test file
            assert!(!v[0].signature().is_empty());
        }
        TrustFactSet::Missing { .. } => panic!("expected Available"),
        TrustFactSet::Error { .. } => panic!("expected Available"),
    }
}

#[test]
fn real_v1_cose_file_runs_validator_pipeline_with_detached_payload() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let payload_path = v1_testdata_path("UnitTestPayload.json");

    let cose_bytes = fs::read(cose_path).unwrap();
    let payload_bytes = fs::read(payload_path).unwrap();

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("always_true_key")
            .with_cose_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Bytes(payload_bytes));
    });

    let result = validator
        .validate_bytes(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());

    // This test is primarily about exercising parsing + pipeline on a "real" file.
    // Signature validation may still fail if the file is malformed; it should never be NotApplicable.
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}
