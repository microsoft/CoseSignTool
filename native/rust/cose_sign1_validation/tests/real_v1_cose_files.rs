// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

fn v1_testdata_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1")
        .join(file_name)
}

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

#[test]
fn real_v1_cose_file_produces_parts_fact() {
    let cose_path = v1_testdata_path("UnitTestSignatureWithCRL.cose");
    let cose_bytes = fs::read(cose_path).unwrap();

    let engine = TrustFactEngine::new(vec![Arc::new(CoseSign1MessageFactProducer::new())])
        .with_cose_sign1_bytes(Arc::from(cose_bytes.into_boxed_slice()));

    let subject = TrustSubject::message(b"seed");
    let parts = engine
        .get_fact_set::<CoseSign1MessagePartsFact>(&subject)
        .unwrap();

    match parts {
        TrustFactSet::Available(v) => {
            assert_eq!(1, v.len());
            assert!(!v[0].protected_header.is_empty());
            assert!(!v[0].unprotected_header.is_empty());
            assert!(!v[0].signature.is_empty());
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
            .with_signing_key_resolver(Arc::new(AlwaysTrueKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::bytes(Arc::from(
            payload_bytes.into_boxed_slice(),
        )));
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .unwrap();

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());

    // This test is primarily about exercising parsing + pipeline on a "real" file.
    // Signature validation may still fail if the file is malformed; it should never be NotApplicable.
    assert_ne!(ValidationResultKind::NotApplicable, result.signature.kind);
}
