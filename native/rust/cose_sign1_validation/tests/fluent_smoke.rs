// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use std::sync::Arc;

struct NoopProducer;

impl TrustFactProducer for NoopProducer {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn produce(&self, _ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        &[]
    }
}

struct NoopPack;

impl CoseSign1TrustPack for NoopPack {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(NoopProducer)
    }
}

#[test]
fn trust_pack_default_methods_are_well_defined() {
    let pack: &dyn CoseSign1TrustPack = &NoopPack;

    assert!(pack.signing_key_resolvers().is_empty());
    assert!(pack.post_signature_validators().is_empty());
    assert!(pack.default_trust_plan().is_none());
}

#[test]
fn fluent_build_validator_with_policy_constructs_validator() {
    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(NoopPack)];

    let _validator = build_validator_with_policy(packs, |p| p.for_message(|s| s.allow_all()))
        .expect("expected fluent validator build to succeed");
}
