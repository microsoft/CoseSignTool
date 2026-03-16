// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_azure_artifact_signing::validation::{AasFactProducer, AzureArtifactSigningTrustPack};
use cose_sign1_azure_artifact_signing::validation::facts::AasSigningServiceIdentifiedFact;
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::{
    facts::{TrustFactProducer, TrustFactEngine},
    subject::TrustSubject,
};
use std::sync::Arc;

#[test]
fn test_ats_fact_producer_name() {
    let producer = AasFactProducer;
    assert_eq!(producer.name(), "azure_artifact_signing");
}

#[test]
fn test_ats_fact_producer_provides() {
    let producer = AasFactProducer;
    let provided = producer.provides();
    // Now returns registered fact keys for AAS detection
    assert_eq!(provided.len(), 2);
}

#[test]
fn test_ats_fact_producer_produce() {
    let producer = AasFactProducer;
    
    // Create a proper fact engine with our producer
    let engine = TrustFactEngine::new(vec![Arc::new(producer) as Arc<dyn TrustFactProducer>]);
    let subject = TrustSubject::message(b"test");
    
    // Try to get facts - this will trigger the producer
    let result = engine.get_facts::<AasSigningServiceIdentifiedFact>(&subject);
    // The producer should run without error, though it may not produce facts
    // since we don't have real COSE message data
    assert!(result.is_ok());
}

#[test]
fn test_azure_artifact_signing_trust_pack_new() {
    let trust_pack = AzureArtifactSigningTrustPack::new();
    
    // Test trait implementations
    assert_eq!(trust_pack.name(), "azure_artifact_signing");
    
    let fact_producer = trust_pack.fact_producer();
    assert_eq!(fact_producer.name(), "azure_artifact_signing");
    
    let resolvers = trust_pack.cose_key_resolvers();
    assert_eq!(resolvers.len(), 0); // AAS delegates to certificates pack
    
    let validators = trust_pack.post_signature_validators();
    assert_eq!(validators.len(), 0);
    
    let plan = trust_pack.default_trust_plan();
    assert!(plan.is_none()); // Users compose their own plan
}

#[test]
fn test_trust_pack_fact_producer_consistency() {
    let trust_pack = AzureArtifactSigningTrustPack::new();
    let fact_producer_from_pack = trust_pack.fact_producer();
    
    let standalone_producer = AasFactProducer;
    
    // Both should have the same name
    assert_eq!(fact_producer_from_pack.name(), standalone_producer.name());
    assert_eq!(fact_producer_from_pack.name(), "azure_artifact_signing");
}
