// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Comprehensive test coverage for ATS validation/mod.rs.
//! 
//! Targets remaining uncovered lines (28 uncov) with focus on:
//! - AtsFactProducer implementation
//! - AzureTrustedSigningTrustPack implementation  
//! - ATS fact production logic
//! - Trust pack composition and methods
//! - CoseSign1TrustPack trait implementation

use cose_sign1_azure_trusted_signing::validation::{
    AtsFactProducer,
    AzureTrustedSigningTrustPack,
};
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::facts::{TrustFactProducer, FactKey};

#[test]
fn test_ats_fact_producer_name() {
    let producer = AtsFactProducer;
    assert_eq!(producer.name(), "azure_trusted_signing");
}

#[test]
fn test_ats_fact_producer_provides() {
    let producer = AtsFactProducer;
    let provided_facts = producer.provides();
    
    // Currently returns empty array - this tests the implementation
    assert_eq!(provided_facts.len(), 0, "Should return empty fact keys array");
}

#[test]
fn test_azure_trusted_signing_trust_pack_new() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    // Should successfully create the trust pack
    assert_eq!(trust_pack.name(), "azure_trusted_signing");
}

#[test]
fn test_azure_trusted_signing_trust_pack_name() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    assert_eq!(trust_pack.name(), "azure_trusted_signing");
}

#[test]
fn test_azure_trusted_signing_trust_pack_fact_producer() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let fact_producer = trust_pack.fact_producer();
    
    // Should return an Arc<dyn TrustFactProducer>
    assert_eq!(fact_producer.name(), "azure_trusted_signing");
}

#[test]
fn test_azure_trusted_signing_trust_pack_fact_producer_consistency() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    // Multiple calls should return the same producer (Arc cloning)
    let producer1 = trust_pack.fact_producer();
    let producer2 = trust_pack.fact_producer();
    
    assert_eq!(producer1.name(), producer2.name());
}

#[test]
fn test_azure_trusted_signing_trust_pack_cose_key_resolvers() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let resolvers = trust_pack.cose_key_resolvers();
    
    // ATS uses X.509 certificates — delegates to certificates pack
    assert_eq!(resolvers.len(), 0, "Should return empty resolvers (delegates to certificates pack)");
}

#[test]
fn test_azure_trusted_signing_trust_pack_post_signature_validators() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let validators = trust_pack.post_signature_validators();
    
    // Currently returns empty validators
    assert_eq!(validators.len(), 0, "Should return empty validators");
}

#[test]
fn test_azure_trusted_signing_trust_pack_default_trust_plan() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let default_plan = trust_pack.default_trust_plan();
    
    // Should return None - users compose their own plan
    assert!(default_plan.is_none(), "Should return None for default trust plan");
}

#[test]
fn test_trust_pack_trait_implementation() {
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let trust_pack_trait: &dyn CoseSign1TrustPack = &trust_pack;
    
    // Test all trait methods through the trait interface
    assert_eq!(trust_pack_trait.name(), "azure_trusted_signing");
    
    let fact_producer = trust_pack_trait.fact_producer();
    assert_eq!(fact_producer.name(), "azure_trusted_signing");
    
    let resolvers = trust_pack_trait.cose_key_resolvers();
    assert_eq!(resolvers.len(), 0);
    
    let validators = trust_pack_trait.post_signature_validators();
    assert_eq!(validators.len(), 0);
    
    let default_plan = trust_pack_trait.default_trust_plan();
    assert!(default_plan.is_none());
}

#[test]
fn test_ats_fact_producer_trait_object() {
    let producer = AtsFactProducer;
    let producer_trait: &dyn TrustFactProducer = &producer;
    
    // Test through trait object
    assert_eq!(producer_trait.name(), "azure_trusted_signing");
    assert_eq!(producer_trait.provides().len(), 0);
}

#[test]
fn test_trust_pack_arc_sharing() {
    // Test that the fact producer Arc is properly shared
    let trust_pack1 = AzureTrustedSigningTrustPack::new();
    let trust_pack2 = AzureTrustedSigningTrustPack::new();
    
    let producer1 = trust_pack1.fact_producer();
    let producer2 = trust_pack2.fact_producer();
    
    // Both should work identically
    assert_eq!(producer1.name(), producer2.name());
}

#[test]
fn test_trust_pack_composition_pattern() {
    // Test that the trust pack properly composes the fact producer
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    // The trust pack should contain an AtsFactProducer
    let fact_producer = trust_pack.fact_producer();
    
    // The fact producer should work when called through the trust pack
    assert_eq!(fact_producer.name(), "azure_trusted_signing");
    assert_eq!(fact_producer.provides().len(), 0);
}

#[test]
fn test_trust_pack_send_sync() {
    // Test that the trust pack implements Send + Sync
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AzureTrustedSigningTrustPack>();
    assert_send_sync::<AtsFactProducer>();
}

#[test]
fn test_fact_producer_provides_empty_initially() {
    // Test that provides() returns empty array initially
    // This documents the current implementation behavior
    let producer = AtsFactProducer;
    let provided = producer.provides();
    
    assert!(provided.is_empty(), "Initially should provide empty fact keys");
    
    // The comment in the code says "TODO: Register fact keys"
    // This test documents the current state
}

#[test]
fn test_trust_pack_delegation_to_certificates() {
    // Test that ATS trust pack delegates key resolution to certificates pack
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    // Should return empty resolvers (delegates to certificates pack)
    let resolvers = trust_pack.cose_key_resolvers();
    assert_eq!(resolvers.len(), 0, "Should delegate to certificates pack");
    
    // Should return empty validators (no ATS-specific validation yet)
    let validators = trust_pack.post_signature_validators();
    assert_eq!(validators.len(), 0, "Should have no ATS-specific validators yet");
}

#[test]
fn test_no_default_trust_plan_philosophy() {
    // Test that ATS pack doesn't provide a default trust plan
    // This follows the philosophy that users compose their own plans
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    let default_plan = trust_pack.default_trust_plan();
    assert!(
        default_plan.is_none(),
        "Should not provide default plan - users compose ATS + certificates pack"
    );
}

#[test]
fn test_multiple_trust_pack_instances() {
    // Test creating multiple instances
    let pack1 = AzureTrustedSigningTrustPack::new();
    let pack2 = AzureTrustedSigningTrustPack::new();
    
    // Both should have identical behavior
    assert_eq!(pack1.name(), pack2.name());
    assert_eq!(pack1.fact_producer().name(), pack2.fact_producer().name());
    assert_eq!(pack1.cose_key_resolvers().len(), pack2.cose_key_resolvers().len());
    assert_eq!(pack1.post_signature_validators().len(), pack2.post_signature_validators().len());
}

#[test]
fn test_fact_producer_stability() {
    // Test that provider behavior is stable across calls
    let producer = AtsFactProducer;
    
    // Multiple calls should return consistent results
    for i in 0..5 {
        assert_eq!(producer.name(), "azure_trusted_signing", "Iteration {}", i);
        assert_eq!(producer.provides().len(), 0, "Iteration {}", i);
    }
}

#[test]
fn test_trust_pack_name_consistency() {
    // Test that the trust pack name is consistent
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    // Name should be consistent across multiple calls
    for i in 0..5 {
        assert_eq!(trust_pack.name(), "azure_trusted_signing", "Iteration {}", i);
    }
}

#[test]
fn test_fact_producer_name_matches_pack() {
    // Test that the fact producer name matches the trust pack name
    let trust_pack = AzureTrustedSigningTrustPack::new();
    let fact_producer = trust_pack.fact_producer();
    
    assert_eq!(trust_pack.name(), fact_producer.name());
}

#[test]
fn test_trust_pack_components_independence() {
    // Test that different components work independently
    let trust_pack = AzureTrustedSigningTrustPack::new();
    
    let fact_producer = trust_pack.fact_producer();
    let resolvers = trust_pack.cose_key_resolvers();
    let validators = trust_pack.post_signature_validators();
    let plan = trust_pack.default_trust_plan();
    
    // Each component should be properly configured
    assert_eq!(fact_producer.name(), "azure_trusted_signing");
    assert_eq!(resolvers.len(), 0);
    assert_eq!(validators.len(), 0);
    assert!(plan.is_none());
}

#[test]
fn test_ats_fact_producer_type_safety() {
    // Test type safety of the fact producer
    let producer = AtsFactProducer;
    
    // Should safely convert to trait object
    let _trait_obj: &dyn TrustFactProducer = &producer;
    
    // Should implement required traits
    fn assert_traits<T: Send + Sync + TrustFactProducer>(_: T) {}
    assert_traits(producer);
}