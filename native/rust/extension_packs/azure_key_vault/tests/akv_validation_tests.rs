// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the Azure Key Vault crate's validation pack, facts, and fluent extensions.
//! These test offline validation logic and don't require Azure service access.

use cose_sign1_azure_key_vault::validation::facts::{
    AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_azure_key_vault::validation::pack::{AzureKeyVaultTrustPack, AzureKeyVaultTrustOptions};
use cose_sign1_validation::fluent::CoseSign1TrustPack;
use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_primitives::CoseSign1Message;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use std::sync::Arc;

// ========================================================================
// Facts — property accessors
// ========================================================================

#[test]
fn kid_detected_fact_properties() {
    let fact = AzureKeyVaultKidDetectedFact {
        is_azure_key_vault_key: true,
    };
    assert_eq!(
        fact.get_property("is_azure_key_vault_key"),
        Some(FactValue::Bool(true))
    );
    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn kid_detected_fact_false() {
    let fact = AzureKeyVaultKidDetectedFact {
        is_azure_key_vault_key: false,
    };
    assert_eq!(
        fact.get_property("is_azure_key_vault_key"),
        Some(FactValue::Bool(false))
    );
}

#[test]
fn kid_allowed_fact_properties() {
    let fact = AzureKeyVaultKidAllowedFact {
        is_allowed: true,
        details: Some("matched pattern".into()),
    };
    assert_eq!(
        fact.get_property("is_allowed"),
        Some(FactValue::Bool(true))
    );
    assert!(fact.get_property("nonexistent").is_none());
}

#[test]
fn kid_allowed_fact_not_allowed() {
    let fact = AzureKeyVaultKidAllowedFact {
        is_allowed: false,
        details: None,
    };
    assert_eq!(
        fact.get_property("is_allowed"),
        Some(FactValue::Bool(false))
    );
}

#[test]
fn kid_detected_debug() {
    let fact = AzureKeyVaultKidDetectedFact {
        is_azure_key_vault_key: true,
    };
    assert!(format!("{:?}", fact).contains("true"));
}

#[test]
fn kid_allowed_debug() {
    let fact = AzureKeyVaultKidAllowedFact {
        is_allowed: true,
        details: Some("test".into()),
    };
    let d = format!("{:?}", fact);
    assert!(d.contains("true"));
    assert!(d.contains("test"));
}

// ========================================================================
// TrustPack — construction and metadata
// ========================================================================

#[test]
fn trust_pack_new_default() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    assert_eq!(CoseSign1TrustPack::name(&pack), "AzureKeyVaultTrustPack");
}

#[test]
fn trust_pack_with_patterns() {
    let options = AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec![
            "https://myvault.vault.azure.net/keys/*".to_string(),
        ],
        ..Default::default()
    };
    let pack = AzureKeyVaultTrustPack::new(options);
    assert_eq!(CoseSign1TrustPack::name(&pack), "AzureKeyVaultTrustPack");
}

#[test]
fn trust_pack_provides_facts() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let producer: &dyn TrustFactProducer = &pack;
    assert!(!producer.provides().is_empty());
}

#[test]
fn trust_pack_default_plan() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let plan = pack.default_trust_plan();
    assert!(plan.is_some());
}

#[test]
fn trust_pack_fact_producer() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let producer = pack.fact_producer();
    assert_eq!(producer.name(), "cose_sign1_azure_key_vault::AzureKeyVaultTrustPack");
}

// ========================================================================
// COSE message helpers for produce() tests
// ========================================================================

fn build_cose_with_kid(kid_bytes: &[u8]) -> (Vec<u8>, CoseSign1Message) {
    let p = EverParseCborProvider;
    // Protected header: alg = ES256, kid = provided bytes
    let mut phdr = p.encoder();
    phdr.encode_map(2).unwrap();
    phdr.encode_i64(1).unwrap();  // alg
    phdr.encode_i64(-7).unwrap(); // ES256
    phdr.encode_i64(4).unwrap();  // kid
    phdr.encode_bstr(kid_bytes).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let msg_bytes = enc.into_bytes();
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    (msg_bytes, msg)
}

fn build_cose_no_kid() -> (Vec<u8>, CoseSign1Message) {
    let p = EverParseCborProvider;
    let mut phdr = p.encoder();
    phdr.encode_map(1).unwrap();
    phdr.encode_i64(1).unwrap();
    phdr.encode_i64(-7).unwrap();
    let phdr_bytes = phdr.into_bytes();

    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&phdr_bytes).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap();
    enc.encode_bstr(b"sig").unwrap();
    let msg_bytes = enc.into_bytes();
    let msg = CoseSign1Message::parse(&msg_bytes).unwrap();
    (msg_bytes, msg)
}

// ========================================================================
// TrustPack produce() — integration tests
// ========================================================================

#[test]
fn produce_with_akv_kid_default_patterns() {
    let kid = b"https://myvault.vault.azure.net/keys/mykey/abc123";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject).unwrap();
    assert!(detected.as_available().is_some());
    let allowed = engine.get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject).unwrap();
    assert!(allowed.as_available().is_some());
}

#[test]
fn produce_with_non_akv_kid() {
    let kid = b"https://signservice.example.com/keys/test/v1";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject).unwrap();
    let vals = detected.as_available().unwrap();
    // Should detect but mark as NOT an AKV key
    assert!(!vals.is_empty());
}

#[test]
fn produce_with_managed_hsm_kid() {
    let kid = b"https://myhsm.managedhsm.azure.net/keys/hsm-key/v1";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject).unwrap();
    assert!(detected.as_available().is_some());
}

#[test]
fn produce_with_no_kid() {
    let (msg_bytes, msg) = build_cose_no_kid();

    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject);
    // Should mark as missing since no kid
    assert!(detected.is_ok());
}

#[test]
fn produce_without_message() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);

    let subject = TrustSubject::message(b"dummy");
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject);
    assert!(detected.is_ok());
}

#[test]
fn produce_with_custom_allowed_patterns() {
    let kid = b"https://custom-vault.example.com/keys/k/v";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let opts = AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://custom-vault.example.com/keys/*".into()],
        require_azure_key_vault_kid: false, // don't require AKV URL format
    };
    let pack = AzureKeyVaultTrustPack::new(opts);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let allowed = engine.get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject).unwrap();
    assert!(allowed.as_available().is_some());
}

#[test]
fn produce_with_regex_pattern() {
    let kid = b"https://myvault.vault.azure.net/keys/special-key/v1";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let opts = AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["regex:.*vault\\.azure\\.net/keys/special-.*".into()],
        require_azure_key_vault_kid: true,
    };
    let pack = AzureKeyVaultTrustPack::new(opts);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let allowed = engine.get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject).unwrap();
    assert!(allowed.as_available().is_some());
}

#[test]
fn produce_with_empty_patterns() {
    let kid = b"https://myvault.vault.azure.net/keys/mykey/v1";
    let (msg_bytes, msg) = build_cose_with_kid(kid);

    let opts = AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec![], // no patterns
        require_azure_key_vault_kid: true,
    };
    let pack = AzureKeyVaultTrustPack::new(opts);
    let engine = TrustFactEngine::new(vec![Arc::new(pack)])
        .with_cose_sign1_bytes(Arc::from(msg_bytes.clone().into_boxed_slice()))
        .with_cose_sign1_message(Arc::new(msg));

    let subject = TrustSubject::message(&msg_bytes);
    let allowed = engine.get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject).unwrap();
    assert!(allowed.as_available().is_some());
}

#[test]
fn produce_non_message_subject() {
    // Non-Message subjects should be skipped
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let engine = TrustFactEngine::new(vec![Arc::new(pack)]);

    let msg_subject = TrustSubject::message(b"dummy");
    let cs_subject = TrustSubject::counter_signature(&msg_subject, b"dummy-cs");
    let detected = engine.get_fact_set::<AzureKeyVaultKidDetectedFact>(&cs_subject);
    assert!(detected.is_ok());
}

// ========================================================================
// Fluent extension traits
// ========================================================================

#[test]
fn fluent_require_azure_key_vault_kid() {
    use cose_sign1_azure_key_vault::validation::fluent_ext::AzureKeyVaultMessageScopeRulesExt;
    use cose_sign1_validation::fluent::TrustPlanBuilder;

    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(
        AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default()),
    );
    let plan = TrustPlanBuilder::new(vec![pack])
        .for_message(|m| m.require_azure_key_vault_kid())
        .compile();
    assert!(plan.is_ok());
}

#[test]
fn fluent_require_not_azure_key_vault_kid() {
    use cose_sign1_azure_key_vault::validation::fluent_ext::AzureKeyVaultKidDetectedWhereExt;
    use cose_sign1_validation::fluent::TrustPlanBuilder;

    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(
        AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default()),
    );
    let plan = TrustPlanBuilder::new(vec![pack])
        .for_message(|m| {
            m.require::<AzureKeyVaultKidDetectedFact>(|w| w.require_not_azure_key_vault_kid())
        })
        .compile();
    assert!(plan.is_ok());
}

#[test]
fn fluent_require_kid_allowed() {
    use cose_sign1_azure_key_vault::validation::fluent_ext::AzureKeyVaultMessageScopeRulesExt;
    use cose_sign1_validation::fluent::TrustPlanBuilder;

    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(
        AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default()),
    );
    let plan = TrustPlanBuilder::new(vec![pack])
        .for_message(|m| m.require_azure_key_vault_kid_allowed())
        .compile();
    assert!(plan.is_ok());
}

#[test]
fn fluent_require_kid_not_allowed() {
    use cose_sign1_azure_key_vault::validation::fluent_ext::AzureKeyVaultKidAllowedWhereExt;
    use cose_sign1_validation::fluent::TrustPlanBuilder;

    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(
        AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default()),
    );
    let plan = TrustPlanBuilder::new(vec![pack])
        .for_message(|m| {
            m.require::<AzureKeyVaultKidAllowedFact>(|w| w.require_kid_not_allowed())
        })
        .compile();
    assert!(plan.is_ok());
}
