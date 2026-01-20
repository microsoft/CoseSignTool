// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_azure_key_vault::facts::{AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact};
use cose_sign1_validation_azure_key_vault::fluent_ext::*;
use cose_sign1_validation_azure_key_vault::pack::{AzureKeyVaultTrustPack, AzureKeyVaultTrustOptions};
use cose_sign1_validation_trust::fact_properties::FactProperties;
use std::sync::Arc;

#[test]
fn akv_fluent_extensions_build_and_compile() {
    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());

    let _plan = TrustPlanBuilder::new(vec![Arc::new(pack)])
        .for_message(|s| {
            s.require_azure_key_vault_kid()
                .and()
                .require_azure_key_vault_kid_allowed()
                .and()
                .require::<AzureKeyVaultKidDetectedFact>(|w| w.require_not_azure_key_vault_kid())
                .and()
                .require::<AzureKeyVaultKidAllowedFact>(|w| w.require_kid_not_allowed())
        })
        .compile()
        .expect("expected plan compile to succeed");
}

#[test]
fn akv_facts_expose_declarative_properties() {
    let detected = AzureKeyVaultKidDetectedFact {
        is_azure_key_vault_key: true,
    };
    assert!(detected.get_property("is_azure_key_vault_key").is_some());
    assert!(detected.get_property("no_such_field").is_none());

    let allowed = AzureKeyVaultKidAllowedFact {
        is_allowed: false,
        details: Some("because".to_string()),
    };
    assert!(allowed.get_property("is_allowed").is_some());
    assert!(allowed.get_property("no_such_field").is_none());
}

#[test]
fn akv_default_trust_plan_is_provided() {
    use cose_sign1_validation::fluent::CoseSign1TrustPack;

    let pack = AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions::default());
    let plan = pack
        .default_trust_plan()
        .expect("expected AKV trust pack to provide a default trust plan");

    // Smoke-check the compiled plan is usable.
    assert!(!plan.required_facts().is_empty());
}
