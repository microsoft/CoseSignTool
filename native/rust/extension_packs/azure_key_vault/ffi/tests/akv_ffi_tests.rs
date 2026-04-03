// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for Azure Key Vault FFI exports.

use cose_sign1_azure_key_vault::validation::pack::{
    AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack,
};
use cose_sign1_azure_key_vault_ffi::{
    cose_akv_key_client_free, cose_akv_trust_options_t, cose_sign1_akv_signing_service_free,
    cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid,
    cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_allowed,
    cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed,
    cose_sign1_akv_trust_policy_builder_require_not_azure_key_vault_kid,
    cose_sign1_validator_builder_with_akv_pack, cose_sign1_validator_builder_with_akv_pack_ex,
};
use cose_sign1_validation::fluent::{CoseSign1TrustPack, TrustPlanBuilder};
use cose_sign1_validation_ffi::{
    cose_sign1_validator_builder_t, cose_status_t, cose_trust_policy_builder_t,
};
use std::sync::Arc;

fn make_builder() -> Box<cose_sign1_validator_builder_t> {
    Box::new(cose_sign1_validator_builder_t {
        packs: Vec::new(),
        compiled_plan: None,
    })
}

fn make_policy_builder_with_akv() -> Box<cose_trust_policy_builder_t> {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(AzureKeyVaultTrustPack::new(
        AzureKeyVaultTrustOptions::default(),
    ));
    let builder = TrustPlanBuilder::new(vec![pack]);
    Box::new(cose_trust_policy_builder_t {
        builder: Some(builder),
    })
}

// ========================================================================
// Validator builder — add pack
// ========================================================================

#[test]
fn with_akv_pack_null_builder() {
    let status = cose_sign1_validator_builder_with_akv_pack(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_akv_pack_success() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_akv_pack(&mut *builder);
    assert_eq!(status, cose_status_t::COSE_OK);
    assert_eq!(builder.packs.len(), 1);
}

#[test]
fn with_akv_pack_ex_null_options() {
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_akv_pack_ex(&mut *builder, std::ptr::null());
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_akv_pack_ex_null_builder() {
    let status =
        cose_sign1_validator_builder_with_akv_pack_ex(std::ptr::null_mut(), std::ptr::null());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn with_akv_pack_ex_with_options() {
    let opts = cose_akv_trust_options_t {
        require_azure_key_vault_kid: true,
        allowed_kid_patterns: std::ptr::null(),
    };
    let mut builder = make_builder();
    let status = cose_sign1_validator_builder_with_akv_pack_ex(&mut *builder, &opts);
    assert_eq!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// Trust policy builders
// ========================================================================

#[test]
fn require_akv_kid_null_builder() {
    let status =
        cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid(std::ptr::null_mut());
    assert_ne!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_akv_kid_success() {
    let mut pb = make_policy_builder_with_akv();
    let status = cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_not_akv_kid_success() {
    let mut pb = make_policy_builder_with_akv();
    let status = cose_sign1_akv_trust_policy_builder_require_not_azure_key_vault_kid(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_akv_kid_allowed_success() {
    let mut pb = make_policy_builder_with_akv();
    let status = cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

#[test]
fn require_akv_kid_not_allowed_success() {
    let mut pb = make_policy_builder_with_akv();
    let status =
        cose_sign1_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(&mut *pb);
    assert_eq!(status, cose_status_t::COSE_OK);
}

// ========================================================================
// Client/service handles — free null is safe
// ========================================================================

#[test]
fn free_null_key_client() {
    cose_akv_key_client_free(std::ptr::null_mut()); // should not crash
}

#[test]
fn free_null_signing_service() {
    cose_sign1_akv_signing_service_free(std::ptr::null_mut()); // should not crash
}
