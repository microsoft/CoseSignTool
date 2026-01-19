// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust pack extension point.
//!
//! A trust pack is the unit of composition for the validator. Packs can contribute:
//! - fact production (inputs to trust evaluation)
//! - signing key resolution (inputs to signature verification)
//! - post-signature validation (additional policy checks)
//! - an optional secure-by-default trust plan

use crate::validator::{PostSignatureValidator, SigningKeyResolver};
use cose_sign1_validation_trust::facts::TrustFactProducer;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::sync::Arc;

/// A composable bundle that makes validation "secure-by-default".
///
/// Packs can provide facts and key resolvers, and may also provide a default trust plan.
/// When callers do not provide an explicit plan, the validator OR-composes the default plans
/// from all configured packs.
pub trait CoseSign1TrustPack: Send + Sync {
    /// Stable pack name for diagnostics.
    fn name(&self) -> &'static str;

    /// Pack-provided fact producer.
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer>;

    /// Signing key resolver(s) contributed by this pack.
    ///
    /// Default is an empty list.
    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        Vec::new()
    }

    /// Post-signature validator(s) contributed by this pack.
    ///
    /// Default is an empty list.
    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        Vec::new()
    }

    /// Returns the pack's secure-by-default trust plan.
    ///
    /// When the caller does not provide an explicit plan, the validator OR-composes all pack plans.
    ///
    /// Default is `None` (pack does not contribute a trust plan).
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None
    }
}
