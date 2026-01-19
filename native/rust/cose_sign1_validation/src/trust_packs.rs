// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::validator::{PostSignatureValidator, SigningKeyResolver};
use cose_sign1_validation_trust::facts::TrustFactProducer;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use std::sync::Arc;

/// A bundle that makes validation "secure-by-default":
/// - provides facts
/// - provides the signing-key resolver(s) needed for signature verification
/// - provides a default trust plan used when the caller does not specify a policy
pub trait CoseSign1TrustPack: Send + Sync {
    fn name(&self) -> &'static str;

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer>;

    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        Vec::new()
    }

    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        Vec::new()
    }

    /// Returns the pack's secure-by-default trust plan.
    ///
    /// When the caller does not provide an explicit plan, the validator OR-composes all pack plans.
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        None
    }
}
