// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fluent trust policy builder extensions for Azure Artifact Signing facts.
//!
//! Provides ergonomic methods to add AAS-specific requirements to trust policies
//! via the fluent `TrustPlanBuilder` API.

use crate::validation::facts::{
    typed_fields as aas_typed, AasComplianceFact, AasSigningServiceIdentifiedFact,
};
use cose_sign1_validation_primitives::fluent::{PrimarySigningKeyScope, ScopeRules, Where};

// ============================================================================
// Where<> extensions for individual fact types
// ============================================================================

/// Fluent helpers for `Where<AasSigningServiceIdentifiedFact>`.
pub trait AasIdentifiedWhereExt {
    /// Require that the signing certificate was issued by Azure Artifact Signing.
    fn require_ats_issued(self) -> Self;

    /// Require that the signing certificate was NOT issued by Azure Artifact Signing.
    fn require_not_ats_issued(self) -> Self;
}

impl AasIdentifiedWhereExt for Where<AasSigningServiceIdentifiedFact> {
    fn require_ats_issued(self) -> Self {
        self.r#true(aas_typed::aas_identified::IS_ATS_ISSUED)
    }

    fn require_not_ats_issued(self) -> Self {
        self.r#false(aas_typed::aas_identified::IS_ATS_ISSUED)
    }
}

/// Fluent helpers for `Where<AasComplianceFact>`.
pub trait AasComplianceWhereExt {
    /// Require that the signing operation is SCITT compliant.
    fn require_scitt_compliant(self) -> Self;

    /// Require that the signing operation is NOT SCITT compliant.
    fn require_not_scitt_compliant(self) -> Self;
}

impl AasComplianceWhereExt for Where<AasComplianceFact> {
    fn require_scitt_compliant(self) -> Self {
        self.r#true(aas_typed::aas_compliance::SCITT_COMPLIANT)
    }

    fn require_not_scitt_compliant(self) -> Self {
        self.r#false(aas_typed::aas_compliance::SCITT_COMPLIANT)
    }
}

// ============================================================================
// Primary signing key scope extensions
// ============================================================================

/// Fluent helper methods for AAS-specific trust policy requirements on
/// the primary signing key scope.
///
/// Usage:
/// ```ignore
/// plan.for_primary_signing_key(|key| key.require_ats_identified())
/// ```
pub trait AasPrimarySigningKeyScopeRulesExt {
    /// Require that the signing certificate was issued by Azure Artifact Signing.
    fn require_ats_identified(self) -> Self;

    /// Require that the signing operation is SCITT compliant (AAS-issued + SCITT headers).
    fn require_ats_compliant(self) -> Self;
}

impl AasPrimarySigningKeyScopeRulesExt for ScopeRules<PrimarySigningKeyScope> {
    fn require_ats_identified(self) -> Self {
        self.require::<AasSigningServiceIdentifiedFact>(|w| w.require_ats_issued())
    }

    fn require_ats_compliant(self) -> Self {
        self.require::<AasComplianceFact>(|w| w.require_scitt_compliant())
    }
}
