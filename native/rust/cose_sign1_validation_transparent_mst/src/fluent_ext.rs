// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    typed_fields as mst_typed, MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact, MstReceiptStatementSha256Fact,
    MstReceiptTrustedFact,
};
use cose_sign1_validation::CounterSignatureSubjectFact;
use cose_sign1_validation_trust::fluent::{ScopeRules, SubjectsFromFactsScope, Where};

pub trait MstReceiptPresentWhereExt {
    fn require_receipt_present(self) -> Self;
    fn require_receipt_not_present(self) -> Self;
}

impl MstReceiptPresentWhereExt for Where<MstReceiptPresentFact> {
    fn require_receipt_present(self) -> Self {
        self.r#true(mst_typed::mst_receipt_present::PRESENT)
    }

    fn require_receipt_not_present(self) -> Self {
        self.r#false(mst_typed::mst_receipt_present::PRESENT)
    }
}

pub trait MstReceiptTrustedWhereExt {
    fn require_receipt_trusted(self) -> Self;
    fn require_receipt_not_trusted(self) -> Self;
}

impl MstReceiptTrustedWhereExt for Where<MstReceiptTrustedFact> {
    fn require_receipt_trusted(self) -> Self {
        self.r#true(mst_typed::mst_receipt_trusted::TRUSTED)
    }

    fn require_receipt_not_trusted(self) -> Self {
        self.r#false(mst_typed::mst_receipt_trusted::TRUSTED)
    }
}

pub trait MstReceiptIssuerWhereExt {
    fn require_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self;
    fn require_receipt_issuer_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptIssuerWhereExt for Where<MstReceiptIssuerFact> {
    fn require_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.str_eq(mst_typed::mst_receipt_issuer::ISSUER, issuer.into())
    }

    fn require_receipt_issuer_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(mst_typed::mst_receipt_issuer::ISSUER, needle.into())
    }
}

pub trait MstReceiptKidWhereExt {
    fn require_receipt_kid_eq(self, kid: impl Into<String>) -> Self;
    fn require_receipt_kid_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptKidWhereExt for Where<MstReceiptKidFact> {
    fn require_receipt_kid_eq(self, kid: impl Into<String>) -> Self {
        self.str_eq(mst_typed::mst_receipt_kid::KID, kid.into())
    }

    fn require_receipt_kid_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(mst_typed::mst_receipt_kid::KID, needle.into())
    }
}

pub trait MstReceiptStatementSha256WhereExt {
    fn require_receipt_statement_sha256_eq(self, sha256_hex: impl Into<String>) -> Self;
}

impl MstReceiptStatementSha256WhereExt for Where<MstReceiptStatementSha256Fact> {
    fn require_receipt_statement_sha256_eq(self, sha256_hex: impl Into<String>) -> Self {
        self.str_eq(
            mst_typed::mst_receipt_statement_sha256::SHA256_HEX,
            sha256_hex.into(),
        )
    }
}

pub trait MstReceiptStatementCoverageWhereExt {
    fn require_receipt_statement_coverage_eq(self, coverage: impl Into<String>) -> Self;
    fn require_receipt_statement_coverage_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptStatementCoverageWhereExt for Where<MstReceiptStatementCoverageFact> {
    fn require_receipt_statement_coverage_eq(self, coverage: impl Into<String>) -> Self {
        self.str_eq(
            mst_typed::mst_receipt_statement_coverage::COVERAGE,
            coverage.into(),
        )
    }

    fn require_receipt_statement_coverage_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(
            mst_typed::mst_receipt_statement_coverage::COVERAGE,
            needle.into(),
        )
    }
}

pub trait MstReceiptSignatureVerifiedWhereExt {
    fn require_receipt_signature_verified(self) -> Self;
    fn require_receipt_signature_not_verified(self) -> Self;
}

impl MstReceiptSignatureVerifiedWhereExt for Where<MstReceiptSignatureVerifiedFact> {
    fn require_receipt_signature_verified(self) -> Self {
        self.r#true(mst_typed::mst_receipt_signature_verified::VERIFIED)
    }

    fn require_receipt_signature_not_verified(self) -> Self {
        self.r#false(mst_typed::mst_receipt_signature_verified::VERIFIED)
    }
}

/// Fluent helper methods for counter-signature scope rules.
///
/// These are intentionally "one click down" from `TrustPlanBuilder::for_counter_signature(...)`.
pub trait MstCounterSignatureScopeRulesExt {
    fn require_mst_receipt_present(self) -> Self;
    fn require_mst_receipt_signature_verified(self) -> Self;
    fn require_mst_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self;
    fn require_mst_receipt_issuer_contains(self, needle: impl Into<String>) -> Self;
    fn require_mst_receipt_kid_eq(self, kid: impl Into<String>) -> Self;

    /// Convenience: trust decision = (receipt trusted) AND (issuer matches).
    ///
    /// Note: Online JWKS fetching is still gated by the MST pack configuration.
    /// This method expresses *trust*; the pack config expresses *operational/network allowance*.
    fn require_mst_receipt_trusted_from_issuer(self, needle: impl Into<String>) -> Self;
}

impl MstCounterSignatureScopeRulesExt
    for ScopeRules<SubjectsFromFactsScope<CounterSignatureSubjectFact>>
{
    fn require_mst_receipt_present(self) -> Self {
        self.require::<MstReceiptPresentFact>(|w| w.require_receipt_present())
    }

    fn require_mst_receipt_signature_verified(self) -> Self {
        self.require::<MstReceiptSignatureVerifiedFact>(|w| w.require_receipt_signature_verified())
    }

    fn require_mst_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_eq(issuer))
    }

    fn require_mst_receipt_issuer_contains(self, needle: impl Into<String>) -> Self {
        self.require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_contains(needle))
    }

    fn require_mst_receipt_trusted_from_issuer(self, needle: impl Into<String>) -> Self {
        self.require::<MstReceiptTrustedFact>(|w| w.require_receipt_trusted())
            .and()
            .require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_contains(needle))
    }

    fn require_mst_receipt_kid_eq(self, kid: impl Into<String>) -> Self {
        self.require::<MstReceiptKidFact>(|w| w.require_receipt_kid_eq(kid))
    }
}
