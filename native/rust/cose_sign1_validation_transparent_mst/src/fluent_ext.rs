// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    typed_fields as mst_typed, MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
    MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation::fluent::CounterSignatureSubjectFact;
use cose_sign1_validation_trust::fluent::{ScopeRules, SubjectsFromFactsScope, Where};

pub trait MstReceiptPresentWhereExt {
    /// Require that the receipt is present.
    fn require_receipt_present(self) -> Self;

    /// Require that the receipt is not present.
    fn require_receipt_not_present(self) -> Self;
}

impl MstReceiptPresentWhereExt for Where<MstReceiptPresentFact> {
    /// Require that the receipt is present.
    fn require_receipt_present(self) -> Self {
        self.r#true(mst_typed::mst_receipt_present::PRESENT)
    }

    /// Require that the receipt is not present.
    fn require_receipt_not_present(self) -> Self {
        self.r#false(mst_typed::mst_receipt_present::PRESENT)
    }
}

pub trait MstReceiptTrustedWhereExt {
    /// Require that the receipt is trusted.
    fn require_receipt_trusted(self) -> Self;

    /// Require that the receipt is not trusted.
    fn require_receipt_not_trusted(self) -> Self;
}

impl MstReceiptTrustedWhereExt for Where<MstReceiptTrustedFact> {
    /// Require that the receipt is trusted.
    fn require_receipt_trusted(self) -> Self {
        self.r#true(mst_typed::mst_receipt_trusted::TRUSTED)
    }

    /// Require that the receipt is not trusted.
    fn require_receipt_not_trusted(self) -> Self {
        self.r#false(mst_typed::mst_receipt_trusted::TRUSTED)
    }
}

pub trait MstReceiptIssuerWhereExt {
    /// Require the receipt issuer to equal the provided value.
    fn require_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self;

    /// Require the receipt issuer to contain the provided substring.
    fn require_receipt_issuer_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptIssuerWhereExt for Where<MstReceiptIssuerFact> {
    /// Require the receipt issuer to equal the provided value.
    fn require_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.str_eq(mst_typed::mst_receipt_issuer::ISSUER, issuer.into())
    }

    /// Require the receipt issuer to contain the provided substring.
    fn require_receipt_issuer_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(mst_typed::mst_receipt_issuer::ISSUER, needle.into())
    }
}

pub trait MstReceiptKidWhereExt {
    /// Require the receipt key id (`kid`) to equal the provided value.
    fn require_receipt_kid_eq(self, kid: impl Into<String>) -> Self;

    /// Require the receipt key id (`kid`) to contain the provided substring.
    fn require_receipt_kid_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptKidWhereExt for Where<MstReceiptKidFact> {
    /// Require the receipt key id (`kid`) to equal the provided value.
    fn require_receipt_kid_eq(self, kid: impl Into<String>) -> Self {
        self.str_eq(mst_typed::mst_receipt_kid::KID, kid.into())
    }

    /// Require the receipt key id (`kid`) to contain the provided substring.
    fn require_receipt_kid_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(mst_typed::mst_receipt_kid::KID, needle.into())
    }
}

pub trait MstReceiptStatementSha256WhereExt {
    /// Require the receipt statement digest to equal the provided hex string.
    fn require_receipt_statement_sha256_eq(self, sha256_hex: impl Into<String>) -> Self;
}

impl MstReceiptStatementSha256WhereExt for Where<MstReceiptStatementSha256Fact> {
    /// Require the receipt statement digest to equal the provided hex string.
    fn require_receipt_statement_sha256_eq(self, sha256_hex: impl Into<String>) -> Self {
        self.str_eq(
            mst_typed::mst_receipt_statement_sha256::SHA256_HEX,
            sha256_hex.into(),
        )
    }
}

pub trait MstReceiptStatementCoverageWhereExt {
    /// Require the receipt coverage description to equal the provided value.
    fn require_receipt_statement_coverage_eq(self, coverage: impl Into<String>) -> Self;

    /// Require the receipt coverage description to contain the provided substring.
    fn require_receipt_statement_coverage_contains(self, needle: impl Into<String>) -> Self;
}

impl MstReceiptStatementCoverageWhereExt for Where<MstReceiptStatementCoverageFact> {
    /// Require the receipt coverage description to equal the provided value.
    fn require_receipt_statement_coverage_eq(self, coverage: impl Into<String>) -> Self {
        self.str_eq(
            mst_typed::mst_receipt_statement_coverage::COVERAGE,
            coverage.into(),
        )
    }

    /// Require the receipt coverage description to contain the provided substring.
    fn require_receipt_statement_coverage_contains(self, needle: impl Into<String>) -> Self {
        self.str_contains(
            mst_typed::mst_receipt_statement_coverage::COVERAGE,
            needle.into(),
        )
    }
}

pub trait MstReceiptSignatureVerifiedWhereExt {
    /// Require that the receipt signature verified.
    fn require_receipt_signature_verified(self) -> Self;

    /// Require that the receipt signature did not verify.
    fn require_receipt_signature_not_verified(self) -> Self;
}

impl MstReceiptSignatureVerifiedWhereExt for Where<MstReceiptSignatureVerifiedFact> {
    /// Require that the receipt signature verified.
    fn require_receipt_signature_verified(self) -> Self {
        self.r#true(mst_typed::mst_receipt_signature_verified::VERIFIED)
    }

    /// Require that the receipt signature did not verify.
    fn require_receipt_signature_not_verified(self) -> Self {
        self.r#false(mst_typed::mst_receipt_signature_verified::VERIFIED)
    }
}

/// Fluent helper methods for counter-signature scope rules.
///
/// These are intentionally "one click down" from `TrustPlanBuilder::for_counter_signature(...)`.
pub trait MstCounterSignatureScopeRulesExt {
    /// Require that an MST receipt is present.
    fn require_mst_receipt_present(self) -> Self;

    /// Require that the receipt's signature verified.
    fn require_mst_receipt_signature_verified(self) -> Self;

    /// Require the receipt issuer to equal the provided value.
    fn require_mst_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self;

    /// Require the receipt issuer to contain the provided substring.
    fn require_mst_receipt_issuer_contains(self, needle: impl Into<String>) -> Self;

    /// Require the receipt key id (`kid`) to equal the provided value.
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
    /// Require that an MST receipt is present.
    fn require_mst_receipt_present(self) -> Self {
        self.require::<MstReceiptPresentFact>(|w| w.require_receipt_present())
    }

    /// Require that the receipt's signature verified.
    fn require_mst_receipt_signature_verified(self) -> Self {
        self.require::<MstReceiptSignatureVerifiedFact>(|w| w.require_receipt_signature_verified())
    }

    /// Require the receipt issuer to equal the provided value.
    fn require_mst_receipt_issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_eq(issuer))
    }

    /// Require the receipt issuer to contain the provided substring.
    fn require_mst_receipt_issuer_contains(self, needle: impl Into<String>) -> Self {
        self.require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_contains(needle))
    }

    fn require_mst_receipt_trusted_from_issuer(self, needle: impl Into<String>) -> Self {
        self.require::<MstReceiptTrustedFact>(|w| w.require_receipt_trusted())
            .and()
            .require::<MstReceiptIssuerFact>(|w| w.require_receipt_issuer_contains(needle))
    }

    /// Require the receipt key id (`kid`) to equal the provided value.
    fn require_mst_receipt_kid_eq(self, kid: impl Into<String>) -> Self {
        self.require::<MstReceiptKidFact>(|w| w.require_receipt_kid_eq(kid))
    }
}
