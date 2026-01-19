// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    typed_fields as x509_typed, X509ChainElementIdentityFact, X509ChainElementValidityFact,
    X509ChainTrustedFact, X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_trust::facts::FactKey;
use cose_sign1_validation_trust::fluent::{PrimarySigningKeyScope, ScopeRules, Where};
use cose_sign1_validation_trust::rules::{
    not_with_reason, require_fact_bool, require_facts_match, FactSelector, MissingBehavior,
};

pub trait X509SigningCertificateIdentityWhereExt {
    /// Require the leaf certificate thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self;

    /// Require that the leaf certificate thumbprint is present and non-empty.
    fn thumbprint_non_empty(self) -> Self;

    /// Require the leaf certificate subject to equal the provided value.
    fn subject_eq(self, subject: impl Into<String>) -> Self;

    /// Require the leaf certificate issuer to equal the provided value.
    fn issuer_eq(self, issuer: impl Into<String>) -> Self;

    /// Require the leaf certificate serial number to equal the provided value.
    fn serial_number_eq(self, serial_number: impl Into<String>) -> Self;

    /// Require `not_before <= max_unix_seconds`.
    fn not_before_le(self, max_unix_seconds: i64) -> Self;

    /// Require `not_before >= min_unix_seconds`.
    fn not_before_ge(self, min_unix_seconds: i64) -> Self;

    /// Require `not_after <= max_unix_seconds`.
    fn not_after_le(self, max_unix_seconds: i64) -> Self;

    /// Require `not_after >= min_unix_seconds`.
    fn not_after_ge(self, min_unix_seconds: i64) -> Self;

    /// Require `not_before <= now_unix_seconds`.
    fn cert_not_before(self, now_unix_seconds: i64) -> Self;

    /// Require `not_after >= now_unix_seconds`.
    fn cert_not_after(self, now_unix_seconds: i64) -> Self;

    /// Require that `now_unix_seconds` lies within the certificate validity window.
    fn cert_valid_at(self, now_unix_seconds: i64) -> Self
    where
        Self: Sized,
    {
        self.cert_not_before(now_unix_seconds)
            .cert_not_after(now_unix_seconds)
    }

    /// Require that the certificate is expired at or before `now_unix_seconds`.
    fn cert_expired_at_or_before(self, now_unix_seconds: i64) -> Self;
}

impl X509SigningCertificateIdentityWhereExt for Where<X509SigningCertificateIdentityFact> {
    /// Require the leaf certificate thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_signing_certificate_identity::CERTIFICATE_THUMBPRINT,
            thumbprint,
        )
    }

    /// Require that the leaf certificate thumbprint is present and non-empty.
    fn thumbprint_non_empty(self) -> Self {
        self.str_non_empty(x509_typed::x509_signing_certificate_identity::CERTIFICATE_THUMBPRINT)
    }

    /// Require the leaf certificate subject to equal the provided value.
    fn subject_eq(self, subject: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_signing_certificate_identity::SUBJECT,
            subject,
        )
    }

    /// Require the leaf certificate issuer to equal the provided value.
    fn issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_signing_certificate_identity::ISSUER,
            issuer,
        )
    }

    /// Require the leaf certificate serial number to equal the provided value.
    fn serial_number_eq(self, serial_number: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_signing_certificate_identity::SERIAL_NUMBER,
            serial_number,
        )
    }

    /// Require `not_before <= max_unix_seconds`.
    fn not_before_le(self, max_unix_seconds: i64) -> Self {
        self.i64_le(
            x509_typed::x509_signing_certificate_identity::NOT_BEFORE_UNIX_SECONDS,
            max_unix_seconds,
        )
    }

    /// Require `not_before >= min_unix_seconds`.
    fn not_before_ge(self, min_unix_seconds: i64) -> Self {
        self.i64_ge(
            x509_typed::x509_signing_certificate_identity::NOT_BEFORE_UNIX_SECONDS,
            min_unix_seconds,
        )
    }

    /// Require `not_after <= max_unix_seconds`.
    fn not_after_le(self, max_unix_seconds: i64) -> Self {
        self.i64_le(
            x509_typed::x509_signing_certificate_identity::NOT_AFTER_UNIX_SECONDS,
            max_unix_seconds,
        )
    }

    /// Require `not_after >= min_unix_seconds`.
    fn not_after_ge(self, min_unix_seconds: i64) -> Self {
        self.i64_ge(
            x509_typed::x509_signing_certificate_identity::NOT_AFTER_UNIX_SECONDS,
            min_unix_seconds,
        )
    }

    /// Require `not_before <= now_unix_seconds`.
    fn cert_not_before(self, now_unix_seconds: i64) -> Self {
        self.not_before_le(now_unix_seconds)
    }

    /// Require `not_after >= now_unix_seconds`.
    fn cert_not_after(self, now_unix_seconds: i64) -> Self {
        self.not_after_ge(now_unix_seconds)
    }

    /// Require that the certificate is expired at or before `now_unix_seconds`.
    fn cert_expired_at_or_before(self, now_unix_seconds: i64) -> Self {
        self.not_after_le(now_unix_seconds)
    }
}

pub trait X509ChainElementIdentityWhereExt {
    /// Require the chain element index to equal `index`.
    fn index_eq(self, index: usize) -> Self;

    /// Require the chain element thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self;

    /// Require that the chain element thumbprint is present and non-empty.
    fn thumbprint_non_empty(self) -> Self;

    /// Require the chain element subject to equal the provided value.
    fn subject_eq(self, subject: impl Into<String>) -> Self;

    /// Require the chain element issuer to equal the provided value.
    fn issuer_eq(self, issuer: impl Into<String>) -> Self;
}

impl X509ChainElementIdentityWhereExt for Where<X509ChainElementIdentityFact> {
    /// Require the chain element index to equal `index`.
    fn index_eq(self, index: usize) -> Self {
        self.usize_eq(x509_typed::x509_chain_element_identity::INDEX, index)
    }

    /// Require the chain element thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_chain_element_identity::CERTIFICATE_THUMBPRINT,
            thumbprint,
        )
    }

    /// Require that the chain element thumbprint is present and non-empty.
    fn thumbprint_non_empty(self) -> Self {
        self.str_non_empty(x509_typed::x509_chain_element_identity::CERTIFICATE_THUMBPRINT)
    }

    /// Require the chain element subject to equal the provided value.
    fn subject_eq(self, subject: impl Into<String>) -> Self {
        self.str_eq(x509_typed::x509_chain_element_identity::SUBJECT, subject)
    }

    /// Require the chain element issuer to equal the provided value.
    fn issuer_eq(self, issuer: impl Into<String>) -> Self {
        self.str_eq(x509_typed::x509_chain_element_identity::ISSUER, issuer)
    }
}

pub trait X509ChainElementValidityWhereExt {
    /// Require the chain element index to equal `index`.
    fn index_eq(self, index: usize) -> Self;

    /// Require `not_before <= max_unix_seconds`.
    fn not_before_le(self, max_unix_seconds: i64) -> Self;

    /// Require `not_before >= min_unix_seconds`.
    fn not_before_ge(self, min_unix_seconds: i64) -> Self;

    /// Require `not_after <= max_unix_seconds`.
    fn not_after_le(self, max_unix_seconds: i64) -> Self;

    /// Require `not_after >= min_unix_seconds`.
    fn not_after_ge(self, min_unix_seconds: i64) -> Self;

    /// Require `not_before <= now_unix_seconds`.
    fn cert_not_before(self, now_unix_seconds: i64) -> Self;

    /// Require `not_after >= now_unix_seconds`.
    fn cert_not_after(self, now_unix_seconds: i64) -> Self;

    /// Require that `now_unix_seconds` lies within the certificate validity window.
    fn cert_valid_at(self, now_unix_seconds: i64) -> Self
    where
        Self: Sized,
    {
        self.cert_not_before(now_unix_seconds)
            .cert_not_after(now_unix_seconds)
    }
}

impl X509ChainElementValidityWhereExt for Where<X509ChainElementValidityFact> {
    /// Require the chain element index to equal `index`.
    fn index_eq(self, index: usize) -> Self {
        self.usize_eq(x509_typed::x509_chain_element_validity::INDEX, index)
    }

    /// Require `not_before <= max_unix_seconds`.
    fn not_before_le(self, max_unix_seconds: i64) -> Self {
        self.i64_le(
            x509_typed::x509_chain_element_validity::NOT_BEFORE_UNIX_SECONDS,
            max_unix_seconds,
        )
    }

    /// Require `not_before >= min_unix_seconds`.
    fn not_before_ge(self, min_unix_seconds: i64) -> Self {
        self.i64_ge(
            x509_typed::x509_chain_element_validity::NOT_BEFORE_UNIX_SECONDS,
            min_unix_seconds,
        )
    }

    /// Require `not_after <= max_unix_seconds`.
    fn not_after_le(self, max_unix_seconds: i64) -> Self {
        self.i64_le(
            x509_typed::x509_chain_element_validity::NOT_AFTER_UNIX_SECONDS,
            max_unix_seconds,
        )
    }

    /// Require `not_after >= min_unix_seconds`.
    fn not_after_ge(self, min_unix_seconds: i64) -> Self {
        self.i64_ge(
            x509_typed::x509_chain_element_validity::NOT_AFTER_UNIX_SECONDS,
            min_unix_seconds,
        )
    }

    /// Require `not_before <= now_unix_seconds`.
    fn cert_not_before(self, now_unix_seconds: i64) -> Self {
        self.not_before_le(now_unix_seconds)
    }

    /// Require `not_after >= now_unix_seconds`.
    fn cert_not_after(self, now_unix_seconds: i64) -> Self {
        self.not_after_ge(now_unix_seconds)
    }
}

pub trait X509ChainTrustedWhereExt {
    /// Require that the chain is trusted.
    fn require_trusted(self) -> Self;

    /// Require that the chain is not trusted.
    fn require_not_trusted(self) -> Self;

    /// Require that the chain could be built (the pack observed at least one element).
    fn require_chain_built(self) -> Self;

    /// Require that the chain could not be built.
    fn require_chain_not_built(self) -> Self;

    /// Require that the chain element count equals `expected`.
    fn element_count_eq(self, expected: usize) -> Self;

    /// Require that the chain status flags equal `expected`.
    fn status_flags_eq(self, expected: u32) -> Self;
}

impl X509ChainTrustedWhereExt for Where<X509ChainTrustedFact> {
    /// Require that the chain is trusted.
    fn require_trusted(self) -> Self {
        self.r#true(x509_typed::x509_chain_trusted::IS_TRUSTED)
    }

    /// Require that the chain is not trusted.
    fn require_not_trusted(self) -> Self {
        self.r#false(x509_typed::x509_chain_trusted::IS_TRUSTED)
    }

    /// Require that the chain could be built (the pack observed at least one element).
    fn require_chain_built(self) -> Self {
        self.r#true(x509_typed::x509_chain_trusted::CHAIN_BUILT)
    }

    /// Require that the chain could not be built.
    fn require_chain_not_built(self) -> Self {
        self.r#false(x509_typed::x509_chain_trusted::CHAIN_BUILT)
    }

    /// Require that the chain element count equals `expected`.
    fn element_count_eq(self, expected: usize) -> Self {
        self.usize_eq(x509_typed::x509_chain_trusted::ELEMENT_COUNT, expected)
    }

    /// Require that the chain status flags equal `expected`.
    fn status_flags_eq(self, expected: u32) -> Self {
        self.u32_eq(x509_typed::x509_chain_trusted::STATUS_FLAGS, expected)
    }
}

pub trait X509PublicKeyAlgorithmWhereExt {
    /// Require the certificate thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self;

    /// Require the public key algorithm OID to equal the provided value.
    fn algorithm_oid_eq(self, oid: impl Into<String>) -> Self;

    /// Require that the algorithm is flagged as PQC.
    fn require_pqc(self) -> Self;

    /// Require that the algorithm is not flagged as PQC.
    fn require_not_pqc(self) -> Self;
}

impl X509PublicKeyAlgorithmWhereExt for Where<X509PublicKeyAlgorithmFact> {
    /// Require the certificate thumbprint to equal the provided value.
    fn thumbprint_eq(self, thumbprint: impl Into<String>) -> Self {
        self.str_eq(
            x509_typed::x509_public_key_algorithm::CERTIFICATE_THUMBPRINT,
            thumbprint,
        )
    }

    /// Require the public key algorithm OID to equal the provided value.
    fn algorithm_oid_eq(self, oid: impl Into<String>) -> Self {
        self.str_eq(x509_typed::x509_public_key_algorithm::ALGORITHM_OID, oid)
    }

    /// Require that the algorithm is flagged as PQC.
    fn require_pqc(self) -> Self {
        self.r#true(x509_typed::x509_public_key_algorithm::IS_PQC)
    }

    /// Require that the algorithm is not flagged as PQC.
    fn require_not_pqc(self) -> Self {
        self.r#false(x509_typed::x509_public_key_algorithm::IS_PQC)
    }
}

/// Fluent helper methods for primary-signing-key scope rules.
///
/// These are intentionally "one click down" from `TrustPlanBuilder::for_primary_signing_key(...)`.
pub trait PrimarySigningKeyScopeRulesExt {
    /// Require that the x509 chain is trusted.
    fn require_x509_chain_trusted(self) -> Self;

    /// Require that the chain element at index 0 has a non-empty thumbprint.
    fn require_leaf_chain_thumbprint_present(self) -> Self;

    /// Require that a signing certificate identity fact is present.
    fn require_signing_certificate_present(self) -> Self;

    /// Pin the leaf certificate's subject name (chain element at index 0).
    fn require_leaf_subject_eq(self, subject: impl Into<String>) -> Self;

    /// Pin the issuer certificate's subject name (chain element at index 1).
    fn require_issuer_subject_eq(self, subject: impl Into<String>) -> Self;

    fn require_signing_certificate_subject_issuer_matches_leaf_chain_element(self) -> Self;

    /// If the issuer element (index 1) is missing, allow; otherwise require issuer chaining.
    fn require_leaf_issuer_is_next_chain_subject_optional(self) -> Self;

    /// Deny if a PQC algorithm is explicitly detected; allow if missing.
    fn require_not_pqc_algorithm_or_missing(self) -> Self;
}

impl PrimarySigningKeyScopeRulesExt for ScopeRules<PrimarySigningKeyScope> {
    /// Require that the x509 chain is trusted.
    fn require_x509_chain_trusted(self) -> Self {
        self.require::<X509ChainTrustedFact>(|w| w.require_trusted())
    }

    /// Require that the chain element at index 0 has a non-empty thumbprint.
    fn require_leaf_chain_thumbprint_present(self) -> Self {
        self.require::<X509ChainElementIdentityFact>(|w| w.index_eq(0).thumbprint_non_empty())
    }

    /// Require that a signing certificate identity fact is present.
    fn require_signing_certificate_present(self) -> Self {
        self.require::<X509SigningCertificateIdentityFact>(|w| w)
    }

    fn require_leaf_subject_eq(self, subject: impl Into<String>) -> Self {
        let subject = subject.into();
        self.require::<X509ChainElementIdentityFact>(|w| w.index_eq(0).subject_eq(subject))
    }

    fn require_issuer_subject_eq(self, subject: impl Into<String>) -> Self {
        let subject = subject.into();
        self.require::<X509ChainElementIdentityFact>(|w| w.index_eq(1).subject_eq(subject))
    }

    fn require_signing_certificate_subject_issuer_matches_leaf_chain_element(self) -> Self {
        let subject_selector = |s: &cose_sign1_validation_trust::subject::TrustSubject| s.clone();

        let left_selector = FactSelector::first();
        let right_selector = FactSelector::first()
            .where_usize(crate::facts::fields::x509_chain_element_identity::INDEX, 0);

        let rule = require_facts_match::<
            X509SigningCertificateIdentityFact,
            X509ChainElementIdentityFact,
            _,
        >(
            "x509_signing_cert_matches_leaf_chain_element",
            subject_selector,
            left_selector,
            right_selector,
            vec![
                (
                    crate::facts::fields::x509_signing_certificate_identity::SUBJECT,
                    crate::facts::fields::x509_chain_element_identity::SUBJECT,
                ),
                (
                    crate::facts::fields::x509_signing_certificate_identity::ISSUER,
                    crate::facts::fields::x509_chain_element_identity::ISSUER,
                ),
            ],
            MissingBehavior::Deny,
            "SubjectIssuerMismatch",
        );

        self.require_rule(
            rule,
            [
                FactKey::of::<X509SigningCertificateIdentityFact>(),
                FactKey::of::<X509ChainElementIdentityFact>(),
            ],
        )
    }

    /// If the issuer element (index 1) is missing, allow; otherwise require issuer chaining.
    fn require_leaf_issuer_is_next_chain_subject_optional(self) -> Self {
        let subject_selector = |s: &cose_sign1_validation_trust::subject::TrustSubject| s.clone();

        let left_selector = FactSelector::first();
        let right_selector = FactSelector::first()
            .where_usize(crate::facts::fields::x509_chain_element_identity::INDEX, 1);

        let rule = require_facts_match::<
            X509SigningCertificateIdentityFact,
            X509ChainElementIdentityFact,
            _,
        >(
            "x509_issuer_is_next_subject",
            subject_selector,
            left_selector,
            right_selector,
            vec![(
                crate::facts::fields::x509_signing_certificate_identity::ISSUER,
                crate::facts::fields::x509_chain_element_identity::SUBJECT,
            )],
            MissingBehavior::Allow,
            "IssuerNotNextSubject",
        );

        self.require_rule(
            rule,
            [
                FactKey::of::<X509SigningCertificateIdentityFact>(),
                FactKey::of::<X509ChainElementIdentityFact>(),
            ],
        )
    }

    /// Deny if a PQC algorithm is explicitly detected; allow if missing.
    fn require_not_pqc_algorithm_or_missing(self) -> Self {
        let subject_selector = |s: &cose_sign1_validation_trust::subject::TrustSubject| s.clone();

        // If the fact is missing, `require_fact_bool` denies, and NOT(deny) => trusted.
        // If the fact is present and IS_PQC == true, inner is trusted and NOT => denied.
        let is_pqc = require_fact_bool::<X509PublicKeyAlgorithmFact, _>(
            "pqc_algorithm",
            subject_selector,
            FactSelector::first(),
            crate::facts::fields::x509_public_key_algorithm::IS_PQC,
            true,
            "NotPqc",
        );

        let not_pqc = not_with_reason("not_pqc", is_pqc, "PQC algorithms are disallowed");

        self.require_rule(not_pqc, [FactKey::of::<X509PublicKeyAlgorithmFact>()])
    }
}
