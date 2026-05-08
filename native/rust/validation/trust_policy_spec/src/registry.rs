// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fact-id registry abstraction (Phase 1).
//!
//! [`IFactRegistry`] is the bridge between the textual `fact_id` carried in a
//! [`crate::spec::TrustPolicySpec::RequireFact`] node and the in-memory fact type that
//! actually satisfies the predicate at evaluation time.
//!
//! Phase 1 ships [`StaticFactRegistry`] — a hand-rolled mapping that mirrors the .NET
//! `StaticFactRegistry.BuildDefaultMappings()`. The static map is **temporary**: Phase 3
//! (`np-fact-registry`) supersedes it with a hand-rolled `register_facts!()` macro per pack
//! (R1 decision: 2026-05-08).
//!
//! # Stable identifier format
//!
//! Fact ids are stable, semver-versioned strings matching `^[a-z][a-z0-9-]*/v[0-9]+$`.
//! The version segment lets a fact's shape evolve independently of its semantic identity:
//! a v2 fact lives at `<id>/v2` and is not interchangeable with `<id>/v1`.

use std::collections::BTreeSet;

/// Abstraction over a fact-id → type-name resolver.
///
/// Phase 1 surfaces only the type-name string (sufficient for the IR roundtrip + diagnostic
/// messages); Phase 3 will introduce a richer descriptor (TypeId, property accessor) so the
/// compiler can lower [`crate::spec::TrustPolicySpec::RequireFact`] into typed
/// `Field<TFact, T>` checks.
///
/// # API stability strategy
///
/// This trait is intentionally minimal in Phase 1. Phase 3 (`np-fact-registry`) extends it
/// via the [`FactRegistryExt`] companion trait — Phase 3 implementors layer the additional
/// resolution shape on the same registry without breaking existing consumers. Adding
/// methods to `IFactRegistry` itself would be a source-breaking change for downstream
/// implementors and is therefore avoided.
pub trait IFactRegistry: Send + Sync {
    /// Returns the runtime type name that satisfies `fact_id`, or `None` when `fact_id`
    /// is not registered.
    fn try_get_fact_type(&self, fact_id: &str) -> Option<&'static str>;

    /// Reverse mapping: returns the canonical fact id for a registered type name.
    ///
    /// Used by audit / diagnostic surfaces that hold a fact type and want to emit the
    /// stable id on the wire.
    fn try_get_fact_id(&self, type_name: &str) -> Option<&'static str>;

    /// All registered fact ids, in deterministic (sorted) iteration order.
    fn all_fact_ids(&self) -> &BTreeSet<String>;
}

/// Forward-compatible extension surface for [`IFactRegistry`] consumers.
///
/// Phase 3 adds methods here (e.g. `try_get_fact_type_id`, `try_get_property_accessor`)
/// without disturbing the Phase 1 [`IFactRegistry`] contract. Consumers that only need
/// id↔name resolution depend on [`IFactRegistry`]; consumers that need richer access
/// require this trait.
///
/// Phase 1 ships an empty default — every method is provided with a default implementation
/// that returns `None` / empty so blanket-implementing this trait on every Phase 1
/// `IFactRegistry` is a one-liner.
pub trait FactRegistryExt: IFactRegistry {
    /// Returns the count of registered fact ids. Default implementation reads
    /// [`IFactRegistry::all_fact_ids`].
    fn fact_id_count(&self) -> usize {
        self.all_fact_ids().len()
    }
}

// Blanket impl: every IFactRegistry is automatically a FactRegistryExt.
impl<T: IFactRegistry + ?Sized> FactRegistryExt for T {}

/// Hand-rolled fact-id mapping mirroring the .NET `StaticFactRegistry.BuildDefaultMappings()`.
///
/// **Temporary**; superseded by hand-rolled `register_facts!()` macro in Phase 3.
///
/// Lifetimes:
/// - `fact_id` strings are owned (`String`) so the set can be returned as a borrow.
/// - `type_name` strings are `&'static str` (compile-time string literals from
///   `std::any::type_name`-style invocations in the Phase 3 lowerer).
pub struct StaticFactRegistry {
    fact_ids: BTreeSet<String>,
    /// `(fact_id, type_name)` pairs in deterministic order.
    forward: Vec<(&'static str, &'static str)>,
}

impl StaticFactRegistry {
    /// Build the default static mapping. Mirrors the .NET reference list verbatim.
    ///
    /// IMPORTANT: every entry's id MUST match `^[a-z][a-z0-9-]*/v[0-9]+$`. The conformance
    /// test in `tests/static_registry.rs` enforces this.
    pub fn default_mappings() -> Self {
        // The type-name column is intentionally a stable, hand-curated string. Phase 3
        // replaces these with `std::any::type_name::<T>()` outputs from the
        // `register_facts!()` macro, which run-time-derive the names from the concrete
        // fact types.
        const ENTRIES: &[(&str, &str)] = &[
            // Certificates pack.
            (
                "x509-chain-trusted/v1",
                "cose_sign1_certificates::validation::facts::X509ChainTrustedFact",
            ),
            (
                "x509-cert-identity/v1",
                "cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityFact",
            ),
            (
                "x509-cert-eku/v1",
                "cose_sign1_certificates::validation::facts::X509SigningCertificateEkuFact",
            ),
            (
                "x509-cert-key-usage/v1",
                "cose_sign1_certificates::validation::facts::X509SigningCertificateKeyUsageFact",
            ),
            (
                "x509-cert-basic-constraints/v1",
                "cose_sign1_certificates::validation::facts::X509SigningCertificateBasicConstraintsFact",
            ),
            (
                "x509-cert-identity-allowed/v1",
                "cose_sign1_certificates::validation::facts::X509SigningCertificateIdentityAllowedFact",
            ),
            (
                "x509-x5chain-cert-identity/v1",
                "cose_sign1_certificates::validation::facts::X509X5ChainCertificateIdentityFact",
            ),
            (
                "x509-chain-element-identity/v1",
                "cose_sign1_certificates::validation::facts::X509ChainElementIdentityFact",
            ),
            (
                "certificate-signing-key-trust/v1",
                "cose_sign1_certificates::validation::facts::CertificateSigningKeyTrustFact",
            ),
            // MST pack.
            (
                "mst-receipt-present/v1",
                "cose_sign1_transparent_mst::validation::facts::MstReceiptPresentFact",
            ),
            (
                "mst-receipt-trusted/v1",
                "cose_sign1_transparent_mst::validation::facts::MstReceiptTrustedFact",
            ),
            (
                "mst-receipt-issuer-host/v1",
                "cose_sign1_transparent_mst::validation::facts::MstReceiptIssuerFact",
            ),
            // Message-level facts (validation/core).
            (
                "content-type/v1",
                "cose_sign1_validation::message_facts::ContentTypeFact",
            ),
            (
                "detached-payload-present/v1",
                "cose_sign1_validation::message_facts::DetachedPayloadPresentFact",
            ),
            (
                "counter-signature-subject/v1",
                "cose_sign1_validation::message_facts::CounterSignatureSubjectFact",
            ),
            (
                "unknown-counter-signature-bytes/v1",
                "cose_sign1_validation::message_facts::UnknownCounterSignatureBytesFact",
            ),
        ];

        let mut fact_ids = BTreeSet::new();
        let mut forward = Vec::with_capacity(ENTRIES.len());
        for (id, type_name) in ENTRIES {
            assert!(
                fact_ids.insert((*id).to_owned()),
                "duplicate fact id in default mappings: {id}"
            );
            forward.push((*id, *type_name));
        }

        Self { fact_ids, forward }
    }

    /// Construct an empty registry. Useful for tests that exercise unknown-fact-id paths.
    pub fn empty() -> Self {
        Self {
            fact_ids: BTreeSet::new(),
            forward: Vec::new(),
        }
    }
}

impl Default for StaticFactRegistry {
    fn default() -> Self {
        Self::default_mappings()
    }
}

impl IFactRegistry for StaticFactRegistry {
    fn try_get_fact_type(&self, fact_id: &str) -> Option<&'static str> {
        self.forward
            .iter()
            .find(|(id, _)| *id == fact_id)
            .map(|(_, type_name)| *type_name)
    }

    fn try_get_fact_id(&self, type_name: &str) -> Option<&'static str> {
        self.forward
            .iter()
            .find(|(_, name)| *name == type_name)
            .map(|(id, _)| *id)
    }

    fn all_fact_ids(&self) -> &BTreeSet<String> {
        &self.fact_ids
    }
}
