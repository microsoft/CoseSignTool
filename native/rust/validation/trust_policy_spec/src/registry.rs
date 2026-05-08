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

use std::collections::{BTreeMap, BTreeSet};

use cose_sign1_validation_primitives::{validate_fact_id, TrustFactDescriptor};

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
/// **Deprecated as of Phase 3 (`np-fact-registry`)** — superseded by
/// [`HandRolledFactRegistry::from_packs`]. Retained as the conformance baseline that the
/// `hand_rolled_equals_static_baseline` test diff-checks; will be removed in Phase 5a.
///
/// Lifetimes:
/// - `fact_id` strings are owned (`String`) so the set can be returned as a borrow.
/// - `type_name` strings are `&'static str` (compile-time string literals from
///   `std::any::type_name`-style invocations in the Phase 3 lowerer).
#[deprecated(
    since = "0.1.0",
    note = "Phase 3 superseded StaticFactRegistry. Use HandRolledFactRegistry::from_packs(&[...]) and pass each pack's __cose_sign1_trust_facts() output. Retained as conformance baseline; will be removed in Phase 5a."
)]
pub struct StaticFactRegistry {
    fact_ids: BTreeSet<String>,
    /// `(fact_id, type_name)` pairs in deterministic order.
    forward: Vec<(&'static str, &'static str)>,
}

#[allow(deprecated)]
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

#[allow(deprecated)]
impl Default for StaticFactRegistry {
    fn default() -> Self {
        Self::default_mappings()
    }
}

#[allow(deprecated)]
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
// =====================================================================
// Phase 3 (np-fact-registry, R1) — HandRolledFactRegistry.
// =====================================================================

/// Errors returned when constructing a [`HandRolledFactRegistry`].
///
/// All registration errors are diagnostic-coded under the `TPX3xx`
/// family so emitters in the rest of the trust-policy pipeline can
/// route them consistently.
///
/// `#[non_exhaustive]` permits future additive `TPX3xx` variants
/// (e.g. cross-pack capability conflicts) without breaking
/// downstream `match` consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryError {
    /// Two distinct concrete fact types attempted to claim the same
    /// `FACT_ID`. Diagnostic code `TPX300`.
    DuplicateId {
        /// The id that was claimed twice.
        id: String,
        /// `std::any::type_name` of the type that registered the id first.
        first_type_name: String,
        /// `std::any::type_name` of the type that tried to re-register.
        second_type_name: String,
    },
    /// A fact descriptor's id failed the `^[a-z][a-z0-9-]*/v[0-9]+$`
    /// regex. Diagnostic code `TPX301`.
    InvalidIdFormat {
        /// The malformed id.
        id: String,
        /// Type name that registered the malformed id.
        type_name: String,
    },
    /// Two distinct `FACT_ID`s mapped to the same concrete `type_name`.
    /// Forbidden because the reverse (`try_get_fact_id`) lookup would
    /// silently lose one mapping. Diagnostic code `TPX302`.
    ///
    /// In practice this is unreachable through [`register_facts!`]
    /// (each Rust type has exactly one `TrustFactWithId` impl with a
    /// single `FACT_ID`), but [`HandRolledFactRegistry::from_packs`]
    /// accepts arbitrary [`TrustFactDescriptor`]s, so the public
    /// constructor has to defend the invariant.
    DuplicateTypeName {
        /// The type name claimed by two distinct ids.
        type_name: String,
        /// The id registered first against this type name.
        first_id: String,
        /// The id that tried to re-register.
        second_id: String,
    },
}

impl RegistryError {
    /// Returns the stable `TPX3xx` diagnostic code for this error variant.
    pub fn diagnostic_code(&self) -> &'static str {
        match self {
            RegistryError::DuplicateId { .. } => "TPX300",
            RegistryError::InvalidIdFormat { .. } => "TPX301",
            RegistryError::DuplicateTypeName { .. } => "TPX302",
        }
    }
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::DuplicateId {
                id,
                first_type_name,
                second_type_name,
            } => write!(
                f,
                "[TPX300] duplicate trust-fact id {id:?}: first registered by {first_type_name}, attempted to re-register from {second_type_name}"
            ),
            RegistryError::InvalidIdFormat { id, type_name } => write!(
                f,
                "[TPX301] trust-fact id {id:?} (registered by {type_name}) does not match ^[a-z][a-z0-9-]*/v[0-9]+$ — every fact id must start with a lowercase letter, contain only [a-z0-9-], and end with /vN"
            ),
            RegistryError::DuplicateTypeName {
                type_name,
                first_id,
                second_id,
            } => write!(
                f,
                "[TPX302] trust-fact type {type_name:?} mapped to two ids: first registered as {first_id:?}, attempted to re-register as {second_id:?}"
            ),
        }
    }
}

impl std::error::Error for RegistryError {}

/// Workspace-level fact-id registry built from per-pack
/// `__cose_sign1_trust_facts()` outputs.
///
/// Phase 3 (`np-fact-registry`) replacement for the deprecated
/// [`StaticFactRegistry`]. Each pack crate calls `register_facts! { ... }`
/// in its `lib.rs`, which expands to a
/// `pub fn __cose_sign1_trust_facts() -> Vec<TrustFactDescriptor>`
/// (per **R1**: hand-rolled macro, no third-party fact-registration
/// crates). The application then constructs the registry by passing
/// each pack's vector explicitly:
///
/// ```ignore
/// use cose_sign1_trust_policy_spec::HandRolledFactRegistry;
///
/// let registry = HandRolledFactRegistry::from_packs(&[
///     cose_sign1_certificates::__cose_sign1_trust_facts(),
///     cose_sign1_transparent_mst::__cose_sign1_trust_facts(),
///     cose_sign1_validation::__cose_sign1_trust_facts(),
/// ]).expect("trust-fact registry construction");
/// ```
///
/// # Determinism
///
/// Internal storage uses [`BTreeMap`] keyed by id, so iteration is
/// stable and sorted regardless of the order packs are passed in.
/// Lookup is O(log n) — appropriate for the single-digit-thousands
/// upper bound on registered facts. The Phase 1 baseline is 16 facts;
/// performance below the noise floor for any realistic registry size.
///
/// # Memory
///
/// The lookup maps are keyed by `&'static str` borrowed directly from
/// each descriptor — fact ids and type names live in the binary's
/// rodata via `const FACT_ID: &'static str` and `std::any::type_name`,
/// so the registry pays no extra allocation per id beyond the single
/// owned-String mirror that [`IFactRegistry::all_fact_ids`] returns.
///
/// # Validation
///
/// Construction rejects:
/// - duplicate ids ([`RegistryError::DuplicateId`], `TPX300`),
/// - malformed ids ([`RegistryError::InvalidIdFormat`], `TPX301`),
/// - duplicate type names ([`RegistryError::DuplicateTypeName`], `TPX302`).
///
/// A fact type missing the `TrustFactWithId` impl is statically
/// uncallable in `register_facts!{}` — that's a compile error, not a
/// runtime check.
#[derive(Debug, Clone)]
pub struct HandRolledFactRegistry {
    /// Forward index, id → descriptor. Keys are `&'static str` borrows
    /// of `descriptor.id`, so no per-id String allocation.
    by_id: BTreeMap<&'static str, TrustFactDescriptor>,
    /// Reverse index, type_name → descriptor. Uniqueness is enforced
    /// at construction time ([`RegistryError::DuplicateTypeName`]).
    by_type_name: BTreeMap<&'static str, TrustFactDescriptor>,
    /// Owned id mirror returned by [`IFactRegistry::all_fact_ids`].
    /// Kept owned to honor the Phase 1 trait contract.
    all_ids: BTreeSet<String>,
}

impl HandRolledFactRegistry {
    /// Construct an empty registry. Useful for tests that exercise
    /// unknown-fact-id paths.
    pub fn empty() -> Self {
        Self {
            by_id: BTreeMap::new(),
            by_type_name: BTreeMap::new(),
            all_ids: BTreeSet::new(),
        }
    }

    /// Build a workspace registry from a list of per-pack descriptor
    /// vectors. See the type-level docs for example wiring.
    ///
    /// # Errors
    ///
    /// Returns a [`RegistryError`] when:
    /// - two descriptors share an id ([`RegistryError::DuplicateId`], `TPX300`),
    /// - a descriptor's id fails the canonical regex
    ///   ([`RegistryError::InvalidIdFormat`], `TPX301`),
    /// - two descriptors share a `type_name`
    ///   ([`RegistryError::DuplicateTypeName`], `TPX302`).
    pub fn from_packs(
        pack_descriptors: &[Vec<TrustFactDescriptor>],
    ) -> Result<Self, RegistryError> {
        let mut by_id: BTreeMap<&'static str, TrustFactDescriptor> = BTreeMap::new();
        let mut by_type_name: BTreeMap<&'static str, TrustFactDescriptor> = BTreeMap::new();
        let mut all_ids: BTreeSet<String> = BTreeSet::new();

        for pack in pack_descriptors {
            for descriptor in pack {
                if !validate_fact_id(descriptor.id) {
                    return Err(RegistryError::InvalidIdFormat {
                        id: descriptor.id.to_string(),
                        type_name: descriptor.type_name.to_string(),
                    });
                }
                if let Some(existing) = by_id.get(descriptor.id) {
                    return Err(RegistryError::DuplicateId {
                        id: descriptor.id.to_string(),
                        first_type_name: existing.type_name.to_string(),
                        second_type_name: descriptor.type_name.to_string(),
                    });
                }
                if let Some(existing) = by_type_name.get(descriptor.type_name) {
                    return Err(RegistryError::DuplicateTypeName {
                        type_name: descriptor.type_name.to_string(),
                        first_id: existing.id.to_string(),
                        second_id: descriptor.id.to_string(),
                    });
                }
                by_id.insert(descriptor.id, descriptor.clone());
                by_type_name.insert(descriptor.type_name, descriptor.clone());
                all_ids.insert(descriptor.id.to_string());
            }
        }

        Ok(Self {
            by_id,
            by_type_name,
            all_ids,
        })
    }

    /// Returns the descriptor registered for `fact_id`, or `None`.
    ///
    /// Phase 3 callers preferring the richer descriptor over the raw
    /// type name use this; [`IFactRegistry::try_get_fact_type`] remains
    /// for Phase 1 compatibility.
    pub fn try_get_descriptor(&self, fact_id: &str) -> Option<&TrustFactDescriptor> {
        self.by_id.get(fact_id)
    }

    /// Returns the descriptor registered for `type_name`, or `None`.
    pub fn try_get_descriptor_by_type_name(
        &self,
        type_name: &str,
    ) -> Option<&TrustFactDescriptor> {
        self.by_type_name.get(type_name)
    }

    /// Returns the count of registered fact ids.
    pub fn len(&self) -> usize {
        self.all_ids.len()
    }

    /// Returns `true` if the registry has no registered facts.
    pub fn is_empty(&self) -> bool {
        self.all_ids.is_empty()
    }

    /// Returns an iterator over every registered descriptor in id order.
    pub fn iter_descriptors(&self) -> impl Iterator<Item = &TrustFactDescriptor> {
        self.by_id.values()
    }
}

impl IFactRegistry for HandRolledFactRegistry {
    fn try_get_fact_type(&self, fact_id: &str) -> Option<&'static str> {
        self.by_id.get(fact_id).map(|d| d.type_name)
    }

    fn try_get_fact_id(&self, type_name: &str) -> Option<&'static str> {
        self.by_type_name.get(type_name).map(|d| d.id)
    }

    fn all_fact_ids(&self) -> &BTreeSet<String> {
        &self.all_ids
    }
}
