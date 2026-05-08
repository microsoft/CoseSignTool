// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stable, semver-versioned trust-fact identifiers — the compile-time
//! contract that supersedes Phase 1's hand-curated `StaticFactRegistry` per
//! decision **R1** of `eval-trust-policy-translation-contract-rust.md`.
//!
//! # The contract
//!
//! Every concrete trust-fact type that participates in a
//! [`TrustPolicySpec`](../../trust_policy_spec/index.html) `RequireFact`
//! predicate implements [`TrustFactWithId`] with a `const FACT_ID` matching
//! the regex `^[a-z][a-z0-9-]*/v[0-9]+$`. A fact's id is **immutable**:
//! breaking shape changes ship as a new `/v2` id, never as a mutation of
//! `/v1`. The Phase 1 baseline (16 ids) is the conformance anchor.
//!
//! # Wiring
//!
//! Each pack crate calls [`register_facts!`] in its `lib.rs` to enumerate
//! the facts it contributes. The macro expands to a `pub fn
//! __cose_sign1_trust_facts() -> Vec<TrustFactDescriptor>` that the
//! workspace-level `HandRolledFactRegistry::from_packs(&[...])` collects
//! by name. No reflection, no third-party crates, no link-time magic.
//!
//! # Validation strategy
//!
//! Hard-checking the id pattern at `const fn` time fails on stable Rust
//! (no `&str` indexing in `const`). Instead this module ships a
//! `const fn` validator over byte slices that the calling crate can wire
//! into a `const _: () = assert!(validate_fact_id(<T as TrustFactWithId>::FACT_ID));`
//! one-liner — that gives compile-time enforcement without nightly
//! features. The runtime registry also rejects malformed ids on
//! construction, so a missed compile-time assertion still fails loudly
//! at startup.

/// Stable, semver-versioned identifier for a concrete trust fact.
///
/// A `FACT_ID` is the wire-stable string carried in
/// `TrustPolicySpec::RequireFact { fact_id, .. }` and emitted in audit
/// trails. It MUST match `^[a-z][a-z0-9-]*/v[0-9]+$` and MUST NOT change
/// for the lifetime of a given concrete type. Breaking changes to a
/// fact's shape ship as a new type with a new `/v2` id.
///
/// # Example
///
/// ```ignore
/// use cose_sign1_validation_primitives::TrustFactWithId;
///
/// pub struct ContentTypeFact { /* ... */ }
///
/// impl TrustFactWithId for ContentTypeFact {
///     const FACT_ID: &'static str = "content-type/v1";
/// }
///
/// // Optional belt-and-suspenders compile-time format check:
/// const _: () = assert!(
///     cose_sign1_validation_primitives::validate_fact_id(
///         <ContentTypeFact as TrustFactWithId>::FACT_ID,
///     )
/// );
/// ```
pub trait TrustFactWithId {
    /// The stable identifier — MUST match `^[a-z][a-z0-9-]*/v[0-9]+$` and
    /// MUST NOT change for the lifetime of the concrete type.
    const FACT_ID: &'static str;
}

/// Self-describing record of a registered trust fact, collected by
/// [`register_facts!`] at startup. Carries enough information for the
/// workspace registry to perform id ↔ type-name resolution and for
/// diagnostic surfaces to attribute a fact to its owning crate.
///
/// `#[non_exhaustive]` permits future additive fields (e.g. a property
/// accessor table, a [`std::any::TypeId`]) without breaking downstream
/// pattern-matching consumers.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustFactDescriptor {
    /// The stable identifier — same value as the source type's
    /// [`TrustFactWithId::FACT_ID`].
    pub id: &'static str,
    /// `std::any::type_name` of the concrete fact type at the point of
    /// registration. Used only for diagnostics; never parsed.
    pub type_name: &'static str,
    /// `CARGO_PKG_NAME` of the registering crate, captured at expansion
    /// time. Lets diagnostic surfaces attribute a fact to the pack that
    /// owns it.
    pub crate_name: &'static str,
}

impl TrustFactDescriptor {
    /// Construct a descriptor explicitly. Internal callers prefer
    /// [`register_facts!`] — this helper exists for tests and for
    /// hand-built registries in conformance fixtures.
    pub const fn new(
        id: &'static str,
        type_name: &'static str,
        crate_name: &'static str,
    ) -> Self {
        Self {
            id,
            type_name,
            crate_name,
        }
    }
}

/// `const fn` validator for the fact-id regex `^[a-z][a-z0-9-]*/v[0-9]+$`.
///
/// Returns `true` iff `id` matches the pattern. Designed to be wired into
/// a `const _: () = assert!(validate_fact_id(<T as TrustFactWithId>::FACT_ID));`
/// one-liner alongside each `impl TrustFactWithId` so a malformed id
/// fails the build, not the binary.
///
/// The runtime registry also re-validates on construction; this gives
/// belt-and-suspenders coverage even when the const-assert is omitted.
#[must_use]
pub const fn validate_fact_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    // First byte: ASCII lowercase letter.
    if !(bytes[0] >= b'a' && bytes[0] <= b'z') {
        return false;
    }

    // Walk forward to the slash, allowing only [a-z0-9-].
    let mut i = 1;
    let mut slash_at: Option<usize> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'/' {
            slash_at = Some(i);
            break;
        }
        let ok = (b >= b'a' && b <= b'z')
            || (b >= b'0' && b <= b'9')
            || b == b'-';
        if !ok {
            return false;
        }
        i += 1;
    }

    let slash_at = match slash_at {
        Some(s) => s,
        None => return false,
    };
    // Need at least "/vN".
    if bytes.len() < slash_at + 3 {
        return false;
    }
    if bytes[slash_at + 1] != b'v' {
        return false;
    }
    // Every remaining byte must be ASCII digit.
    let mut j = slash_at + 2;
    while j < bytes.len() {
        let b = bytes[j];
        if !(b >= b'0' && b <= b'9') {
            return false;
        }
        j += 1;
    }
    true
}

/// Declarative registration macro — each pack crate calls it from its
/// `lib.rs` to enumerate the concrete fact types it contributes.
///
/// # Expansion
///
/// ```ignore
/// register_facts! {
///     ContentTypeFact,
///     DetachedPayloadPresentFact,
/// }
/// ```
///
/// expands to:
///
/// ```ignore
/// pub fn __cose_sign1_trust_facts() -> ::std::vec::Vec<TrustFactDescriptor> {
///     ::std::vec![
///         TrustFactDescriptor::new(
///             <ContentTypeFact as TrustFactWithId>::FACT_ID,
///             ::std::any::type_name::<ContentTypeFact>(),
///             env!("CARGO_PKG_NAME"),
///         ),
///         TrustFactDescriptor::new(
///             <DetachedPayloadPresentFact as TrustFactWithId>::FACT_ID,
///             ::std::any::type_name::<DetachedPayloadPresentFact>(),
///             env!("CARGO_PKG_NAME"),
///         ),
///     ]
/// }
/// ```
///
/// The workspace registry calls each pack's `__cose_sign1_trust_facts()`
/// explicitly — no reflection, no link-time discovery, no third-party
/// crates (per **R1**).
///
/// # Determinism
///
/// The output `Vec` preserves source order. The workspace registry
/// re-sorts by id when building its `BTreeMap`, so the order of types
/// inside `register_facts!{}` does not affect the canonical output, but
/// is stable for diagnostic output.
#[macro_export]
macro_rules! register_facts {
    ( $($ty:ty),+ $(,)? ) => {
        /// Auto-generated by `register_facts!{}` — returns the trust-fact
        /// descriptors contributed by this crate. Consumed by
        /// `HandRolledFactRegistry::from_packs(&[...])`.
        ///
        /// The `__` prefix marks the symbol as a stable plumbing point
        /// rather than a public API; do not call it directly.
        pub fn __cose_sign1_trust_facts() -> ::std::vec::Vec<
            $crate::TrustFactDescriptor,
        > {
            ::std::vec![
                $(
                    $crate::TrustFactDescriptor::new(
                        <$ty as $crate::TrustFactWithId>::FACT_ID,
                        ::std::any::type_name::<$ty>(),
                        env!("CARGO_PKG_NAME"),
                    ),
                )+
            ]
        }
    };
}
