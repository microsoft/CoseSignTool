// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Canonical JSON serialization (D9 cache-key invariant).
//!
//! "Canonical" here means: for a given input [`crate::spec::TrustPolicySpec`], two calls to
//! [`to_canonical_json`] from the same build produce byte-identical output. The translator
//! cache (Phase 2) keys on the BLAKE3 hash of this output, so any non-determinism here would
//! poison the cache.
//!
//! Determinism guarantees:
//! - Object keys appearing in property-assertion maps use [`std::collections::BTreeMap`] in
//!   the spec, so they iterate in lexicographic order. `serde_json::Map` is itself a
//!   `BTreeMap` in this crate (the `preserve_order` feature is **not** enabled in
//!   `[workspace.dependencies]`), so embedded `serde_json::Value::Object` literals also sort.
//! - Vector slots (`And.specs`, `Or.specs`, `requirements`, ...) are **order-preserving**:
//!   short-circuit evaluation makes order semantically meaningful, so the canonical form
//!   intentionally preserves authoring order rather than sorting.
//! - Variant tag emission order is fixed by `serde_json` (the tag field is emitted first).
//!
//! Compactness:
//! - The output uses `serde_json::to_string` (no whitespace) — every byte is significant.

use crate::spec::TrustPolicySpec;

/// Serialize `spec` to its canonical JSON representation.
///
/// See module docs for the determinism contract.
pub fn to_canonical_json(spec: &TrustPolicySpec) -> Result<String, serde_json::Error> {
    serde_json::to_string(spec)
}

/// Serialize `spec` to its canonical pretty-printed form.
///
/// Pretty output is **not** stability-bound — only [`to_canonical_json`] participates in the
/// cache-key contract. Pretty output is provided for human inspection and golden-file tests.
pub fn to_canonical_pretty(spec: &TrustPolicySpec) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(spec)
}
