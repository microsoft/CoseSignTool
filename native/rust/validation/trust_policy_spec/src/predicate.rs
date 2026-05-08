// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hybrid predicate language for `RequireFact` (D1).
//!
//! Two surfaces are supported:
//!
//! - [`PropertyAssertionPredicateSpec`] — sugar for "all of these properties equal these values".
//!   Maps to typed `Field<TFact, T>` checks at lowering time (Phase 3).
//! - [`PathOperatorPredicateSpec`] — universal fallback. A JSON-pointer-style path plus an
//!   operator keyword and an optional value. Lowers to a `serde_json::Value` walker that
//!   inspects facts at runtime.
//!
//! [`FactPredicateSpec`] is `#[serde(untagged)]`: serde tries each variant in declaration order.
//! Property-assertion is tried first because its shape (`{"assertions": {...}}`) is unambiguous;
//! path-operator (`{"path": ..., "operator": ...}`) is the universal fallback.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Set of property→value equality assertions, AND-combined.
///
/// `assertions` uses `BTreeMap` so that canonical JSON serialization is deterministic
/// regardless of insertion order — a hard requirement of D9 (cache-key stability).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PropertyAssertionPredicateSpec {
    /// Property name → expected JSON value. All assertions are AND-combined.
    pub assertions: BTreeMap<String, serde_json::Value>,
}

impl PropertyAssertionPredicateSpec {
    /// Construct a new, empty assertion set.
    pub fn new() -> Self {
        Self {
            assertions: BTreeMap::new(),
        }
    }

    /// Builder helper: add (or replace) a property assertion.
    pub fn with(mut self, property: impl Into<String>, value: impl Into<serde_json::Value>) -> Self {
        self.assertions.insert(property.into(), value.into());
        self
    }
}

impl Default for PropertyAssertionPredicateSpec {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON-pointer-style predicate with a single operator and (optional) value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathOperatorPredicateSpec {
    /// JSON-pointer-style dotted path into the fact's serialized properties (e.g. `chain.length`).
    pub path: String,
    /// Operator applied to the path's value.
    pub operator: PredicateOperator,
    /// Operand value. `None` is only legal for `Exists` (presence-only check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

/// Closed enum of supported predicate operators.
///
/// Stable identifiers; values must round-trip through serde without alias drift.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredicateOperator {
    /// The path resolves to a present (non-null) value. `value` MUST be `None`.
    Exists,
    /// `path == value`.
    Equals,
    /// `path != value`.
    NotEquals,
    /// `path < value` (numeric).
    LessThan,
    /// `path <= value` (numeric).
    LessThanOrEqual,
    /// `path > value` (numeric).
    GreaterThan,
    /// `path >= value` (numeric).
    GreaterThanOrEqual,
    /// `path` is a string and starts with `value` (string).
    StartsWith,
    /// `path` is a string and ends with `value` (string).
    EndsWith,
    /// `path` is a string/array and contains `value`.
    Contains,
    /// `path` is one of the elements of `value` (where `value` is a JSON array).
    In,
}

impl PredicateOperator {
    /// Returns `true` when this operator is presence-only (does not consume a value operand).
    pub fn is_presence_only(self) -> bool {
        matches!(self, PredicateOperator::Exists)
    }
}

/// Hybrid fact predicate — either a property-assertion or a path-operator predicate.
///
/// Serialized untagged: serde tries the variants in order. Use [`Self::is_property_assertion`]
/// or pattern-match to disambiguate after deserialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FactPredicateSpec {
    /// Sugar variant: AND of property-equality assertions.
    Property(PropertyAssertionPredicateSpec),
    /// Universal fallback: path-operator predicate.
    PathOperator(PathOperatorPredicateSpec),
}

impl FactPredicateSpec {
    /// Construct a property-assertion predicate from an iterator of `(name, value)` pairs.
    pub fn property_assertions<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        let mut assertions = BTreeMap::new();
        for (k, v) in pairs {
            assertions.insert(k.into(), v.into());
        }
        Self::Property(PropertyAssertionPredicateSpec { assertions })
    }

    /// Construct a path-operator predicate.
    pub fn path_operator(
        path: impl Into<String>,
        operator: PredicateOperator,
        value: Option<serde_json::Value>,
    ) -> Self {
        Self::PathOperator(PathOperatorPredicateSpec {
            path: path.into(),
            operator,
            value,
        })
    }

    /// Returns `true` when this predicate is the property-assertion variant.
    pub fn is_property_assertion(&self) -> bool {
        matches!(self, Self::Property(_))
    }

    /// Returns `true` when this predicate is the path-operator variant.
    pub fn is_path_operator(&self) -> bool {
        matches!(self, Self::PathOperator(_))
    }
}
