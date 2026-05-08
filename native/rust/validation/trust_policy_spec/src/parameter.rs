// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Post-parse parameter substitution (D5).
//!
//! Frontends (Phase 2 JSON, Phase 5a Rego) parse documents into a [`TrustPolicySpec`] tree
//! that may contain *parameter references* — JSON literals of the shape
//! `{"$param": "name", "default": <value>}` — anywhere a `serde_json::Value` slot accepts
//! a value (predicate operands, property assertion right-hand-sides).
//!
//! The [`bind`] function walks the spec tree and substitutes each [`ParameterRef`] with a
//! concrete value from the supplied parameter map (or its `default`, when present).
//! Missing-without-default raises [`BindError::MissingParameter`].
//!
//! # Phase boundaries
//!
//! Phase 1 binds **blindly**: it does not know the predicate operator's expected type and
//! therefore cannot detect a type mismatch (e.g. binding a `string` parameter into a
//! `LessThan` operand that wants a number). Phase 2's JSON frontend schema-validates
//! pre-bind to catch these — the bind step's contract here is "structural substitution".
//!
//! # Reserved key
//!
//! Parameter literals are recognized by the presence of the key `$param` (a string).
//! The `$` prefix is reserved: user-controlled JSON objects must not include `$param`
//! as a non-parameter key. Frontends are responsible for namespacing user data away
//! from this reserved keyword (e.g. by validating that user values conform to a schema
//! that forbids `$`-prefixed keys).

use crate::diagnostic_codes;
use crate::predicate::{FactPredicateSpec, PathOperatorPredicateSpec, PropertyAssertionPredicateSpec};
use crate::spec::TrustPolicySpec;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Reserved JSON object key used to mark a parameter literal.
pub const PARAM_KEY: &str = "$param";

/// JSON literal shape recognized by [`bind`] as a parameter reference.
///
/// Serializes as:
///
/// ```json
/// {"$param": "max_chain_length", "default": 5}
/// ```
///
/// The `default` field is optional. When `default` is absent and the parameter map omits
/// `name`, [`bind`] returns [`BindError::MissingParameter`]. When `default` is present
/// and the parameter map omits `name`, the default value is substituted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterRef {
    /// Parameter name. Stable across binds for the same document.
    #[serde(rename = "$param")]
    pub name: String,
    /// Optional default value used when `name` is absent from the parameter map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

impl ParameterRef {
    /// Construct a parameter reference with no default.
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            default: None,
        }
    }

    /// Construct a parameter reference with a default value.
    pub fn with_default(name: impl Into<String>, default: impl Into<serde_json::Value>) -> Self {
        Self {
            name: name.into(),
            default: Some(default.into()),
        }
    }

    /// Render this parameter reference back to its JSON literal shape.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            PARAM_KEY.to_owned(),
            serde_json::Value::String(self.name.clone()),
        );
        if let Some(default) = &self.default {
            obj.insert("default".to_owned(), default.clone());
        }
        serde_json::Value::Object(obj)
    }

    /// Recognize a parameter reference embedded in a [`serde_json::Value`].
    ///
    /// A JSON object is a parameter reference when:
    /// - It contains the key [`PARAM_KEY`] (`$param`).
    /// - The value of `$param` is a JSON string.
    /// - It contains no keys other than `$param` and (optionally) `default`.
    ///
    /// Returns `Ok(Some(parsed))` for a recognized parameter reference, `Ok(None)` for a
    /// JSON object that is not a parameter reference, or `Err(BindError)` for a malformed
    /// parameter literal (key present but value or co-keys are wrong).
    pub fn try_recognize(value: &serde_json::Value) -> Result<Option<Self>, BindError> {
        let serde_json::Value::Object(obj) = value else {
            return Ok(None);
        };
        let Some(name_value) = obj.get(PARAM_KEY) else {
            return Ok(None);
        };
        let serde_json::Value::String(name) = name_value else {
            return Err(BindError::Malformed {
                detail: format!(
                    "$param key must be a string, got {}",
                    short_kind(name_value)
                ),
            });
        };
        for k in obj.keys() {
            if k != PARAM_KEY && k != "default" {
                return Err(BindError::Malformed {
                    detail: format!("unexpected key '{k}' alongside $param literal"),
                });
            }
        }
        let default = obj.get("default").cloned();
        Ok(Some(Self {
            name: name.clone(),
            default,
        }))
    }
}

/// Errors produced by [`bind`].
///
/// Every variant carries a stable diagnostic code from [`crate::diagnostic_codes`] (TPX400 /
/// TPX401 / TPX301), surfaced verbatim in the [`std::fmt::Display`] impl so log scrapers
/// and audit pipelines can grep/correlate without parsing free-form text.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BindError {
    /// A `$param` reference has neither a binding nor a default. (`TPX400`)
    MissingParameter {
        /// Parameter name that could not be resolved.
        name: String,
        /// Path breadcrumb (e.g. `RequireFact[0].predicate.assertions["chain_built"]`)
        /// useful for diagnostics. Empty when the location is the root.
        location: String,
    },
    /// A `$param` literal is structurally malformed (e.g. non-string `$param` value or
    /// extra co-keys). (`TPX401`)
    Malformed {
        /// Human-readable description of the malformation.
        detail: String,
    },
    /// Recursion depth cap exceeded during the bind walk. (`TPX301`)
    RecursionLimitExceeded {
        /// Configured depth limit.
        limit: usize,
    },
}

impl BindError {
    /// Stable diagnostic code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingParameter { .. } => diagnostic_codes::TPX_400_PARAMETER_BIND_FAILED,
            Self::Malformed { .. } => diagnostic_codes::TPX_401_PARAMETER_REF_MALFORMED,
            Self::RecursionLimitExceeded { .. } => diagnostic_codes::TPX_301_RECURSION_LIMIT,
        }
    }
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingParameter { name, location } => {
                if location.is_empty() {
                    write!(f, "[{}] missing parameter '{name}' (no default)", self.code())
                } else {
                    write!(
                        f,
                        "[{}] missing parameter '{name}' at {location} (no default)",
                        self.code()
                    )
                }
            }
            Self::Malformed { detail } => {
                write!(f, "[{}] malformed parameter literal: {detail}", self.code())
            }
            Self::RecursionLimitExceeded { limit } => {
                write!(
                    f,
                    "[{}] bind recursion limit {limit} exceeded",
                    self.code()
                )
            }
        }
    }
}

impl std::error::Error for BindError {}

/// Default maximum recursion depth honored by [`bind`]. Same default as
/// [`crate::compile::DEFAULT_MAX_DEPTH`] for symmetry.
pub const DEFAULT_MAX_DEPTH: usize = 256;

/// Configuration for [`bind_with_options`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct BindOptions {
    /// Maximum recursion depth honored when walking nested specs and JSON values.
    pub max_depth: usize,
}

impl BindOptions {
    /// Construct options with the given recursion depth cap.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self { max_depth }
    }
}

impl Default for BindOptions {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
        }
    }
}

/// Substitute every [`ParameterRef`] in `spec` with a concrete value from `parameters`.
///
/// `parameters` uses `BTreeMap` for deterministic iteration; the order has no semantic
/// effect on the result since lookups are exact-match by key.
///
/// Errors:
/// - [`BindError::MissingParameter`] — a referenced parameter has no binding and no default.
/// - [`BindError::Malformed`] — a `$param` literal is structurally invalid.
/// - [`BindError::RecursionLimitExceeded`] — input nesting depth exceeded
///   [`DEFAULT_MAX_DEPTH`]. Use [`bind_with_options`] to override.
pub fn bind(
    spec: TrustPolicySpec,
    parameters: &BTreeMap<String, serde_json::Value>,
) -> Result<TrustPolicySpec, BindError> {
    bind_with_options(spec, parameters, &BindOptions::default())
}

/// As [`bind`], but with caller-supplied [`BindOptions`].
pub fn bind_with_options(
    spec: TrustPolicySpec,
    parameters: &BTreeMap<String, serde_json::Value>,
    options: &BindOptions,
) -> Result<TrustPolicySpec, BindError> {
    let mut walker = SpecWalker {
        parameters,
        max_depth: options.max_depth,
        breadcrumb: BreadcrumbStack::new(),
    };
    walker.walk_spec(spec, 0)
}

struct SpecWalker<'a> {
    parameters: &'a BTreeMap<String, serde_json::Value>,
    max_depth: usize,
    breadcrumb: BreadcrumbStack,
}

/// Reusable breadcrumb stack — pushes are in-place and only materialize a string when an
/// error is constructed. Avoids the per-recursive-step `format!` allocations the original
/// implementation incurred.
struct BreadcrumbStack {
    segments: Vec<String>,
}

impl BreadcrumbStack {
    fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    fn push(&mut self, segment: String) {
        self.segments.push(segment);
    }

    fn pop(&mut self) {
        self.segments.pop();
    }

    /// Render the current breadcrumb as a dotted path. Allocates only when called.
    fn render(&self) -> String {
        self.segments.join(".")
    }
}

impl<'a> SpecWalker<'a> {
    fn check_depth(&self, depth: usize) -> Result<(), BindError> {
        if depth >= self.max_depth {
            return Err(BindError::RecursionLimitExceeded {
                limit: self.max_depth,
            });
        }
        Ok(())
    }

    fn walk_spec(
        &mut self,
        spec: TrustPolicySpec,
        depth: usize,
    ) -> Result<TrustPolicySpec, BindError> {
        self.check_depth(depth)?;
        match spec {
            TrustPolicySpec::AllowAll => Ok(TrustPolicySpec::AllowAll),
            TrustPolicySpec::DenyAll { reason } => Ok(TrustPolicySpec::DenyAll { reason }),
            TrustPolicySpec::And { specs } => Ok(TrustPolicySpec::And {
                specs: self.walk_vec(specs, "and", depth + 1)?,
            }),
            TrustPolicySpec::Or { specs } => Ok(TrustPolicySpec::Or {
                specs: self.walk_vec(specs, "or", depth + 1)?,
            }),
            TrustPolicySpec::Not { spec, reason } => {
                self.breadcrumb.push("not".to_owned());
                let inner = self.walk_spec(*spec, depth + 1);
                self.breadcrumb.pop();
                Ok(TrustPolicySpec::Not {
                    spec: Box::new(inner?),
                    reason,
                })
            }
            TrustPolicySpec::Implies {
                antecedent,
                consequent,
            } => {
                self.breadcrumb.push("implies.antecedent".to_owned());
                let a = self.walk_spec(*antecedent, depth + 1);
                self.breadcrumb.pop();
                let a = a?;
                self.breadcrumb.push("implies.consequent".to_owned());
                let c = self.walk_spec(*consequent, depth + 1);
                self.breadcrumb.pop();
                Ok(TrustPolicySpec::Implies {
                    antecedent: Box::new(a),
                    consequent: Box::new(c?),
                })
            }
            TrustPolicySpec::Message { requirements } => Ok(TrustPolicySpec::Message {
                requirements: self.walk_vec(requirements, "message", depth + 1)?,
            }),
            TrustPolicySpec::PrimarySigningKey { requirements } => {
                Ok(TrustPolicySpec::PrimarySigningKey {
                    requirements: self.walk_vec(requirements, "primary_signing_key", depth + 1)?,
                })
            }
            TrustPolicySpec::AnyCounterSignature {
                on_empty,
                requirements,
            } => Ok(TrustPolicySpec::AnyCounterSignature {
                on_empty,
                requirements: self.walk_vec(requirements, "any_counter_signature", depth + 1)?,
            }),
            TrustPolicySpec::RequireFact {
                fact_id,
                predicate,
                failure_message,
            } => {
                self.breadcrumb.push("require_fact.predicate".to_owned());
                let predicate = self.walk_predicate(predicate, depth + 1);
                self.breadcrumb.pop();
                Ok(TrustPolicySpec::RequireFact {
                    fact_id,
                    predicate: predicate?,
                    failure_message,
                })
            }
        }
    }

    fn walk_vec(
        &mut self,
        specs: Vec<TrustPolicySpec>,
        kind: &str,
        depth: usize,
    ) -> Result<Vec<TrustPolicySpec>, BindError> {
        let mut out = Vec::with_capacity(specs.len());
        for (i, s) in specs.into_iter().enumerate() {
            self.breadcrumb.push(format!("{kind}[{i}]"));
            let walked = self.walk_spec(s, depth);
            self.breadcrumb.pop();
            out.push(walked?);
        }
        Ok(out)
    }

    fn walk_predicate(
        &mut self,
        predicate: FactPredicateSpec,
        depth: usize,
    ) -> Result<FactPredicateSpec, BindError> {
        self.check_depth(depth)?;
        match predicate {
            FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions }) => {
                let mut out = BTreeMap::new();
                for (k, v) in assertions {
                    self.breadcrumb.push(format!("assertions[{k}]"));
                    let walked = self.walk_value(v, depth + 1);
                    self.breadcrumb.pop();
                    out.insert(k, walked?);
                }
                Ok(FactPredicateSpec::Property(PropertyAssertionPredicateSpec {
                    assertions: out,
                }))
            }
            FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
                path,
                operator,
                value,
            }) => {
                let value = match value {
                    Some(v) => {
                        self.breadcrumb.push("value".to_owned());
                        let walked = self.walk_value(v, depth + 1);
                        self.breadcrumb.pop();
                        Some(walked?)
                    }
                    None => None,
                };
                Ok(FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
                    path,
                    operator,
                    value,
                }))
            }
        }
    }

    fn walk_value(
        &mut self,
        value: serde_json::Value,
        depth: usize,
    ) -> Result<serde_json::Value, BindError> {
        self.check_depth(depth)?;
        if let Some(param) = ParameterRef::try_recognize(&value)? {
            return self.resolve(&param);
        }
        match value {
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.into_iter().enumerate() {
                    self.breadcrumb.push(format!("[{i}]"));
                    let walked = self.walk_value(item, depth + 1);
                    self.breadcrumb.pop();
                    out.push(walked?);
                }
                Ok(serde_json::Value::Array(out))
            }
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    self.breadcrumb.push(k.clone());
                    let walked = self.walk_value(v, depth + 1);
                    self.breadcrumb.pop();
                    out.insert(k, walked?);
                }
                Ok(serde_json::Value::Object(out))
            }
            other => Ok(other),
        }
    }

    fn resolve(&self, param: &ParameterRef) -> Result<serde_json::Value, BindError> {
        if let Some(v) = self.parameters.get(&param.name) {
            return Ok(v.clone());
        }
        if let Some(default) = &param.default {
            return Ok(default.clone());
        }
        Err(BindError::MissingParameter {
            name: param.name.clone(),
            location: self.breadcrumb.render(),
        })
    }
}

fn short_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
