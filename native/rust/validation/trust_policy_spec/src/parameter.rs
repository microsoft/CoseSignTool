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
        if !obj.contains_key(PARAM_KEY) {
            return Ok(None);
        }
        let name_value = obj.get(PARAM_KEY).expect("contains_key returned true");
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// A `$param` reference has neither a binding nor a default.
    MissingParameter {
        /// Parameter name that could not be resolved.
        name: String,
        /// Path breadcrumb (e.g. `RequireFact[0].predicate.assertions["chain_built"]`)
        /// useful for diagnostics. Empty when the location is the root.
        location: String,
    },
    /// A `$param` literal is structurally malformed (e.g. non-string `$param` value or
    /// extra co-keys).
    Malformed {
        /// Human-readable description of the malformation.
        detail: String,
    },
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingParameter { name, location } => {
                if location.is_empty() {
                    write!(f, "missing parameter '{name}' (no default)")
                } else {
                    write!(f, "missing parameter '{name}' at {location} (no default)")
                }
            }
            Self::Malformed { detail } => write!(f, "malformed parameter literal: {detail}"),
        }
    }
}

impl std::error::Error for BindError {}

/// Substitute every [`ParameterRef`] in `spec` with a concrete value from `parameters`.
///
/// `parameters` uses `BTreeMap` for deterministic iteration; the order has no semantic
/// effect on the result since lookups are exact-match by key.
///
/// Errors:
/// - [`BindError::MissingParameter`] — a referenced parameter has no binding and no default.
/// - [`BindError::Malformed`] — a `$param` literal is structurally invalid.
pub fn bind(
    spec: TrustPolicySpec,
    parameters: &BTreeMap<String, serde_json::Value>,
) -> Result<TrustPolicySpec, BindError> {
    let mut walker = SpecWalker { parameters };
    walker.walk_spec(spec, "")
}

struct SpecWalker<'a> {
    parameters: &'a BTreeMap<String, serde_json::Value>,
}

impl<'a> SpecWalker<'a> {
    fn walk_spec(
        &mut self,
        spec: TrustPolicySpec,
        location: &str,
    ) -> Result<TrustPolicySpec, BindError> {
        match spec {
            TrustPolicySpec::AllowAll => Ok(TrustPolicySpec::AllowAll),
            TrustPolicySpec::DenyAll { reason } => Ok(TrustPolicySpec::DenyAll { reason }),
            TrustPolicySpec::And { specs } => Ok(TrustPolicySpec::And {
                specs: self.walk_vec(specs, location, "and")?,
            }),
            TrustPolicySpec::Or { specs } => Ok(TrustPolicySpec::Or {
                specs: self.walk_vec(specs, location, "or")?,
            }),
            TrustPolicySpec::Not { spec, reason } => {
                let inner = self.walk_spec(*spec, &push(location, "not"))?;
                Ok(TrustPolicySpec::Not {
                    spec: Box::new(inner),
                    reason,
                })
            }
            TrustPolicySpec::Implies {
                antecedent,
                consequent,
            } => {
                let a = self.walk_spec(*antecedent, &push(location, "implies.antecedent"))?;
                let c = self.walk_spec(*consequent, &push(location, "implies.consequent"))?;
                Ok(TrustPolicySpec::Implies {
                    antecedent: Box::new(a),
                    consequent: Box::new(c),
                })
            }
            TrustPolicySpec::Message { requirements } => Ok(TrustPolicySpec::Message {
                requirements: self.walk_vec(requirements, location, "message")?,
            }),
            TrustPolicySpec::PrimarySigningKey { requirements } => {
                Ok(TrustPolicySpec::PrimarySigningKey {
                    requirements: self.walk_vec(requirements, location, "primary_signing_key")?,
                })
            }
            TrustPolicySpec::AnyCounterSignature {
                on_empty,
                requirements,
            } => Ok(TrustPolicySpec::AnyCounterSignature {
                on_empty,
                requirements: self.walk_vec(requirements, location, "any_counter_signature")?,
            }),
            TrustPolicySpec::RequireFact {
                fact_id,
                predicate,
                failure_message,
            } => Ok(TrustPolicySpec::RequireFact {
                fact_id,
                predicate: self.walk_predicate(
                    predicate,
                    &push(location, "require_fact.predicate"),
                )?,
                failure_message,
            }),
        }
    }

    fn walk_vec(
        &mut self,
        specs: Vec<TrustPolicySpec>,
        location: &str,
        kind: &str,
    ) -> Result<Vec<TrustPolicySpec>, BindError> {
        let mut out = Vec::with_capacity(specs.len());
        for (i, s) in specs.into_iter().enumerate() {
            out.push(self.walk_spec(s, &push(location, &format!("{kind}[{i}]")))?);
        }
        Ok(out)
    }

    fn walk_predicate(
        &mut self,
        predicate: FactPredicateSpec,
        location: &str,
    ) -> Result<FactPredicateSpec, BindError> {
        match predicate {
            FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions }) => {
                let mut out = BTreeMap::new();
                for (k, v) in assertions {
                    let key_loc = push(location, &format!("assertions[{k}]"));
                    out.insert(k, self.walk_value(v, &key_loc)?);
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
                    Some(v) => Some(self.walk_value(v, &push(location, "value"))?),
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
        location: &str,
    ) -> Result<serde_json::Value, BindError> {
        if let Some(param) = ParameterRef::try_recognize(&value)? {
            return self.resolve(&param, location);
        }
        match value {
            serde_json::Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for (i, item) in items.into_iter().enumerate() {
                    out.push(self.walk_value(item, &push(location, &format!("[{i}]")))?);
                }
                Ok(serde_json::Value::Array(out))
            }
            serde_json::Value::Object(map) => {
                let mut out = serde_json::Map::with_capacity(map.len());
                for (k, v) in map {
                    let key_loc = push(location, &format!(".{k}"));
                    out.insert(k, self.walk_value(v, &key_loc)?);
                }
                Ok(serde_json::Value::Object(out))
            }
            other => Ok(other),
        }
    }

    fn resolve(
        &self,
        param: &ParameterRef,
        location: &str,
    ) -> Result<serde_json::Value, BindError> {
        if let Some(v) = self.parameters.get(&param.name) {
            return Ok(v.clone());
        }
        if let Some(default) = &param.default {
            return Ok(default.clone());
        }
        Err(BindError::MissingParameter {
            name: param.name.clone(),
            location: location.to_owned(),
        })
    }
}

fn push(prefix: &str, segment: &str) -> String {
    if prefix.is_empty() {
        segment.to_owned()
    } else {
        format!("{prefix}.{segment}")
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
