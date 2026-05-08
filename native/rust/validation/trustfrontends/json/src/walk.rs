// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Document walker — translates a schema-validated `serde_json::Value` tree into a
//! [`TrustPolicySpec`]. Mirrors the .NET `DocumentTranslator` line-for-line.

use crate::codes::{
    TPX_200_UNKNOWN_FACT_ID, TPX_201_PREDICATE_SCHEMA_MISMATCH, TPX_300_RECURSION_LIMIT,
    TPX_301_UNTRANSLATABLE,
};
use crate::options::CoseTpJsonOptions;
use cose_sign1_trust_policy_spec::{
    FactPredicateSpec, OnEmptyBehavior, PathOperatorPredicateSpec, PredicateOperator,
    PropertyAssertionPredicateSpec, SourceLocation, TrustPolicySeverity, TrustPolicySpec,
    TrustPolicyTranslationContext, TrustPolicyTranslationDiagnostic,
};
use jsonschema::{draft202012, Validator};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub(crate) struct DocumentTranslator<'a> {
    pub ctx: &'a TrustPolicyTranslationContext,
    pub options: &'a CoseTpJsonOptions,
    pub document_source: Option<&'a str>,
    pub diagnostics: &'a mut Vec<TrustPolicyTranslationDiagnostic>,
}

impl<'a> DocumentTranslator<'a> {
    pub fn walk_root(
        &mut self,
        mut root: Map<String, Value>,
        frontend_id: &'static str,
    ) -> TrustPolicySpec {
        // Defensive frontend-mismatch check (also enforced by the schema's `const`).
        if let Some(Value::String(declared)) = root.get("frontend") {
            if declared != frontend_id {
                self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
                    TrustPolicySeverity::Error,
                    crate::codes::TPX_101_FRONTEND_MISMATCH,
                    format!(
                        "Document declares frontend '{declared}' but this translator handles '{frontend_id}'.",
                    ),
                    Some(self.location_for("$.frontend")),
                    None,
                ));
            }
        }

        let top_combinator = root
            .get("combinator")
            .and_then(Value::as_str)
            .unwrap_or("and")
            .to_owned();

        let mut scopes: Vec<TrustPolicySpec> = Vec::with_capacity(3);

        if let Some(Value::Object(message)) = root.remove("message") {
            let inner = self.walk_expression(message, "$.message", 1);
            scopes.push(TrustPolicySpec::message([inner]));
        }
        if let Some(Value::Object(psk)) = root.remove("primary_signing_key") {
            let inner = self.walk_expression(psk, "$.primary_signing_key", 1);
            scopes.push(TrustPolicySpec::primary_signing_key([inner]));
        }
        if let Some(Value::Object(acs)) = root.remove("any_counter_signature") {
            scopes.push(self.walk_any_counter_signature(acs, "$.any_counter_signature", 1));
        }

        if scopes.is_empty() {
            // Schema's anyOf enforces at least one of the three scopes — defensive arm.
            return TrustPolicySpec::message([TrustPolicySpec::DenyAll {
                reason: "no scope produced by translator (schema gate violated)".to_owned(),
            }]);
        }
        if scopes.len() == 1 {
            return scopes.pop().expect("len==1");
        }
        if top_combinator == "or" {
            TrustPolicySpec::or(scopes)
        } else {
            TrustPolicySpec::and(scopes)
        }
    }

    fn walk_any_counter_signature(
        &mut self,
        mut obj: Map<String, Value>,
        pointer: &str,
        depth: usize,
    ) -> TrustPolicySpec {
        let on_empty = match obj.remove("on_empty") {
            Some(Value::String(s)) if s == "allow" => OnEmptyBehavior::Allow,
            _ => OnEmptyBehavior::Deny,
        };

        let inner = self.walk_expression(obj, pointer, depth);
        TrustPolicySpec::any_counter_signature(on_empty, [inner])
    }

    fn walk_expression(
        &mut self,
        mut obj: Map<String, Value>,
        pointer: &str,
        depth: usize,
    ) -> TrustPolicySpec {
        if !self.check_depth(depth, pointer) {
            return deny_placeholder("recursion-limit-exceeded");
        }

        if obj.contains_key("fact") {
            return self.walk_require_fact(obj, pointer);
        }
        if let Some(Value::Array(arr)) = obj.remove("all_of") {
            let inner_pointer = format!("{pointer}.all_of");
            return self.walk_combinator(arr, &inner_pointer, depth + 1, true);
        }
        if let Some(Value::Array(arr)) = obj.remove("any_of") {
            let inner_pointer = format!("{pointer}.any_of");
            return self.walk_combinator(arr, &inner_pointer, depth + 1, false);
        }
        if let Some(Value::Object(inner)) = obj.remove("not") {
            let inner_pointer = format!("{pointer}.not");
            let reason = obj.remove("reason").and_then(|v| match v {
                Value::String(s) if !s.trim().is_empty() => Some(s),
                _ => None,
            });
            let walked = self.walk_expression(inner, &inner_pointer, depth + 1);
            return TrustPolicySpec::not(walked, reason);
        }
        if let Some(Value::Object(impl_obj)) = obj.remove("implies") {
            return self.walk_implies(impl_obj, pointer, depth);
        }
        if obj.contains_key("allow_all") {
            return TrustPolicySpec::AllowAll;
        }
        if let Some(Value::String(deny_reason)) = obj.remove("deny_all") {
            return TrustPolicySpec::DenyAll {
                reason: deny_reason,
            };
        }

        // Defensive — schema validation should have caught this before us. Surface as
        // TPX301 and fail closed.
        self.emit_untranslatable(pointer);
        deny_placeholder("untranslatable-node")
    }

    fn walk_combinator(
        &mut self,
        items: Vec<Value>,
        pointer: &str,
        depth: usize,
        is_and: bool,
    ) -> TrustPolicySpec {
        if !self.check_depth(depth, pointer) {
            return deny_placeholder("recursion-limit-exceeded");
        }
        let mut operands: Vec<TrustPolicySpec> = Vec::with_capacity(items.len());
        for (index, item) in items.into_iter().enumerate() {
            let child_pointer = format!("{pointer}[{index}]");
            match item {
                Value::Object(child) => {
                    operands.push(self.walk_expression(child, &child_pointer, depth + 1));
                }
                _ => {
                    self.emit_untranslatable(&child_pointer);
                    operands.push(deny_placeholder("untranslatable-node"));
                }
            }
        }
        if is_and {
            TrustPolicySpec::and(operands)
        } else {
            TrustPolicySpec::or(operands)
        }
    }

    fn walk_implies(
        &mut self,
        mut impl_obj: Map<String, Value>,
        pointer: &str,
        depth: usize,
    ) -> TrustPolicySpec {
        if !self.check_depth(depth + 1, pointer) {
            return deny_placeholder("recursion-limit-exceeded");
        }
        let antecedent_pointer = format!("{pointer}.implies.antecedent");
        let consequent_pointer = format!("{pointer}.implies.consequent");
        let antecedent = match impl_obj.remove("antecedent") {
            Some(Value::Object(obj)) => self.walk_expression(obj, &antecedent_pointer, depth + 2),
            _ => {
                self.emit_untranslatable(&antecedent_pointer);
                deny_placeholder("untranslatable-node")
            }
        };
        let consequent = match impl_obj.remove("consequent") {
            Some(Value::Object(obj)) => self.walk_expression(obj, &consequent_pointer, depth + 2),
            _ => {
                self.emit_untranslatable(&consequent_pointer);
                deny_placeholder("untranslatable-node")
            }
        };
        TrustPolicySpec::implies(antecedent, consequent)
    }

    fn walk_require_fact(
        &mut self,
        mut obj: Map<String, Value>,
        pointer: &str,
    ) -> TrustPolicySpec {
        let fact_id = match obj.remove("fact") {
            Some(Value::String(s)) => s,
            _ => {
                self.emit_untranslatable(pointer);
                return deny_placeholder("untranslatable-node");
            }
        };
        let predicate_node = obj.remove("predicate").unwrap_or(Value::Null);
        let failure_message = match obj.remove("failure_message") {
            Some(Value::String(s)) if !s.trim().is_empty() => s,
            _ => default_failure_message(&fact_id),
        };

        // Capability gating (D4).
        if let Some(caps) = self.ctx.available_facts.as_ref() {
            if !self.ctx.allow_unknown_facts && !caps.available_fact_ids.contains(&fact_id) {
                let formatted = caps
                    .available_fact_ids
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ");
                self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
                    TrustPolicySeverity::Error,
                    TPX_200_UNKNOWN_FACT_ID,
                    format!(
                        "Document references unknown fact id '{fact_id}'. Available fact ids: {formatted}.",
                    ),
                    Some(self.location_for(&format!("{pointer}.fact"))),
                    None,
                ));
                return TrustPolicySpec::DenyAll {
                    reason: failure_message,
                };
            }

            if let Some(schema_value) = caps.predicate_schemas.get(&fact_id) {
                let predicate_pointer = format!("{pointer}.predicate");
                self.validate_predicate_against_schema(
                    schema_value,
                    &predicate_node,
                    &fact_id,
                    &predicate_pointer,
                );
            }
        }

        let predicate_spec =
            self.walk_predicate(predicate_node, &format!("{pointer}.predicate"));
        TrustPolicySpec::require_fact(fact_id, predicate_spec, failure_message)
    }

    fn validate_predicate_against_schema(
        &mut self,
        schema_value: &Value,
        predicate: &Value,
        fact_id: &str,
        pointer: &str,
    ) {
        let validator: Validator = match draft202012::new(schema_value) {
            Ok(v) => v,
            Err(err) => {
                self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
                    TrustPolicySeverity::Error,
                    TPX_201_PREDICATE_SCHEMA_MISMATCH,
                    format!(
                        "Predicate schema for fact '{fact_id}' is not a valid Draft-2020-12 schema: {err}",
                    ),
                    Some(self.location_for(pointer)),
                    None,
                ));
                return;
            }
        };
        for error in validator.iter_errors(predicate) {
            self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
                TrustPolicySeverity::Error,
                TPX_201_PREDICATE_SCHEMA_MISMATCH,
                format!(
                    "Predicate for fact '{fact_id}' does not match the published predicate schema at '{pointer}': {error}",
                ),
                Some(self.location_for(pointer)),
                None,
            ));
        }
    }

    fn walk_predicate(&mut self, predicate: Value, pointer: &str) -> FactPredicateSpec {
        let obj = match predicate {
            Value::Object(map) => map,
            _ => {
                self.emit_untranslatable(pointer);
                return FactPredicateSpec::path_operator("$", PredicateOperator::Exists, None);
            }
        };
        if obj.contains_key("operator") || obj.contains_key("path") {
            return self.walk_path_operator_predicate(obj, pointer);
        }
        // Property-assertion form. Each entry is property -> expected value.
        let mut assertions = BTreeMap::new();
        for (key, value) in obj.into_iter() {
            assertions.insert(key, value);
        }
        FactPredicateSpec::Property(PropertyAssertionPredicateSpec { assertions })
    }

    fn walk_path_operator_predicate(
        &mut self,
        mut obj: Map<String, Value>,
        pointer: &str,
    ) -> FactPredicateSpec {
        let path = match obj.remove("path") {
            Some(Value::String(s)) => s,
            _ => "$".to_owned(),
        };
        let operator_text = match obj.remove("operator") {
            Some(Value::String(s)) => s,
            _ => "Exists".to_owned(),
        };
        let value = obj.remove("value");
        let operator = parse_operator(&operator_text).unwrap_or_else(|| {
            self.emit_untranslatable(&format!("{pointer}.operator"));
            PredicateOperator::Exists
        });
        FactPredicateSpec::PathOperator(PathOperatorPredicateSpec {
            path,
            operator,
            value,
        })
    }

    fn check_depth(&mut self, depth: usize, pointer: &str) -> bool {
        if depth >= self.options.max_depth {
            self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
                TrustPolicySeverity::Error,
                TPX_300_RECURSION_LIMIT,
                format!(
                    "Document nesting exceeds the configured max depth ({}). Construct at '{pointer}' was rejected.",
                    self.options.max_depth,
                ),
                Some(self.location_for(pointer)),
                None,
            ));
            return false;
        }
        true
    }

    fn emit_untranslatable(&mut self, pointer: &str) {
        self.diagnostics.push(TrustPolicyTranslationDiagnostic::new(
            TrustPolicySeverity::Error,
            TPX_301_UNTRANSLATABLE,
            format!(
                "Document node at '{pointer}' could not be translated; expected one of: fact, all_of, any_of, not, implies, allow_all, deny_all.",
            ),
            Some(self.location_for(pointer)),
            None,
        ));
    }

    fn location_for(&self, _pointer: &str) -> SourceLocation {
        let _ = self.document_source;
        SourceLocation::at(0, 0)
    }
}

fn deny_placeholder(reason: &str) -> TrustPolicySpec {
    TrustPolicySpec::DenyAll {
        reason: reason.to_owned(),
    }
}

fn default_failure_message(fact_id: &str) -> String {
    format!("Fact requirement on '{fact_id}' was not satisfied.")
}

fn parse_operator(text: &str) -> Option<PredicateOperator> {
    // Schema accepts PascalCase form; the IR uses snake_case. Match case-insensitively
    // so the translator is tolerant of both forms.
    match text.to_ascii_lowercase().as_str() {
        "exists" => Some(PredicateOperator::Exists),
        "equals" => Some(PredicateOperator::Equals),
        "notequals" | "not_equals" => Some(PredicateOperator::NotEquals),
        "lessthan" | "less_than" => Some(PredicateOperator::LessThan),
        "lessthanorequal" | "less_than_or_equal" => Some(PredicateOperator::LessThanOrEqual),
        "greaterthan" | "greater_than" => Some(PredicateOperator::GreaterThan),
        "greaterthanorequal" | "greater_than_or_equal" => {
            Some(PredicateOperator::GreaterThanOrEqual)
        }
        "startswith" | "starts_with" => Some(PredicateOperator::StartsWith),
        "endswith" | "ends_with" => Some(PredicateOperator::EndsWith),
        "contains" => Some(PredicateOperator::Contains),
        "in" => Some(PredicateOperator::In),
        _ => None,
    }
}
