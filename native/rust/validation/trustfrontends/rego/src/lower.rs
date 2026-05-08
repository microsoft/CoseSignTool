// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Lowers the parsed [`crate::ast::RegoValueNode`] tree into a
//! [`serde_json::Value`] that matches the canonical `cose-tp-json/v1`
//! document shape.
//!
//! The JSON frontend's schema validator + walker is reused on the lowered
//! tree, so byte-equality with the JSON frontend's canonical IR is a
//! property of construction, not of duplicated logic.
//!
//! The only Rego→JSON projection that doesn't fall out of "literal-to-literal"
//! is the [`RegoValueNode::InputRef`] case: an `input.<name>` reference becomes
//! the `{"$param": "<name>"}` object the JSON frontend recognises (per D5).
//! This is a faithful translation: both frontends produce the same
//! `ParameterRef` in the IR, so the post-translate `bind` pass behaves
//! identically.

use crate::ast::{RegoObjectEntry, RegoScalarKind, RegoValueNode};
use crate::strings::PROPERTY_PARAM;
use serde_json::{Map, Number, Value};

/// Lower the AST root to a [`serde_json::Value`] tree.
pub(crate) fn lower(node: &RegoValueNode) -> Value {
    match node {
        RegoValueNode::Object(entries) => Value::Object(lower_object(entries)),
        RegoValueNode::Array(items) => Value::Array(lower_array(items)),
        RegoValueNode::Scalar(kind, text) => lower_scalar(*kind, text),
        RegoValueNode::InputRef(name) => lower_input_ref(name),
    }
}

fn lower_object(entries: &[RegoObjectEntry]) -> Map<String, Value> {
    let mut result = Map::with_capacity(entries.len());
    for entry in entries {
        result.insert(entry.key.clone(), lower(&entry.value));
    }
    result
}

fn lower_array(items: &[RegoValueNode]) -> Vec<Value> {
    items.iter().map(lower).collect()
}

fn lower_scalar(kind: RegoScalarKind, text: &str) -> Value {
    match kind {
        RegoScalarKind::String => Value::String(text.to_owned()),
        RegoScalarKind::True => Value::Bool(true),
        RegoScalarKind::False => Value::Bool(false),
        RegoScalarKind::Null => Value::Null,
        RegoScalarKind::Number => lower_number(text),
    }
}

fn lower_number(text: &str) -> Value {
    // Prefer integer projection so canonical IR byte-equality with the
    // cose-tp-json/v1 fixtures (which use integer literals where possible)
    // is preserved. Fall back to f64 only when the literal genuinely needs
    // it.
    if let Ok(i) = text.parse::<i64>() {
        return Value::Number(Number::from(i));
    }
    if let Ok(u) = text.parse::<u64>() {
        return Value::Number(Number::from(u));
    }
    if let Ok(f) = text.parse::<f64>() {
        if let Some(n) = Number::from_f64(f) {
            return Value::Number(n);
        }
    }
    // The grammar rejects malformed numbers at parse time, so this branch
    // is structurally unreachable for any AST that survives parsing. The
    // explicit fallback keeps `lower` total even if a future parser
    // change widens the accepted numeric grammar past the i64/u64/f64
    // surface.
    unreachable_number_fallback()
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn unreachable_number_fallback() -> Value {
    Value::Number(Number::from(0))
}

fn lower_input_ref(name: &str) -> Value {
    let mut obj = Map::with_capacity(1);
    obj.insert(PROPERTY_PARAM.to_owned(), Value::String(name.to_owned()));
    Value::Object(obj)
}
