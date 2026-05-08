// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Source location used by translator frontends to attach line/column anchors to diagnostics.
//!
//! Phase 1 defines the type and re-uses it in error contexts; concrete frontends (Phase 2 JSON
//! and Phase 5a Rego) populate it during parsing.

use serde::{Deserialize, Serialize};

/// 1-indexed line/column pointer into a source document.
///
/// `byte_offset` is optional because some frontends (e.g. JSON parsers that report
/// `line:col` without a byte offset) cannot fill it. When present, it points at the
/// first byte of the located construct.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceLocation {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number.
    pub column: u32,
    /// Byte offset from the start of the source document, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<usize>,
}

impl SourceLocation {
    /// Construct a location with line + column only.
    pub fn at(line: u32, column: u32) -> Self {
        Self {
            line,
            column,
            byte_offset: None,
        }
    }

    /// Construct a location with a known byte offset.
    pub fn at_offset(line: u32, column: u32, byte_offset: usize) -> Self {
        Self {
            line,
            column,
            byte_offset: Some(byte_offset),
        }
    }
}

impl std::fmt::Display for SourceLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {} column {}", self.line, self.column)
    }
}
