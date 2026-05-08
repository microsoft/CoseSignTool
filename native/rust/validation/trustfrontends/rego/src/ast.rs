// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Closed AST emitted by [`crate::parser`] and consumed by [`crate::lower`].
//!
//! Mirrors the .NET `RegoValueNode` hierarchy verbatim. Adding a new node
//! kind requires touching this file, the parser, AND the lowerer in the
//! same change-set — the parser/lowerer pair is the contract surface, so
//! the closed-hierarchy invariant prevents drift.

/// Discriminator for [`RegoScalarNode`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegoScalarKind {
    /// Decoded string literal.
    String,
    /// Numeric literal — integer or decimal (sign-prefix folded into the text).
    Number,
    /// Boolean true.
    True,
    /// Boolean false.
    False,
    /// The null literal.
    Null,
}

/// One entry in an object literal: a string key paired with a value node.
#[derive(Debug)]
pub(crate) struct RegoObjectEntry {
    pub key: String,
    pub value: RegoValueNode,
}

/// Closed Rego-subset AST. Every legal cose-tp-rego/v1 construct is one of
/// these variants; the parser produces nothing else.
#[derive(Debug)]
pub(crate) enum RegoValueNode {
    /// `{"k": v, ...}` — object literal.
    Object(Vec<RegoObjectEntry>),
    /// `[a, b, c]` — array literal.
    Array(Vec<RegoValueNode>),
    /// Scalar literal: string, number, bool, null.
    Scalar(RegoScalarKind, String),
    /// `input.<name>` — lowers to `{"$param": "<name>"}` JSON.
    InputRef(String),
}
