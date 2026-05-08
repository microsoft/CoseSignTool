// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stable diagnostic codes emitted by the cose-tp-rego/v1 frontend.
//!
//! Mirrors the .NET Phase 5a code namespace verbatim. The TPX300 band is
//! split into per-cause sub-codes so blue-team telemetry can attribute
//! rejection rates to the offending construct class without parsing the
//! human-readable message.
//!
//! # Layered code-space note
//!
//! The Rego frontend reuses the `TPX001` parse-error code from the trust
//! policy spec layer (`cose_sign1_trust_policy_spec::diagnostic_codes`) so
//! the diagnostic vocabulary is identical between frontends. The `TPX301`
//! code in the spec layer (`TPX_301_RECURSION_LIMIT`) describes a
//! compile-time recursion guard reached *after* translation succeeded;
//! `TPX301` here describes a *parse-time* forbidden-builtin rejection that
//! prevents the document from ever reaching the spec layer. The codes are
//! distinguished by the layer that emits them — Rego frontend rejection
//! happens before any spec recursion can occur, so the two paths are
//! mutually exclusive at runtime. The numbering is locked verbatim with
//! the .NET Phase 5a deliverable so cross-port telemetry stays comparable.

/// `TPX001` — parser / lexer fault (unterminated string, malformed number,
/// unexpected token).
pub const TPX_001_MALFORMED_REGO: &str = "TPX001";

/// `TPX002` — missing or wrong `package` declaration.
pub const TPX_002_MISSING_PACKAGE: &str = "TPX002";

/// `TPX003` — no `policy := …` rule.
pub const TPX_003_MISSING_POLICY_RULE: &str = "TPX003";

/// `TPX004` — unsupported `import` statement.
pub const TPX_004_FORBIDDEN_IMPORT: &str = "TPX004";

/// `TPX005` — more than one rule per package.
pub const TPX_005_MULTIPLE_RULES: &str = "TPX005";

/// `TPX300` — catch-all untranslatable construct (unknown identifier,
/// generic comprehension fallback).
pub const TPX_300_UNTRANSLATABLE_CONSTRUCT: &str = "TPX300";

/// `TPX301` — forbidden builtin: `http.*` / `regex.*` / `file.*` / `io.*`
/// / `os.*` / `crypto.*` / `net.*` / `time.*` / `opa.*`.
pub const TPX_301_FORBIDDEN_BUILTIN: &str = "TPX301";

/// `TPX302` — unconstrained iteration / quantification: `some` / `every` /
/// `with` / `default` / `not` / `eval`.
pub const TPX_302_UNCONSTRAINED_ITERATION: &str = "TPX302";

/// `TPX303` — reserved `data.<…>` reference (only `input.<…>` is allowed).
pub const TPX_303_RESERVED_DATA_REFERENCE: &str = "TPX303";

/// `TPX304` — comprehension expression: `[ x | y ]` / `{ x | y }` /
/// `{ k: v | y }`.
pub const TPX_304_COMPREHENSION_REJECTED: &str = "TPX304";

/// `TPX305` — maximum nesting depth exceeded — defense-in-depth against
/// stack-exhaustion DoS.
pub const TPX_305_MAX_NESTING_DEPTH_EXCEEDED: &str = "TPX305";

/// `TPX306` — input-size cap exceeded — defense-in-depth against
/// memory-exhaustion DoS.
pub const TPX_306_INPUT_TOO_LARGE: &str = "TPX306";
