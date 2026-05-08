// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Centralised string-literal pool for the cose-tp-rego/v1 frontend.
//!
//! Mirrors the .NET `AssemblyStrings` constants verbatim so contract-text
//! changes happen in one place and the cross-port ports stay byte-equal in
//! the diagnostic vocabulary they emit. Every user-visible literal lives
//! here.

// --- Frontend identity ---

/// Stable frontend identifier.
pub const FRONTEND_ID: &str = "cose-tp-rego/v1";

/// IANA media type accepted by [`crate::CoseTpRegoFrontend`].
pub const MEDIA_TYPE_REGO: &str = "application/x-cose-trust-policy+rego";

/// Canonical file extension for documents this frontend recognises.
pub const FILE_EXTENSION: &str = ".coseTrustPolicy.rego";

/// Sniff prefix written by every legal cose-tp-rego/v1 document.
pub const SNIFF_PREFIX: &str = "package cose_trust_policy";

// --- Rego subset — required boilerplate ---

pub(crate) const REQUIRED_PACKAGE: &str = "cose_trust_policy";
pub(crate) const POLICY_RULE_NAME: &str = "policy";
pub(crate) const KEYWORD_PACKAGE: &str = "package";
pub(crate) const KEYWORD_IMPORT: &str = "import";
pub(crate) const KEYWORD_TRUE: &str = "true";
pub(crate) const KEYWORD_FALSE: &str = "false";
pub(crate) const KEYWORD_NULL: &str = "null";
pub(crate) const KEYWORD_INPUT: &str = "input";
pub(crate) const ALLOWED_IMPORT_FUTURE_KEYWORDS_IN: &str = "future.keywords.in";

// --- Forbidden tokens — closed reject-list ---

pub(crate) const FORBIDDEN_IDENT_SOME: &str = "some";
pub(crate) const FORBIDDEN_IDENT_EVERY: &str = "every";
pub(crate) const FORBIDDEN_IDENT_WITH: &str = "with";
pub(crate) const FORBIDDEN_IDENT_DEFAULT: &str = "default";
pub(crate) const FORBIDDEN_IDENT_NOT: &str = "not";
pub(crate) const FORBIDDEN_IDENT_DATA: &str = "data";
pub(crate) const FORBIDDEN_IDENT_EVAL: &str = "eval";
pub(crate) const FORBIDDEN_NAMESPACE_HTTP: &str = "http";
pub(crate) const FORBIDDEN_NAMESPACE_REGEX: &str = "regex";
pub(crate) const FORBIDDEN_NAMESPACE_FILE: &str = "file";
pub(crate) const FORBIDDEN_NAMESPACE_IO: &str = "io";
pub(crate) const FORBIDDEN_NAMESPACE_OS: &str = "os";
pub(crate) const FORBIDDEN_NAMESPACE_CRYPTO: &str = "crypto";
pub(crate) const FORBIDDEN_NAMESPACE_NET: &str = "net";
pub(crate) const FORBIDDEN_NAMESPACE_TIME: &str = "time";
pub(crate) const FORBIDDEN_NAMESPACE_OPA: &str = "opa";

// --- DoS caps ---

/// Maximum allowed nesting depth for object / array literals.
///
/// The §6.5.6 example sits at depth ~4; 64 is comfortably above any
/// realistic cose-tp/v1 policy and well below a stack-exhaustion threshold
/// on the recursion path. Matches the .NET Phase 5a cap verbatim so both
/// frontends agree on what a "DoS-shaped document" looks like.
pub const MAX_NESTING_DEPTH: usize = 64;

/// Maximum allowed input size in bytes (UTF-8 length). Tokenization
/// materialises the full token stream before parsing, so a multi-megabyte
/// hostile input would be a memory-DoS vector even if the parser is
/// depth-bounded. 1 MiB is comfortably above any plausible real-world
/// cose-tp-rego/v1 document; the §6.5.6 example is ~600 bytes.
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;

// --- Property names produced by the lowerer ---

pub(crate) const PROPERTY_PARAM: &str = "$param";

// --- Source-pointer formatting ---

pub(crate) const TOKEN_EOF_TEXT: &str = "<end-of-input>";
pub(crate) const PIPE_CHAR: &str = "|";

// --- Suggestions ---

pub(crate) const SUGGESTION_USE_INPUT: &str = "Replace 'data.<name>' with 'input.<name>' so the value is supplied via the host's parameter binder (D5).";
pub(crate) const SUGGESTION_USE_PROPERTY: &str = "Use the JSON property-shorthand or path/operator predicate forms (see cose-tp-json/v1 §6.5.5).";
pub(crate) const SUGGESTION_REMOVE_SIDE_EFFECTING_BUILTIN: &str = "Side-effecting / non-deterministic builtins (HTTP, regex, filesystem, network, cryptography, time, OPA) are not permitted in cose-tp-rego/v1. Express the equivalent value as a literal or pass it via 'input.<name>'.";
pub(crate) const SUGGESTION_FLATTEN_NESTING: &str = "Reduce object / array nesting depth (current limit is 64). Real-world cose-tp/v1 policies fit comfortably; deeply nested input here is treated as a DoS signal.";
