// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stable diagnostic codes emitted by the `cose-tp-json/v1` frontend.
//!
//! Each code is a UTF-8 byte-stable string in the `TPXxxx` namespace. Hosts switch on
//! `code` to route diagnostics; never parse the message body.
//!
//! Code map (mirrors the .NET frontend exactly so cross-port diagnostics don't drift):
//!
//! | Code     | Meaning                                                                              |
//! |----------|--------------------------------------------------------------------------------------|
//! | `TPX001` | Document is not legal JSON (parser error).                                           |
//! | `TPX100` | JSON-Schema validation failure (one error per leaf failure).                         |
//! | `TPX101` | `frontend` discriminator does not match `cose-tp-json/v1`.                           |
//! | `TPX200` | Unknown fact id (capability gating).                                                 |
//! | `TPX201` | Predicate fails the host-supplied per-fact predicate schema.                         |
//! | `TPX300` | Recursion-depth cap exceeded during the translator walk.                             |
//! | `TPX301` | Document node is structurally untranslatable (defensive — schema rejects first).     |
//! | `TPX400` | Reserved — surfaced by the post-translate bind pass on missing parameter binding.    |

/// `TPX001` — the document is not legal JSON.
pub const TPX_001_PARSE_ERROR: &str = "TPX001";

/// `TPX100` — the document parses but fails the embedded JSON Schema.
pub const TPX_100_SCHEMA_VIOLATION: &str = "TPX100";

/// `TPX101` — the document's `frontend` value disagrees with `cose-tp-json/v1`.
pub const TPX_101_FRONTEND_MISMATCH: &str = "TPX101";

/// `TPX200` — a `fact` reference cites an id that the host's
/// [`crate::FactCapabilities`] does not advertise.
pub const TPX_200_UNKNOWN_FACT_ID: &str = "TPX200";

/// `TPX201` — the user's predicate failed the host-supplied per-fact predicate schema.
pub const TPX_201_PREDICATE_SCHEMA_MISMATCH: &str = "TPX201";

/// `TPX300` — the translator walked beyond [`crate::CoseTpJsonOptions::max_depth`].
pub const TPX_300_RECURSION_LIMIT: &str = "TPX300";

/// `TPX301` — defensive: the schema-validated tree carried a node that the closed
/// translator grammar could not match.
pub const TPX_301_UNTRANSLATABLE: &str = "TPX301";

/// `TPX400` — placeholder for the post-translate bind pass; emitted by
/// [`cose_sign1_trust_policy_spec::bind`].
pub const TPX_400_PARAMETER_BIND_FAILED: &str = "TPX400";
