// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stable diagnostic codes used by the trust-policy translation pipeline.
//!
//! Code ranges (per design D6):
//! - **TPX001–TPX099**: parser / lexer faults (the document is not legal JSON / spec).
//! - **TPX100–TPX199**: schema-shape violations (the document parses but its structure violates
//!   the IR contract).
//! - **TPX200–TPX299**: registry / fact-id resolution faults.
//! - **TPX300–TPX399**: untranslatable constructs (the spec is well-formed but the lowering
//!   pipeline cannot express it on the configured target).
//! - **TPX400–TPX499**: parameter binding faults (`$param` references with missing values).
//! - **TPX500–TPX599**: predicate evaluation faults at compile time (e.g. type-incompatible
//!   constants in path-operator predicates).
//! - **TPX600–TPX699**: pack-coverage / capability-set violations (the configured registry
//!   does not advertise the facts the spec demands).
//!
//! Codes are stable: once published, a code's meaning does not change. New failure modes
//! get new codes.

/// `TPX001` — the trust-policy document is not legal JSON.
pub const TPX_001_PARSE_ERROR: &str = "TPX001";

/// `TPX100` — the document parses as JSON but violates the `TrustPolicySpec` schema
/// (missing required field, unknown field with `deny_unknown_fields`, wrong shape).
pub const TPX_100_SCHEMA_VIOLATION: &str = "TPX100";

/// `TPX200` — a `RequireFact.fact_id` is not advertised by the configured fact registry.
pub const TPX_200_UNKNOWN_FACT_ID: &str = "TPX200";

/// `TPX201` — the registered fact-id mapping is malformed (e.g. id does not match
/// `^[a-z][a-z0-9-]*/v[0-9]+$`).
pub const TPX_201_INVALID_FACT_ID_FORMAT: &str = "TPX201";

/// `TPX300` — a spec construct cannot be lowered against the current capability set
/// (e.g. an `AnyCounterSignature` without a Phase 3 fact lowerer registered).
pub const TPX_300_UNTRANSLATABLE: &str = "TPX300";

/// `TPX301` — recursion depth exceeded while compiling a spec tree (defends against
/// pathological inputs).
pub const TPX_301_RECURSION_LIMIT: &str = "TPX301";

/// `TPX400` — a `$param` reference has no binding and no default.
pub const TPX_400_PARAMETER_BIND_FAILED: &str = "TPX400";

/// `TPX401` — a `$param` literal is structurally malformed (e.g. non-string `$param` value).
pub const TPX_401_PARAMETER_REF_MALFORMED: &str = "TPX401";

/// `TPX500` — a predicate value is incompatible with its operator (e.g. `LessThan` against
/// a string literal).
pub const TPX_500_PREDICATE_TYPE_MISMATCH: &str = "TPX500";

/// `TPX600` — an `AnyCounterSignature` was requested but the registry doesn't list
/// counter-signature subject discovery.
pub const TPX_600_PACK_CAPABILITY_MISSING: &str = "TPX600";
