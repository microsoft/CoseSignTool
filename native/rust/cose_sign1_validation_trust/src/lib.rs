// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trust evaluation engine for COSE_Sign1 validation.
//!
//! This crate models “trust” as an explicit decision over a [`subject`] using a
//! plan/policy composed of [`rules`] evaluated against a set of [`facts`].
//!
//! Most callers should use the fluent builders in [`fluent`] (often indirectly
//! via `cose_sign1_validation::fluent`) rather than assembling rules and plans
//! manually.

pub mod audit;
pub mod cose_sign1;
pub mod decision;
pub mod error;
pub mod evaluation_options;
pub mod fact_properties;
pub mod facts;
pub mod field;
pub mod fluent;
pub mod ids;
pub mod plan;
pub mod policy;
pub mod rules;
pub mod subject;

pub use cose_sign1::{CoseHeaderMap, CoseHeaderValue, CoseSign1ParsedMessage};
pub use decision::TrustDecision;
pub use evaluation_options::{CoseHeaderLocation, TrustEvaluationOptions};
