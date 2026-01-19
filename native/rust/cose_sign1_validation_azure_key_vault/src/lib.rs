// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Key Vault-related trust pack components.
//!
//! This crate provides a trust pack for scenarios where COSE headers (for
//! example, `kid`) are used to bind a message to an Azure Key Vault key
//! identity/policy.
//!
//! The primary integration point is [`pack`], typically composed via
//! `cose_sign1_validation::fluent`.

pub mod facts;
pub mod fluent_ext;
pub mod pack;
