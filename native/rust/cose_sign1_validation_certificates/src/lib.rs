// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificates trust pack for COSE_Sign1 validation.
//!
//! This crate contributes facts, resolvers, and default trust behavior focused
//! on X.509-backed signatures (for example, `x5chain`).
//!
//! The main integration point is [`pack`], which can be composed into a
//! `cose_sign1_validation` validator pipeline via the fluent API.

pub mod facts;
pub mod fluent_ext;
pub mod pack;
pub mod signing_key_resolver;
