// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! AKV validation support.
//!
//! Provides trust facts, fluent API extensions, trust pack, and
//! key resolvers for validating COSE signatures using Azure Key Vault.

pub mod facts;
pub mod fluent_ext;
pub mod pack;

pub use facts::*;
pub use fluent_ext::*;
pub use pack::*;
