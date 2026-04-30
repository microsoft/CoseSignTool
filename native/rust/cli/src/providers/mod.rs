// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider registry — compile-time feature-gated signing service providers.

pub mod local;
pub mod plugin;

#[cfg(feature = "aas")]
pub mod aas;

#[cfg(feature = "akv")]
pub mod akv;

#[cfg(feature = "mst")]
pub mod mst;
