// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider registry — compile-time feature-gated signing service providers.

pub mod local;
pub mod plugin;

#[cfg(feature = "ats")]
pub mod ats;

#[cfg(feature = "akv")]
pub mod akv;

#[cfg(feature = "mst")]
pub mod mst;
