// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider registry — compile-time feature-gated signing service providers.

pub mod local;

#[cfg(feature = "ats")]
pub mod ats;

#[cfg(feature = "mst")]
pub mod mst;
