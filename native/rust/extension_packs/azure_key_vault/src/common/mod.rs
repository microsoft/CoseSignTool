// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common Azure Key Vault types and utilities.
//!
//! This module provides shared functionality for AKV signing and validation,
//! including algorithm mapping and crypto client abstractions.

pub mod error;
pub mod crypto_client;
pub mod akv_key_client;

pub use error::AkvError;
pub use crypto_client::KeyVaultCryptoClient;
pub use akv_key_client::AkvKeyClient;
