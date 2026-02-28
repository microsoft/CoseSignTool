// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing support for Azure Trusted Signing.

pub mod ats_crypto_signer;
pub mod certificate_source;
pub mod did_x509_helper;
pub mod signing_service;

pub use signing_service::AzureTrustedSigningService;