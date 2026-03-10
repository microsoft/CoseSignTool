// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing support for Azure Artifact Signing.

pub mod aas_crypto_signer;
pub mod certificate_source;
pub mod did_x509_helper;
pub mod signing_service;

pub use signing_service::AzureArtifactSigningService;