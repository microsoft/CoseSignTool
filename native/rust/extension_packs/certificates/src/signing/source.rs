// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate source abstraction — maps V2 ICertificateSource.
//! Abstracts where certificates come from (local file, store, remote service).

use crate::chain_builder::CertificateChainBuilder;
use crate::error::CertificateError;

/// Abstracts certificate source — where certificates come from.
/// Maps V2 `ICertificateSource`.
///
/// Implementations:
/// - `DirectCertificateSource`: Certificate provided directly as DER bytes
/// - Remote sources: Retrieved from Azure Key Vault, Azure Artifact Signing, etc.
pub trait CertificateSource: Send + Sync {
    /// Gets the signing certificate as DER-encoded bytes.
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError>;

    /// Whether the certificate has a locally-accessible private key.
    /// False for remote certificates where signing happens remotely.
    fn has_private_key(&self) -> bool;

    /// Gets the chain builder for this certificate source.
    fn get_chain_builder(&self) -> &dyn CertificateChainBuilder;
}
