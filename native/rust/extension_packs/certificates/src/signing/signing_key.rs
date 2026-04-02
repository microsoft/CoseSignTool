// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate signing key — maps V2 ICertificateSigningKey.

use cose_sign1_signing::SigningServiceKey;
use crypto_primitives::CryptoSigner;

use crate::chain_sort_order::X509ChainSortOrder;
use crate::error::CertificateError;

/// Certificate signing key extending SigningServiceKey with cert-specific operations.
/// Maps V2 `ICertificateSigningKey`.
///
/// Provides access to the signing certificate and certificate chain
/// for x5t/x5chain header generation.
pub trait CertificateSigningKey: SigningServiceKey + CryptoSigner {
    /// Gets the signing certificate as DER-encoded bytes.
    fn get_signing_certificate(&self) -> Result<&[u8], CertificateError>;

    /// Gets the certificate chain in the specified order.
    /// Each entry is a DER-encoded X.509 certificate.
    fn get_certificate_chain(
        &self,
        sort_order: X509ChainSortOrder,
    ) -> Result<Vec<Vec<u8>>, CertificateError>;
}
