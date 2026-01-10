// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Extends ISigningServiceKey with certificate-specific operations.
/// Provides access to the signing certificate and certificate chain for X5T/X5Chain header generation.
/// </summary>
/// <remarks>
/// This interface extends <see cref="ISigningServiceKey"/> (not just <see cref="ISigningKey"/>) because
/// certificate-based signing inherently requires metadata and service context for proper header
/// construction (algorithm selection, chain building, etc.).
/// </remarks>
public interface ICertificateSigningKey : ISigningServiceKey
{
    /// <summary>
    /// Gets the signing certificate used for the signing operation.
    /// </summary>
    /// <returns>The X509Certificate2 instance used for signing.</returns>
    X509Certificate2 GetSigningCertificate();

    /// <summary>
    /// Gets the certificate chain for the signing certificate.
    /// </summary>
    /// <param name="sortOrder">The sort order for the certificate chain (LeafFirst or RootFirst).</param>
    /// <returns>An enumerable of certificates in the specified order.</returns>
    IEnumerable<X509Certificate2> GetCertificateChain(X509ChainSortOrder sortOrder);
}