// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Extends ISigningKey with certificate-specific operations.
/// Provides access to the signing certificate and certificate chain for X5T/X5Chain header generation.
/// </summary>
public interface ICertificateSigningKey : ISigningKey
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