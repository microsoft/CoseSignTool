// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Abstracts certificate source - where certificates come from.
/// Implementations:
/// - DirectCertificateSource: X509Certificate2 directly provided
/// - PfxCertificateSource: Loaded from PFX file
/// - StoreCertificateSource: Retrieved from Windows certificate store
/// - RemoteCertificateSource: Retrieved from remote signing service
/// </summary>
public interface ICertificateSource : IDisposable
{
    /// <summary>
    /// Gets the signing certificate.
    /// </summary>
    /// <returns>The X509Certificate2 to use for signing</returns>
    X509Certificate2 GetSigningCertificate();

    /// <summary>
    /// Gets whether the certificate has a private key accessible locally.
    /// False for remote certificates where signing happens remotely.
    /// </summary>
    bool HasPrivateKey { get; }

    /// <summary>
    /// Gets the certificate chain builder for this source.
    /// </summary>
    /// <returns>The certificate chain builder</returns>
    ICertificateChainBuilder GetChainBuilder();
}