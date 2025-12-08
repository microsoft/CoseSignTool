// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate signing service for local (in-memory) certificates with direct key access.
/// Supports RSA and ECDsa algorithms using X509Certificate2 private keys.
/// </summary>
public class LocalCertificateSigningService : CertificateSigningService
{
    private readonly CertificateSigningKey _signingKey;

    /// <summary>
    /// Initializes a new instance of LocalCertificateSigningService.
    /// </summary>
    /// <param name="certificate">Certificate with private key for signing</param>
    /// <param name="chainBuilder">Chain builder to construct the certificate chain. Required.</param>
    public LocalCertificateSigningService(
        X509Certificate2 certificate,
        ICertificateChainBuilder chainBuilder)
        : base(isRemote: false)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (chainBuilder == null)
        {
            throw new ArgumentNullException(nameof(chainBuilder));
        }

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "Certificate must have a private key for local signing.",
                nameof(certificate));
        }

        var certificateSource = new DirectCertificateSource(certificate, chainBuilder);
        var signingKeyProvider = new DirectSigningKeyProvider(certificate);
        _signingKey = new CertificateSigningKey(certificateSource, signingKeyProvider, this);
    }

    /// <summary>
    /// Initializes a new instance of LocalCertificateSigningService with an explicit chain.
    /// </summary>
    /// <param name="certificate">Certificate with private key for signing</param>
    /// <param name="certificateChain">The complete certificate chain including the signing certificate</param>
    public LocalCertificateSigningService(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> certificateChain)
        : base(isRemote: false)
    {
        if (certificate == null)
        {
            throw new ArgumentNullException(nameof(certificate));
        }

        if (certificateChain == null)
        {
            throw new ArgumentNullException(nameof(certificateChain));
        }

        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException(
                "Certificate must have a private key for local signing.",
                nameof(certificate));
        }

        var certificateSource = new DirectCertificateSource(certificate, certificateChain);
        var signingKeyProvider = new DirectSigningKeyProvider(certificate);
        _signingKey = new CertificateSigningKey(certificateSource, signingKeyProvider, this);
    }

    /// <inheritdoc/>
    protected override ISigningKey GetSigningKey(SigningContext context)
    {
        // Always return the same signing key instance (cached)
        return _signingKey;
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _signingKey?.Dispose();
        }

        base.Dispose(disposing);
    }
}
