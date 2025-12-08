// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.ChainBuilders;
using CoseSign1.Certificates.Interfaces;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that wraps a directly provided X509Certificate2 with chain support.
/// The chain is managed through an <see cref="ICertificateChainBuilder"/>.
/// </summary>
public class DirectCertificateSource : ICertificateSource
{
    private readonly X509Certificate2 _certificate;
    private readonly ICertificateChainBuilder _chainBuilder;
    private bool _disposed;

    /// <summary>
    /// Initializes a new instance of DirectCertificateSource with an explicit chain.
    /// Creates an <see cref="ExplicitCertificateChainBuilder"/> to manage the provided chain.
    /// </summary>
    /// <param name="certificate">The signing certificate</param>
    /// <param name="certificateChain">The complete certificate chain including the signing certificate</param>
    public DirectCertificateSource(X509Certificate2 certificate, IReadOnlyList<X509Certificate2> certificateChain)
        : this(certificate, new ExplicitCertificateChainBuilder(certificateChain))
    {
    }

    /// <summary>
    /// Initializes a new instance of DirectCertificateSource with a chain builder.
    /// </summary>
    /// <param name="certificate">The signing certificate</param>
    /// <param name="chainBuilder">Chain builder to construct the certificate chain</param>
    public DirectCertificateSource(X509Certificate2 certificate, ICertificateChainBuilder chainBuilder)
    {
        _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
        _chainBuilder = chainBuilder ?? throw new ArgumentNullException(nameof(chainBuilder));
    }

    /// <inheritdoc/>
    public X509Certificate2 GetSigningCertificate() => _certificate;

    /// <inheritdoc/>
    public bool HasPrivateKey => _certificate.HasPrivateKey;

    /// <inheritdoc/>
    public ICertificateChainBuilder GetChainBuilder() => _chainBuilder;

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        if (_chainBuilder is IDisposable disposable)
        {
            disposable.Dispose();
        }

        // Don't dispose the certificate - caller owns it
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
