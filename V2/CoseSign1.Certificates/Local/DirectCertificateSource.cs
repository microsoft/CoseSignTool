// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.ChainBuilders;

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Certificate source that wraps a directly provided X509Certificate2 with chain support.
/// The chain is managed through an <see cref="ICertificateChainBuilder"/>.
/// </summary>
public class DirectCertificateSource : CertificateSourceBase
{
    private readonly X509Certificate2 Certificate;

    /// <summary>
    /// Initializes a new instance of DirectCertificateSource with an explicit chain.
    /// Creates an <see cref="ExplicitCertificateChainBuilder"/> to manage the provided chain.
    /// </summary>
    /// <param name="certificate">The signing certificate</param>
    /// <param name="certificateChain">The complete certificate chain including the signing certificate</param>
    /// <param name="chainBuilder">Optional custom chain builder. If null, creates ExplicitCertificateChainBuilder.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> or <paramref name="certificateChain"/> is null.</exception>
    public DirectCertificateSource(
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> certificateChain,
        ICertificateChainBuilder? chainBuilder = null)
        : base(certificateChain, chainBuilder)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
    }

    /// <summary>
    /// Initializes a new instance of DirectCertificateSource with a chain builder.
    /// </summary>
    /// <param name="certificate">The signing certificate</param>
    /// <param name="chainBuilder">Chain builder to construct the certificate chain</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificate"/> is null.</exception>
    public DirectCertificateSource(X509Certificate2 certificate, ICertificateChainBuilder chainBuilder)
        : base(chainBuilder)
    {
        Certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
    }

    /// <inheritdoc/>
    public override X509Certificate2 GetSigningCertificate() => Certificate;

    /// <inheritdoc/>
    public override bool HasPrivateKey => Certificate.HasPrivateKey;

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        // Don't dispose the certificate - caller owns it
        base.Dispose(disposing);
    }
}