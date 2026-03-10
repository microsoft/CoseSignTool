// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact describing a certificate present in the message's x5chain header.
/// </summary>
public sealed class X509X5ChainCertificateIdentityFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509X5ChainCertificateIdentityFact"/> class.
    /// </summary>
    /// <param name="index">The index in the provided chain (0-based).</param>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="subject">Certificate subject.</param>
    /// <param name="issuer">Certificate issuer.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/>, <paramref name="subject"/>, or <paramref name="issuer"/> is null.</exception>
    public X509X5ChainCertificateIdentityFact(int index, string certificateThumbprint, string subject, string issuer)
    {
        Guard.ThrowIfNull(certificateThumbprint);
        Guard.ThrowIfNull(subject);
        Guard.ThrowIfNull(issuer);

        Index = index;
        CertificateThumbprint = certificateThumbprint;
        Subject = subject;
        Issuer = issuer;
    }

    /// <summary>
    /// Gets the index in the provided chain (0-based).
    /// </summary>
    public int Index { get; }

    /// <summary>
    /// Gets the certificate thumbprint (hex string).
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// Gets the certificate subject.
    /// </summary>
    public string Subject { get; }

    /// <summary>
    /// Gets the certificate issuer.
    /// </summary>
    public string Issuer { get; }
}
