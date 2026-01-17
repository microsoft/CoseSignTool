// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact indicating whether the signing certificate identity satisfies the configured allow-list.
/// </summary>
public sealed class X509SigningCertificateIdentityAllowedFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509SigningCertificateIdentityAllowedFact"/> class.
    /// </summary>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="subject">Certificate subject.</param>
    /// <param name="issuer">Certificate issuer.</param>
    /// <param name="isAllowed">True if the identity is allowed; otherwise, false.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/>, <paramref name="subject"/>, or <paramref name="issuer"/> is null.</exception>
    public X509SigningCertificateIdentityAllowedFact(
        string certificateThumbprint,
        string subject,
        string issuer,
        bool isAllowed)
    {
        Guard.ThrowIfNull(certificateThumbprint);
        Guard.ThrowIfNull(subject);
        Guard.ThrowIfNull(issuer);

        CertificateThumbprint = certificateThumbprint;
        Subject = subject;
        Issuer = issuer;
        IsAllowed = isAllowed;
    }

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

    /// <summary>
    /// Gets a value indicating whether the certificate identity is allowed by configuration.
    /// </summary>
    public bool IsAllowed { get; }
}
