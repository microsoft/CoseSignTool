// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact describing the signing certificate used for a message's signing key.
/// </summary>
public sealed class X509SigningCertificateIdentityFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509SigningCertificateIdentityFact"/> class.
    /// </summary>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="subject">Certificate subject.</param>
    /// <param name="issuer">Certificate issuer.</param>
    /// <param name="serialNumber">Certificate serial number (hex string).</param>
    /// <param name="notBefore">Certificate not-before timestamp (UTC).</param>
    /// <param name="notAfter">Certificate not-after timestamp (UTC).</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/>, <paramref name="subject"/>, <paramref name="issuer"/>, or <paramref name="serialNumber"/> is null.</exception>
    public X509SigningCertificateIdentityFact(
        string certificateThumbprint,
        string subject,
        string issuer,
        string serialNumber,
        DateTime notBefore,
        DateTime notAfter)
    {
        CertificateThumbprint = certificateThumbprint ?? throw new ArgumentNullException(nameof(certificateThumbprint));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        SerialNumber = serialNumber ?? throw new ArgumentNullException(nameof(serialNumber));
        NotBeforeUtc = notBefore.ToUniversalTime();
        NotAfterUtc = notAfter.ToUniversalTime();
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
    /// Gets the certificate serial number (hex string).
    /// </summary>
    public string SerialNumber { get; }

    /// <summary>
    /// Gets the certificate not-before timestamp (UTC).
    /// </summary>
    public DateTime NotBeforeUtc { get; }

    /// <summary>
    /// Gets the certificate not-after timestamp (UTC).
    /// </summary>
    public DateTime NotAfterUtc { get; }
}
