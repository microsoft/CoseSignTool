// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact representing the key usage flags present on the signing certificate.
/// </summary>
public sealed class X509SigningCertificateKeyUsageFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509SigningCertificateKeyUsageFact"/> class.
    /// </summary>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="keyUsages">The key usage flags.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/> is null.</exception>
    public X509SigningCertificateKeyUsageFact(string certificateThumbprint, X509KeyUsageFlags keyUsages)
    {
        Guard.ThrowIfNull(certificateThumbprint);
        CertificateThumbprint = certificateThumbprint;
        KeyUsages = keyUsages;
    }

    /// <summary>
    /// Gets the certificate thumbprint (hex string).
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// Gets the key usage flags.
    /// </summary>
    public X509KeyUsageFlags KeyUsages { get; }
}
