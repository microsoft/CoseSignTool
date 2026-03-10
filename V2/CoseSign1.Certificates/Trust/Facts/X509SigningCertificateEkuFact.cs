// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact representing an EKU OID on the signing certificate.
/// </summary>
public sealed class X509SigningCertificateEkuFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509SigningCertificateEkuFact"/> class.
    /// </summary>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="oidValue">The EKU OID value.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/> or <paramref name="oidValue"/> is null.</exception>
    public X509SigningCertificateEkuFact(string certificateThumbprint, string oidValue)
    {
        Guard.ThrowIfNull(certificateThumbprint);
        Guard.ThrowIfNull(oidValue);

        CertificateThumbprint = certificateThumbprint;
        OidValue = oidValue;
    }

    /// <summary>
    /// Gets the certificate thumbprint (hex string).
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// Gets the EKU OID value.
    /// </summary>
    public string OidValue { get; }
}
