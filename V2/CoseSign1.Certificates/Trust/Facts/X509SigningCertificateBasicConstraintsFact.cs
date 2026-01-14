// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Trust.Facts;

using CoseSign1.Validation.Trust.Facts;

/// <summary>
/// Fact describing the basic constraints of the signing certificate.
/// </summary>
public sealed class X509SigningCertificateBasicConstraintsFact : ISigningKeyFact
{
    /// <inheritdoc />
    public TrustFactScope Scope => TrustFactScope.SigningKey;

    /// <summary>
    /// Initializes a new instance of the <see cref="X509SigningCertificateBasicConstraintsFact"/> class.
    /// </summary>
    /// <param name="certificateThumbprint">Certificate thumbprint (hex string).</param>
    /// <param name="certificateAuthority">True if the certificate is a CA; otherwise false.</param>
    /// <param name="hasPathLengthConstraint">True if a path length constraint is present; otherwise false.</param>
    /// <param name="pathLengthConstraint">The path length constraint value when present; otherwise 0.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateThumbprint"/> is null.</exception>
    public X509SigningCertificateBasicConstraintsFact(
        string certificateThumbprint,
        bool certificateAuthority,
        bool hasPathLengthConstraint,
        int pathLengthConstraint)
    {
        CertificateThumbprint = certificateThumbprint ?? throw new ArgumentNullException(nameof(certificateThumbprint));
        CertificateAuthority = certificateAuthority;
        HasPathLengthConstraint = hasPathLengthConstraint;
        PathLengthConstraint = pathLengthConstraint;
    }

    /// <summary>
    /// Gets the certificate thumbprint (hex string).
    /// </summary>
    public string CertificateThumbprint { get; }

    /// <summary>
    /// Gets a value indicating whether the certificate is a certificate authority.
    /// </summary>
    public bool CertificateAuthority { get; }

    /// <summary>
    /// Gets a value indicating whether the path length constraint is present.
    /// </summary>
    public bool HasPathLengthConstraint { get; }

    /// <summary>
    /// Gets the path length constraint value.
    /// </summary>
    public int PathLengthConstraint { get; }
}
