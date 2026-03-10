// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Configuration options for certificate creation.
/// Use the fluent builder pattern to configure options.
/// </summary>
public class CertificateOptions
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string DefaultSubjectName = "CN=Ephemeral Certificate";
    }

    /// <summary>
    /// Gets or sets the subject name (Distinguished Name) for the certificate.
    /// Example: "CN=My Certificate, O=My Organization, C=US"
    /// Default: "CN=Ephemeral Certificate"
    /// </summary>
    public string SubjectName { get; set; } = ClassStrings.DefaultSubjectName;

    /// <summary>
    /// Gets or sets the cryptographic algorithm for key generation.
    /// Default: RSA
    /// </summary>
    public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.RSA;

    /// <summary>
    /// Gets or sets the key size in bits.
    /// If null, uses algorithm defaults: RSA=2048, ECDSA=256, ML-DSA=65.
    /// </summary>
    public int? KeySize { get; set; }

    /// <summary>
    /// Gets or sets the hash algorithm for certificate signing.
    /// Default: SHA256
    /// </summary>
    public CertificateHashAlgorithm HashAlgorithm { get; set; } = CertificateHashAlgorithm.SHA256;

    /// <summary>
    /// Gets or sets the certificate validity duration from creation time.
    /// Default: 1 hour (for ephemeral certificates).
    /// </summary>
    public TimeSpan Validity { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the not-before offset from current time.
    /// Negative values allow for clock skew tolerance.
    /// Default: -5 minutes
    /// </summary>
    public TimeSpan NotBeforeOffset { get; set; } = TimeSpan.FromMinutes(-5);

    /// <summary>
    /// Gets or sets whether this certificate is a Certificate Authority.
    /// Default: false
    /// </summary>
    public bool IsCertificateAuthority { get; set; }

    /// <summary>
    /// Gets or sets the CA path length constraint.
    /// Only applicable when IsCertificateAuthority is true.
    /// Default: 0 (can only issue end-entity certificates)
    /// </summary>
    public int PathLengthConstraint { get; set; } = 0;

    /// <summary>
    /// Gets or sets the key usage flags for the certificate.
    /// Default: DigitalSignature
    /// </summary>
    public X509KeyUsageFlags KeyUsage { get; set; } = X509KeyUsageFlags.DigitalSignature;

    /// <summary>
    /// Gets or sets the Enhanced Key Usage (EKU) OIDs.
    /// If null or empty, uses default code signing EKUs.
    /// </summary>
    public IList<string>? EnhancedKeyUsages { get; set; }

    /// <summary>
    /// Gets or sets Subject Alternative Names (SANs) as (type, value) tuples.
    /// Supported types: "dns", "email", "uri"
    /// If null or empty, adds a DNS SAN based on the subject name.
    /// </summary>
    public IList<(string Type, string Value)>? SubjectAlternativeNames { get; set; }

    /// <summary>
    /// Gets or sets the issuer certificate for creating signed certificates.
    /// If null, creates a self-signed certificate.
    /// </summary>
    public X509Certificate2? Issuer { get; set; }

    /// <summary>
    /// Gets or sets custom certificate extensions to add.
    /// </summary>
    public IList<X509Extension>? CustomExtensions { get; set; }

    /// <summary>
    /// Gets the computed NotBefore date for the certificate.
    /// </summary>
    public DateTimeOffset NotBefore => DateTimeOffset.UtcNow.Add(NotBeforeOffset);

    /// <summary>
    /// Gets the computed NotAfter date for the certificate.
    /// </summary>
    public DateTimeOffset NotAfter => DateTimeOffset.UtcNow.Add(Validity);
}