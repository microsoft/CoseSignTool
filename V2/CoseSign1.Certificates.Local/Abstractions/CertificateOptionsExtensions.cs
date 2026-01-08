// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Local;

/// <summary>
/// Fluent builder extensions for <see cref="CertificateOptions"/>.
/// </summary>
public static class CertificateOptionsExtensions
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string SubjectAltNameTypeDns = "dns";
        public const string SubjectAltNameTypeEmail = "email";
        public const string SubjectAltNameTypeUri = "uri";
    }

    /// <summary>
    /// Sets the subject name for the certificate.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="subjectName">The subject name.</param>
    /// <returns>The same options instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="subjectName"/> is null.</exception>
    public static CertificateOptions WithSubjectName(this CertificateOptions options, string subjectName)
    {
        options.SubjectName = subjectName ?? throw new ArgumentNullException(nameof(subjectName));
        return options;
    }

    /// <summary>
    /// Sets the cryptographic algorithm for key generation.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="algorithm">The key algorithm.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithKeyAlgorithm(this CertificateOptions options, KeyAlgorithm algorithm)
    {
        options.KeyAlgorithm = algorithm;
        return options;
    }

    /// <summary>
    /// Sets the key size in bits.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="keySize">The key size in bits.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithKeySize(this CertificateOptions options, int keySize)
    {
        options.KeySize = keySize;
        return options;
    }

    /// <summary>
    /// Sets the hash algorithm for certificate signing.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithHashAlgorithm(this CertificateOptions options, CertificateHashAlgorithm hashAlgorithm)
    {
        options.HashAlgorithm = hashAlgorithm;
        return options;
    }

    /// <summary>
    /// Sets the certificate validity duration.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="validity">The validity duration.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithValidity(this CertificateOptions options, TimeSpan validity)
    {
        options.Validity = validity;
        return options;
    }

    /// <summary>
    /// Sets the not-before offset for clock skew tolerance.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="offset">The not-before offset.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithNotBeforeOffset(this CertificateOptions options, TimeSpan offset)
    {
        options.NotBeforeOffset = offset;
        return options;
    }

    /// <summary>
    /// Configures this certificate as a Certificate Authority.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="pathLengthConstraint">The CA path length constraint.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions AsCertificateAuthority(this CertificateOptions options, int pathLengthConstraint = 0)
    {
        options.IsCertificateAuthority = true;
        options.PathLengthConstraint = pathLengthConstraint;
        options.KeyUsage = X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature;
        return options;
    }

    /// <summary>
    /// Sets the key usage flags.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="keyUsage">The key usage flags.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithKeyUsage(this CertificateOptions options, X509KeyUsageFlags keyUsage)
    {
        options.KeyUsage = keyUsage;
        return options;
    }

    /// <summary>
    /// Adds Enhanced Key Usage OIDs.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="ekuOids">Enhanced key usage OID values.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithEnhancedKeyUsages(this CertificateOptions options, params string[] ekuOids)
    {
        options.EnhancedKeyUsages ??= new List<string>();
        foreach (string oid in ekuOids)
        {
            options.EnhancedKeyUsages.Add(oid);
        }
        return options;
    }

    /// <summary>
    /// Adds a DNS Subject Alternative Name.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="dnsName">The DNS name.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithDnsSan(this CertificateOptions options, string dnsName)
    {
        options.SubjectAlternativeNames ??= new List<(string, string)>();
        options.SubjectAlternativeNames.Add((ClassStrings.SubjectAltNameTypeDns, dnsName));
        return options;
    }

    /// <summary>
    /// Adds an email Subject Alternative Name.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="email">The email address.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithEmailSan(this CertificateOptions options, string email)
    {
        options.SubjectAlternativeNames ??= new List<(string, string)>();
        options.SubjectAlternativeNames.Add((ClassStrings.SubjectAltNameTypeEmail, email));
        return options;
    }

    /// <summary>
    /// Adds a URI Subject Alternative Name.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="uri">The URI value.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithUriSan(this CertificateOptions options, string uri)
    {
        options.SubjectAlternativeNames ??= new List<(string, string)>();
        options.SubjectAlternativeNames.Add((ClassStrings.SubjectAltNameTypeUri, uri));
        return options;
    }

    /// <summary>
    /// Sets the issuer certificate for creating signed certificates.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="issuer">The issuer certificate.</param>
    /// <returns>The same options instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="issuer"/> is null.</exception>
    public static CertificateOptions SignedBy(this CertificateOptions options, X509Certificate2 issuer)
    {
        options.Issuer = issuer ?? throw new ArgumentNullException(nameof(issuer));
        return options;
    }

    /// <summary>
    /// Adds a custom X509 extension.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="extension">The extension to add.</param>
    /// <returns>The same options instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="extension"/> is null.</exception>
    public static CertificateOptions WithExtension(this CertificateOptions options, X509Extension extension)
    {
        options.CustomExtensions ??= new List<X509Extension>();
        options.CustomExtensions.Add(extension ?? throw new ArgumentNullException(nameof(extension)));
        return options;
    }

    /// <summary>
    /// Adds the Microsoft Lifetime Signing EKU.
    /// This indicates signatures remain valid after the certificate expires.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithLifetimeSigning(this CertificateOptions options)
    {
        return options.WithEnhancedKeyUsages(EnhancedKeyUsageOids.LifetimeSigning);
    }

    /// <summary>
    /// Configures the certificate with Code Signing EKU.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions ForCodeSigning(this CertificateOptions options)
    {
        return options.WithEnhancedKeyUsages(EnhancedKeyUsageOids.CodeSigning);
    }

    /// <summary>
    /// Configures the certificate with TLS authentication EKUs (server and client).
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions ForTlsAuthentication(this CertificateOptions options)
    {
        return options.WithEnhancedKeyUsages(
            EnhancedKeyUsageOids.ServerAuthentication,
            EnhancedKeyUsageOids.ClientAuthentication);
    }

    /// <summary>
    /// Adds multiple Subject Alternative Names.
    /// </summary>
    /// <param name="options">The certificate options.</param>
    /// <param name="sans">SANs as (type, value) tuples where type is "dns", "email", or "uri".</param>
    /// <returns>The same options instance.</returns>
    public static CertificateOptions WithSubjectAlternativeNames(
        this CertificateOptions options,
        params (string Type, string Value)[] sans)
    {
        options.SubjectAlternativeNames ??= new List<(string, string)>();
        foreach (var san in sans)
        {
            options.SubjectAlternativeNames.Add(san);
        }
        return options;
    }
}