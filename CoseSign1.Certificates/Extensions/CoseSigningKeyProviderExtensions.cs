// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Headers;

namespace CoseSign1.Certificates.Extensions;

/// <summary>
/// Extension methods for <see cref="CertificateCoseSigningKeyProvider"/> to facilitate creation of
/// header extenders that include CWT (CBOR Web Token) Claims for SCITT compliance.
/// </summary>
public static class CoseSigningKeyProviderExtensions
{
    /// <summary>
    /// Creates an <see cref="ICoseHeaderExtender"/> that adds certificate headers and default CWT claims
    /// (DID:x509 issuer and "unknown.intent" subject) for SCITT compliance.
    /// </summary>
    /// <param name="certificateProvider">The certificate-based signing key provider.</param>
    /// <returns>
    /// An <see cref="X509CertificateWithCWTClaimsHeaderExtender"/> that includes both
    /// certificate-specific headers (X5T, X5Chain) and default CWT claims.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateProvider"/> is null.</exception>
    /// <remarks>
    /// This method creates a header extender with "safe defaults" for SCITT compliance:
    /// - Issuer (iss): Derived as a DID:x509 identifier from the certificate chain
    /// - Subject (sub): Set to "unknown.intent"
    /// </remarks>
    public static ICoseHeaderExtender CreateHeaderExtenderWithDefaultCWTClaims(
        this CertificateCoseSigningKeyProvider certificateProvider)
    {
        if (certificateProvider == null)
        {
            throw new ArgumentNullException(nameof(certificateProvider));
        }

        return new X509CertificateWithCWTClaimsHeaderExtender(certificateProvider);
    }

    /// <summary>
    /// Creates an <see cref="ICoseHeaderExtender"/> that adds certificate headers and custom CWT claims
    /// for SCITT compliance.
    /// </summary>
    /// <param name="certificateProvider">The certificate-based signing key provider.</param>
    /// <param name="customCWTClaims">
    /// A custom <see cref="CWTClaimsHeaderExtender"/> with user-specified CWT claims.
    /// If null, default claims (DID:x509 issuer and "unknown.intent" subject) will be used.
    /// </param>
    /// <returns>
    /// An <see cref="X509CertificateWithCWTClaimsHeaderExtender"/> that includes both
    /// certificate-specific headers (X5T, X5Chain) and the specified CWT claims.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateProvider"/> is null.</exception>
    /// <remarks>
    /// This method allows full customization of CWT claims while ensuring certificate headers are properly included.
    /// </remarks>
    public static ICoseHeaderExtender CreateHeaderExtenderWithCustomCWTClaims(
        this CertificateCoseSigningKeyProvider certificateProvider,
        CWTClaimsHeaderExtender? customCWTClaims)
    {
        if (certificateProvider == null)
        {
            throw new ArgumentNullException(nameof(certificateProvider));
        }

        return new X509CertificateWithCWTClaimsHeaderExtender(certificateProvider, customCWTClaims);
    }

    /// <summary>
    /// Creates an <see cref="ICoseHeaderExtender"/> that adds certificate headers and CWT claims
    /// with custom issuer and subject values for SCITT compliance.
    /// </summary>
    /// <param name="certificateProvider">The certificate-based signing key provider.</param>
    /// <param name="issuer">
    /// The issuer (iss) claim value. If null, defaults to a DID:x509 identifier derived from the certificate chain.
    /// </param>
    /// <param name="subject">
    /// The subject (sub) claim value. If null, defaults to "unknown.intent".
    /// </param>
    /// <returns>
    /// An <see cref="X509CertificateWithCWTClaimsHeaderExtender"/> that includes both
    /// certificate-specific headers (X5T, X5Chain) and CWT claims with the specified issuer and subject.
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateProvider"/> is null.</exception>
    /// <remarks>
    /// This convenience method allows customization of the most commonly used CWT claims (issuer and subject)
    /// without needing to manually create a <see cref="CWTClaimsHeaderExtender"/>.
    /// </remarks>
    public static ICoseHeaderExtender CreateHeaderExtenderWithCWTClaims(
        this CertificateCoseSigningKeyProvider certificateProvider,
        string? issuer = null,
        string? subject = null)
    {
        if (certificateProvider == null)
        {
            throw new ArgumentNullException(nameof(certificateProvider));
        }

        // If both are null, use defaults
        if (issuer == null && subject == null)
        {
            return new X509CertificateWithCWTClaimsHeaderExtender(certificateProvider);
        }

        // Create a custom CWT claims extender with the specified values
        CWTClaimsHeaderExtender cwtClaims = new();

        if (issuer != null)
        {
            cwtClaims.SetIssuer(issuer);
        }
        else
        {
            // Use the provider's Issuer property (defaults to DID:x509 but can be overridden)
            string? providerIssuer = certificateProvider.Issuer;
            if (!string.IsNullOrEmpty(providerIssuer))
            {
                cwtClaims.SetIssuer(providerIssuer);
            }
        }

        if (subject != null)
        {
            cwtClaims.SetSubject(subject);
        }
        else
        {
            cwtClaims.SetSubject(X509CertificateWithCWTClaimsHeaderExtender.DefaultSubject);
        }

        return new X509CertificateWithCWTClaimsHeaderExtender(certificateProvider, cwtClaims);
    }
}
