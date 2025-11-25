// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers;
using System.Diagnostics;

namespace CoseSign1.Certificates;

/// <summary>
/// An implementation of <see cref="ICoseHeaderExtender"/> that combines X.509 certificate headers
/// with CWT (CBOR Web Token) Claims headers. This extender ensures SCITT (Supply Chain Integrity,
/// Transparency, and Trust) compliance by adding required CWT claims alongside certificate-specific headers.
/// </summary>
/// <remarks>
/// <para>
/// This class is strongly-typed to <see cref="CertificateCoseSigningKeyProvider"/> for compile-time type safety.
/// </para>
/// <para>
/// This class provides "safe defaults" for SCITT compliance when signing with X.509 certificates:
/// - Issuer (iss): Derived from the certificate provider's <see cref="CertificateCoseSigningKeyProvider.Issuer"/> 
///   property, which defaults to a DID:x509 identifier from the certificate chain but can be overridden in derived classes
/// - Subject (sub): Defaults to "unknown.intent" if not explicitly specified
/// </para>
/// <para>
/// The DID:x509 issuer format follows the specification at:
/// https://github.com/microsoft/did-x509/blob/main/specification.md
/// </para>
/// <para>
/// This extender chains certificate headers (X5T, X5Chain) with CWT claims in the protected headers.
/// Callers can customize the CWT claims by providing their own <see cref="CWTClaimsHeaderExtender"/>.
/// </para>
/// </remarks>
public class X509CertificateWithCWTClaimsHeaderExtender : ICoseHeaderExtender
{
    private readonly CertificateCoseSigningKeyProvider CertificateKeyProvider;
    private readonly CWTClaimsHeaderExtender? CustomCWTClaimsExtender;
    private readonly CWTClaimsHeaderExtender DefaultCWTClaimsExtender;

    /// <summary>
    /// The default subject value used when no custom subject is specified.
    /// </summary>
    public const string DefaultSubject = "unknown.intent";

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificateWithCWTClaimsHeaderExtender"/> class
    /// with default CWT claims (DID:x509 issuer and "unknown.intent" subject).
    /// </summary>
    /// <param name="certificateKeyProvider">The certificate-based signing key provider.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateKeyProvider"/> is null.</exception>
    public X509CertificateWithCWTClaimsHeaderExtender(CertificateCoseSigningKeyProvider certificateKeyProvider)
    {
        CertificateKeyProvider = certificateKeyProvider ?? throw new ArgumentNullException(nameof(certificateKeyProvider));
        CustomCWTClaimsExtender = null;

        // Initialize default CWT claims extender with DID:x509 issuer and default subject
        DefaultCWTClaimsExtender = CreateDefaultCWTClaimsExtender();

        Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Initialized with default CWT claims.");
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CertificateWithCWTClaimsHeaderExtender"/> class
    /// with custom CWT claims.
    /// </summary>
    /// <param name="certificateKeyProvider">The certificate-based signing key provider.</param>
    /// <param name="customCWTClaimsExtender">
    /// A custom <see cref="CWTClaimsHeaderExtender"/> to use instead of the defaults.
    /// If provided, this completely replaces the default CWT claims (issuer and subject).
    /// If null, default claims will be used.
    /// </param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="certificateKeyProvider"/> is null.</exception>
    public X509CertificateWithCWTClaimsHeaderExtender(
        CertificateCoseSigningKeyProvider certificateKeyProvider,
        CWTClaimsHeaderExtender? customCWTClaimsExtender)
    {
        CertificateKeyProvider = certificateKeyProvider ?? throw new ArgumentNullException(nameof(certificateKeyProvider));
        CustomCWTClaimsExtender = customCWTClaimsExtender;

        // Initialize default CWT claims extender as fallback
        DefaultCWTClaimsExtender = CreateDefaultCWTClaimsExtender();

        if (customCWTClaimsExtender != null)
        {
            Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Initialized with custom CWT claims.");
        }
        else
        {
            Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Initialized with default CWT claims.");
        }
    }

    /// <summary>
    /// Creates a default <see cref="CWTClaimsHeaderExtender"/> with DID:x509 issuer and default subject.
    /// </summary>
    /// <returns>A <see cref="CWTClaimsHeaderExtender"/> with default claims.</returns>
    private CWTClaimsHeaderExtender CreateDefaultCWTClaimsExtender()
    {
        try
        {
            // Get the issuer from the certificate provider (defaults to DID:x509 but can be overridden)
            string? issuer = CertificateKeyProvider.Issuer;

            if (string.IsNullOrEmpty(issuer))
            {
                throw new InvalidOperationException("Certificate provider did not return a valid issuer value.");
            }

            // Create the CWT claims extender with default values
            CWTClaimsHeaderExtender extender = new CWTClaimsHeaderExtender()
                .SetIssuer(issuer)
                .SetSubject(DefaultSubject);

            Trace.TraceInformation($"X509CertificateWithCWTClaimsHeaderExtender: Created default CWT claims with issuer='{issuer}' and subject='{DefaultSubject}'.");
            return extender;
        }
        catch (Exception ex)
        {
            Trace.TraceError($"X509CertificateWithCWTClaimsHeaderExtender: Failed to create default CWT claims: {ex.Message}");
            throw new InvalidOperationException("Failed to create default CWT claims from certificate chain.", ex);
        }
    }

    /// <inheritdoc/>
    public CoseHeaderMap ExtendProtectedHeaders(CoseHeaderMap protectedHeaders)
    {
        if (protectedHeaders == null)
        {
            throw new ArgumentNullException(nameof(protectedHeaders));
        }

        // First, add certificate-specific headers (X5T, X5Chain)
        CoseHeaderMap? certHeaders = CertificateKeyProvider.GetProtectedHeaders();
        if (certHeaders != null)
        {
            foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> header in certHeaders)
            {
                protectedHeaders[header.Key] = header.Value;
            }
            Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Added certificate headers to protected headers.");
        }

        // Then, add CWT claims (custom or default)
        CWTClaimsHeaderExtender cwtExtender = CustomCWTClaimsExtender ?? DefaultCWTClaimsExtender;
        protectedHeaders = cwtExtender.ExtendProtectedHeaders(protectedHeaders);

        Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Extended protected headers with certificate and CWT claims.");
        return protectedHeaders;
    }

    /// <inheritdoc/>
    public CoseHeaderMap ExtendUnProtectedHeaders(CoseHeaderMap? unProtectedHeaders)
    {
        // Get unprotected headers from the certificate provider (if any)
        CoseHeaderMap? certUnprotectedHeaders = CertificateKeyProvider.GetUnProtectedHeaders();

        if (certUnprotectedHeaders != null)
        {
            unProtectedHeaders ??= new CoseHeaderMap();
            foreach (KeyValuePair<CoseHeaderLabel, CoseHeaderValue> header in certUnprotectedHeaders)
            {
                unProtectedHeaders[header.Key] = header.Value;
            }
            Trace.TraceInformation("X509CertificateWithCWTClaimsHeaderExtender: Added certificate unprotected headers.");
        }

        // CWT claims extender doesn't modify unprotected headers (CWT claims are protected only)
        CWTClaimsHeaderExtender cwtExtender = CustomCWTClaimsExtender ?? DefaultCWTClaimsExtender;
        unProtectedHeaders = cwtExtender.ExtendUnProtectedHeaders(unProtectedHeaders);

        return unProtectedHeaders ?? new CoseHeaderMap();
    }

    /// <summary>
    /// Gets the CWT claims extender being used (either custom or default).
    /// </summary>
    public CWTClaimsHeaderExtender ActiveCWTClaimsExtender => CustomCWTClaimsExtender ?? DefaultCWTClaimsExtender;
}
