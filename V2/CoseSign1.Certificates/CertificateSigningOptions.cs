// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Headers;

namespace CoseSign1.Certificates;

/// <summary>
/// Options specific to certificate-based signing operations.
/// Extends base SigningOptions with certificate-specific settings.
/// </summary>
public class CertificateSigningOptions : SigningOptions
{
    /// <summary>
    /// Gets or sets whether SCITT (Supply Chain Integrity, Transparency, and Trust) compliance is enabled.
    /// When enabled, default CWT claims (issuer and subject) will be automatically added to the signature
    /// for compliance with SCITT transparency service requirements.
    /// Default is false.
    /// </summary>
    /// <remarks>
    /// <para>
    /// SCITT requires CWT Claims (RFC 9597) in the protected headers with at minimum:
    /// - Issuer (iss): Typically a DID:x509 identifier from the certificate chain
    /// - Subject (sub): The subject of the signed content (defaults to "unknown.intent")
    /// - IssuedAt (iat): Timestamp when the signature was created
    /// - NotBefore (nbf): Timestamp before which the signature should not be accepted
    /// </para>
    /// <para>
    /// Use CustomCwtClaims to provide custom claims that override the defaults.
    /// See: https://ietf-wg-scitt.github.io/draft-ietf-scitt-architecture/
    /// </para>
    /// </remarks>
    public bool EnableScittCompliance { get; set; } = false;

    /// <summary>
    /// Gets or sets custom CWT claims to use when SCITT compliance is enabled.
    /// If null and EnableScittCompliance is true, default claims will be generated with:
    /// - Issuer: DID:x509 identifier from the signing certificate chain
    /// - Subject: "unknown.intent"
    /// - IssuedAt: Current timestamp
    /// - NotBefore: Current timestamp
    /// 
    /// Set this property to provide custom claims that override or augment the defaults.
    /// At minimum, SCITT compliance requires issuer and subject claims.
    /// </summary>
    /// <example>
    /// <code>
    /// var options = new CertificateSigningOptions
    /// {
    ///     EnableScittCompliance = true,
    ///     CustomCwtClaims = new CwtClaims
    ///     {
    ///         Issuer = "https://example.com/issuer",
    ///         Subject = "pkg:npm/my-package@1.0.0",
    ///         Audience = "https://transparency.example.com"
    ///     }
    /// };
    /// </code>
    /// </example>
    public CwtClaims? CustomCwtClaims { get; set; }
}