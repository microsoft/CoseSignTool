// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Domain-specific builder for certificate validation.
/// Keeps certificate-specific APIs separate from main builder.
/// </summary>
public interface ICertificateValidationBuilder
{
    /// <summary>
    /// Validates that the certificate has the specified common name (CN).
    /// </summary>
    /// <param name="commonName">The expected common name.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder HasCommonName(string commonName);

    /// <summary>
    /// Validates that the certificate is issued by the specified issuer.
    /// </summary>
    /// <param name="issuerName">The expected issuer name.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder IsIssuedBy(string issuerName);

    /// <summary>
    /// Validates that the certificate has not expired (uses current time).
    /// </summary>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder NotExpired();

    /// <summary>
    /// Validates that the certificate was valid at the specified time.
    /// </summary>
    /// <param name="asOf">The time at which to validate the certificate.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder NotExpired(DateTime asOf);

    /// <summary>
    /// Validates that the certificate has the specified enhanced key usage (EKU).
    /// </summary>
    /// <param name="eku">The required enhanced key usage OID.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku);

    /// <summary>
    /// Validates that the certificate has the specified enhanced key usage (EKU) by OID value.
    /// </summary>
    /// <param name="ekuOid">The required enhanced key usage OID value.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid);

    /// <summary>
    /// Validates that the certificate has the specified key usage flags.
    /// </summary>
    /// <param name="usage">The required key usage flags.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage);

    /// <summary>
    /// Validates the certificate using a custom predicate.
    /// </summary>
    /// <param name="predicate">The custom validation function.</param>
    /// <param name="failureMessage">The error message if validation fails.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null);

    /// <summary>
    /// Configures whether to allow unprotected headers for certificate lookup.
    /// </summary>
    /// <param name="allow">Whether to allow unprotected headers.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder AllowUnprotectedHeaders(bool allow = true);
}
