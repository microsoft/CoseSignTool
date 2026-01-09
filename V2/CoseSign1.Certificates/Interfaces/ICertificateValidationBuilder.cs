// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Interfaces;

/// <summary>
/// Domain-specific builder for certificate validation.
/// Keeps certificate-specific APIs separate from main builder.
/// </summary>
public interface ICertificateValidationBuilder
{
    /// <summary>
    /// Builds the configured certificate validator.
    /// Signature validation is always included.
    /// </summary>
    /// <returns>The composed validator.</returns>
    IValidator Build();

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

    /// <summary>
    /// Configures the logger factory for diagnostic logging in validators.
    /// </summary>
    /// <param name="loggerFactory">The logger factory to use for creating loggers.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder WithLoggerFactory(ILoggerFactory? loggerFactory);

    /// <summary>
    /// Validates the certificate chain using system roots.
    /// </summary>
    /// <param name="allowUntrusted">Whether to allow an untrusted chain.</param>
    /// <param name="revocationMode">The revocation mode.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder ValidateChain(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online);

    /// <summary>
    /// Validates the certificate chain using custom roots.
    /// </summary>
    /// <param name="customRoots">The custom roots to trust.</param>
    /// <param name="trustUserRoots">Whether to trust user root stores in addition to <paramref name="customRoots"/>.</param>
    /// <param name="revocationMode">The revocation mode.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online);

    /// <summary>
    /// Validates the certificate chain using a custom chain builder.
    /// </summary>
    /// <param name="chainBuilder">The chain builder to use.</param>
    /// <param name="allowUntrusted">Whether to allow an untrusted chain.</param>
    /// <param name="customRoots">Optional custom roots.</param>
    /// <param name="trustUserRoots">Whether to trust user root stores in addition to <paramref name="customRoots"/>.</param>
    /// <returns>The builder for method chaining.</returns>
    ICertificateValidationBuilder ValidateChain(
        ICertificateChainBuilder chainBuilder,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true);
}