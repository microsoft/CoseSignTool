// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Local;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Extension methods for adding certificate validation to the builder.
/// </summary>
public static class CertificateValidationExtensions
{
    /// <summary>
    /// Validates certificate properties using a domain-specific builder.
    /// Transfers control to ICertificateValidationBuilder for certificate-specific configuration.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="configure">Configuration action for the certificate validation builder.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificate(
        this ICoseMessageValidationBuilder builder,
        Action<ICertificateValidationBuilder> configure)
    {
        var certBuilder = new CertificateValidationBuilder();
        configure(certBuilder);

        // Build certificate validator and add to main builder
        var validator = certBuilder.Build();
        return builder.AddValidator(validator);
    }

    /// <summary>
    /// Validates that the signing certificate's common name matches the expected value.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="expectedCommonName">The expected common name (CN) value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateCommonName(
        this ICoseMessageValidationBuilder builder,
        string expectedCommonName,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateCommonNameValidator(expectedCommonName, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates that the signing certificate has not expired.
    /// Uses the current time for validation.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateExpiration(
        this ICoseMessageValidationBuilder builder,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateExpirationValidator(allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates that the signing certificate was valid at the specified time.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="validationTime">The time at which to validate the certificate.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateExpiration(
        this ICoseMessageValidationBuilder builder,
        DateTime validationTime,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateExpirationValidator(validationTime, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates the certificate chain trust using system roots.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateChain(
        this ICoseMessageValidationBuilder builder,
        bool allowUnprotectedHeaders = false,
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        return builder.AddValidator(new CertificateChainValidator(allowUnprotectedHeaders, allowUntrusted, revocationMode));
    }

    /// <summary>
    /// Validates the certificate chain trust using custom roots.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="customRoots">Custom root certificates to trust.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    /// <param name="revocationMode">The revocation check mode.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateChain(
        this ICoseMessageValidationBuilder builder,
        X509Certificate2Collection customRoots,
        bool allowUnprotectedHeaders = false,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        return builder.AddValidator(new CertificateChainValidator(customRoots, allowUnprotectedHeaders, trustUserRoots, revocationMode));
    }

    /// <summary>
    /// Validates the certificate chain trust using a custom chain builder.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="chainBuilder">The chain builder to use for validation.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="allowUntrusted">Whether to allow untrusted roots to pass validation.</param>
    /// <param name="customRoots">Optional custom root certificates.</param>
    /// <param name="trustUserRoots">Whether to trust the custom roots.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateChain(
        this ICoseMessageValidationBuilder builder,
        ICertificateChainBuilder chainBuilder,
        bool allowUnprotectedHeaders = false,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true)
    {
        return builder.AddValidator(new CertificateChainValidator(chainBuilder, allowUnprotectedHeaders, allowUntrusted, customRoots, trustUserRoots));
    }

    /// <summary>
    /// Validates that the signing certificate has the required key usage flags.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="requiredKeyUsage">The required key usage flags.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateKeyUsage(
        this ICoseMessageValidationBuilder builder,
        X509KeyUsageFlags requiredKeyUsage,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateKeyUsageValidator(requiredKeyUsage, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates that the signing certificate has the required enhanced key usage (EKU).
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="requiredEku">The required enhanced key usage OID.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateEnhancedKeyUsage(
        this ICoseMessageValidationBuilder builder,
        Oid requiredEku,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateKeyUsageValidator(requiredEku, allowUnprotectedHeaders));
    }

    /// <summary>
    /// Validates that the signing certificate has the required enhanced key usage (EKU) by OID value.
    /// </summary>
    /// <param name="builder">The validation builder.</param>
    /// <param name="requiredEkuOid">The required enhanced key usage OID value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <returns>The builder for method chaining.</returns>
    public static ICoseMessageValidationBuilder ValidateCertificateEnhancedKeyUsage(
        this ICoseMessageValidationBuilder builder,
        string requiredEkuOid,
        bool allowUnprotectedHeaders = false)
    {
        return builder.AddValidator(new CertificateKeyUsageValidator(requiredEkuOid, allowUnprotectedHeaders));
    }
}