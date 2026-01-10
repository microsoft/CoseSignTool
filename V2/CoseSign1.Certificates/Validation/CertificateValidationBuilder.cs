// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Implementation of the certificate validation builder.
/// Collects certificate assertion providers and builds a collection of them.
/// </summary>
public sealed class CertificateValidationBuilder : ICertificateValidationBuilder
{
    private readonly List<Func<ILoggerFactory?, ISigningKeyAssertionProvider>> ProviderFactories = new();
    private ILoggerFactory? LoggerFactoryField;

    /// <summary>
    /// Creates a builder for certificate assertion providers.
    /// </summary>
    public CertificateValidationBuilder()
    {
    }

    /// <summary>
    /// Creates a builder for certificate assertion providers with logging.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for diagnostic logging.</param>
    public CertificateValidationBuilder(ILoggerFactory? loggerFactory)
    {
        LoggerFactoryField = loggerFactory;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder WithLoggerFactory(ILoggerFactory? loggerFactory)
    {
        LoggerFactoryField = loggerFactory;
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasCommonName(string commonName)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateCommonNameAssertionProvider(
                commonName,
                loggerFactory?.CreateLogger<CertificateCommonNameAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder IsIssuedBy(string issuerName)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateIssuerAssertionProvider(
                issuerName,
                loggerFactory?.CreateLogger<CertificateIssuerAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired()
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateExpirationAssertionProvider(
                loggerFactory?.CreateLogger<CertificateExpirationAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired(DateTime asOf)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateExpirationAssertionProvider(
                asOf,
                loggerFactory?.CreateLogger<CertificateExpirationAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateKeyUsageAssertionProvider(
                eku,
                loggerFactory?.CreateLogger<CertificateKeyUsageAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateKeyUsageAssertionProvider(
                ekuOid,
                loggerFactory?.CreateLogger<CertificateKeyUsageAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateKeyUsageAssertionProvider(
                usage,
                loggerFactory?.CreateLogger<CertificateKeyUsageAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null)
    {
        ThrowIfNull(predicate, nameof(predicate));

        ProviderFactories.Add(loggerFactory =>
            new CertificatePredicateAssertionProvider(
                predicate,
                failureMessage,
                loggerFactory?.CreateLogger<CertificatePredicateAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder WithCertificateHeaderLocation(CoseHeaderLocation headerLocation)
    {
        // This is no longer used as assertion providers receive the signing key directly
        // Keeping for API compatibility but it's a no-op
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ProviderFactories.Add(loggerFactory =>
            new CertificateChainAssertionProvider(
                allowUntrusted,
                revocationMode,
                loggerFactory?.CreateLogger<CertificateChainAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ThrowIfNull(customRoots, nameof(customRoots));

        ProviderFactories.Add(loggerFactory =>
            new CertificateChainAssertionProvider(
                customRoots,
                trustUserRoots,
                revocationMode,
                loggerFactory?.CreateLogger<CertificateChainAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        ICertificateChainBuilder chainBuilder,
        bool allowUntrusted = false,
        X509Certificate2Collection? customRoots = null,
        bool trustUserRoots = true)
    {
        ThrowIfNull(chainBuilder, nameof(chainBuilder));

        ProviderFactories.Add(loggerFactory =>
            new CertificateChainAssertionProvider(
                chainBuilder,
                allowUntrusted,
                customRoots,
                trustUserRoots,
                loggerFactory?.CreateLogger<CertificateChainAssertionProvider>()));
        return this;
    }

    /// <inheritdoc />
    public IReadOnlyList<ISigningKeyAssertionProvider> Build()
    {
        return ProviderFactories
            .Select(factory => factory(LoggerFactoryField))
            .ToList();
    }

    private static void ThrowIfNull(object? value, string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName);
        }
    }
}