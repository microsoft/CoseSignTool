// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Implementation of the certificate validation builder.
/// Collects certificate validators and builds a composite validator.
/// </summary>
public sealed class CertificateValidationBuilder : ICertificateValidationBuilder
{
    private readonly List<Func<bool, ILoggerFactory?, IValidator>> ValidatorFactories = new();
    private bool AllowUnprotectedHeadersField = false;
    private ILoggerFactory? LoggerFactoryField;

    private readonly byte[]? DetachedPayload;

    /// <summary>
    /// Creates a builder for embedded signature validation.
    /// </summary>
    public CertificateValidationBuilder()
    {
        DetachedPayload = null;
    }

    /// <summary>
    /// Creates a builder for embedded signature validation with logging.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for diagnostic logging.</param>
    public CertificateValidationBuilder(ILoggerFactory? loggerFactory)
    {
        DetachedPayload = null;
        LoggerFactoryField = loggerFactory;
    }

    /// <summary>
    /// Creates a builder for detached signature validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="detachedPayload"/> is null.</exception>
    public CertificateValidationBuilder(byte[] detachedPayload)
    {
        DetachedPayload = detachedPayload ?? throw new ArgumentNullException(nameof(detachedPayload));
    }

    /// <summary>
    /// Creates a builder for detached signature validation with logging.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <param name="loggerFactory">Optional logger factory for diagnostic logging.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="detachedPayload"/> is null.</exception>
    public CertificateValidationBuilder(byte[] detachedPayload, ILoggerFactory? loggerFactory)
    {
        DetachedPayload = detachedPayload ?? throw new ArgumentNullException(nameof(detachedPayload));
        LoggerFactoryField = loggerFactory;
    }

    /// <summary>
    /// Creates a builder for detached signature validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    public CertificateValidationBuilder(ReadOnlyMemory<byte> detachedPayload)
    {
        DetachedPayload = detachedPayload.ToArray();
    }

    /// <summary>
    /// Creates a builder for detached signature validation with logging.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    /// <param name="loggerFactory">Optional logger factory for diagnostic logging.</param>
    public CertificateValidationBuilder(ReadOnlyMemory<byte> detachedPayload, ILoggerFactory? loggerFactory)
    {
        DetachedPayload = detachedPayload.ToArray();
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
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateCommonNameValidator(
                commonName,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateCommonNameValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder IsIssuedBy(string issuerName)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateIssuerValidator(
                issuerName,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateIssuerValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired()
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateExpirationValidator(
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateExpirationValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired(DateTime asOf)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateExpirationValidator(
                asOf,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateExpirationValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateKeyUsageValidator(
                eku,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateKeyUsageValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateKeyUsageValidator(
                ekuOid,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateKeyUsageValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateKeyUsageValidator(
                usage,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificateKeyUsageValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null)
    {
        ThrowIfNull(predicate, nameof(predicate));

        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificatePredicateValidator(
                predicate,
                failureMessage,
                allowUnprotectedHeaders,
                loggerFactory?.CreateLogger<CertificatePredicateValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder AllowUnprotectedHeaders(bool allow = true)
    {
        AllowUnprotectedHeadersField = allow;
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        bool allowUntrusted = false,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateChainValidator(
                allowUnprotectedHeaders,
                allowUntrusted,
                revocationMode,
                loggerFactory?.CreateLogger<CertificateChainValidator>()));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ThrowIfNull(customRoots, nameof(customRoots));

        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateChainValidator(
                customRoots,
                allowUnprotectedHeaders,
                trustUserRoots,
                revocationMode,
                loggerFactory?.CreateLogger<CertificateChainValidator>()));
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

        ValidatorFactories.Add((allowUnprotectedHeaders, loggerFactory) =>
            new CertificateChainValidator(
                chainBuilder,
                allowUnprotectedHeaders,
                allowUntrusted,
                customRoots,
                trustUserRoots,
                loggerFactory?.CreateLogger<CertificateChainValidator>()));
        return this;
    }

    /// <inheritdoc />
    public IValidator Build()
    {
        var validators = new List<IValidator>
        {
            DetachedPayload is null
                ? new CertificateSignatureValidator(AllowUnprotectedHeadersField)
                : new CertificateSignatureValidator(DetachedPayload, AllowUnprotectedHeadersField)
        };

        validators.AddRange(
            ValidatorFactories.Select(factory => factory(AllowUnprotectedHeadersField, LoggerFactoryField)));

        if (validators.Count == 1)
        {
            return validators[0];
        }

        return new CompositeValidator(validators);
    }

    private static void ThrowIfNull(object? value, string paramName)
    {
        if (value is null)
        {
            throw new ArgumentNullException(paramName);
        }
    }
}