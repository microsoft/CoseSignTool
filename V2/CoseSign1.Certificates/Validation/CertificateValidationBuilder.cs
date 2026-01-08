// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Implementation of the certificate validation builder.
/// Collects certificate validators and builds a composite validator.
/// </summary>
public sealed class CertificateValidationBuilder : ICertificateValidationBuilder
{
    private readonly List<Func<bool, IValidator>> ValidatorFactories = new();
    private bool AllowUnprotectedHeadersField = false;

    private readonly byte[]? DetachedPayload;

    /// <summary>
    /// Creates a builder for embedded signature validation.
    /// </summary>
    public CertificateValidationBuilder()
    {
        DetachedPayload = null;
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
    /// Creates a builder for detached signature validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes.</param>
    public CertificateValidationBuilder(ReadOnlyMemory<byte> detachedPayload)
    {
        DetachedPayload = detachedPayload.ToArray();
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasCommonName(string commonName)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateCommonNameValidator(commonName, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder IsIssuedBy(string issuerName)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateIssuerValidator(issuerName, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired()
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateExpirationValidator(allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder NotExpired(DateTime asOf)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateExpirationValidator(asOf, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateKeyUsageValidator(eku, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateKeyUsageValidator(ekuOid, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage)
    {
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateKeyUsageValidator(usage, allowUnprotectedHeaders));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null)
    {
        ThrowIfNull(predicate, nameof(predicate));

        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificatePredicateValidator(predicate, failureMessage, allowUnprotectedHeaders));
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
        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateChainValidator(allowUnprotectedHeaders, allowUntrusted, revocationMode));
        return this;
    }

    /// <inheritdoc />
    public ICertificateValidationBuilder ValidateChain(
        X509Certificate2Collection customRoots,
        bool trustUserRoots = true,
        X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        ThrowIfNull(customRoots, nameof(customRoots));

        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateChainValidator(customRoots, allowUnprotectedHeaders, trustUserRoots, revocationMode));
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

        ValidatorFactories.Add(allowUnprotectedHeaders =>
            new CertificateChainValidator(chainBuilder, allowUnprotectedHeaders, allowUntrusted, customRoots, trustUserRoots));
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
            ValidatorFactories.Select(factory => factory(AllowUnprotectedHeadersField)));

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