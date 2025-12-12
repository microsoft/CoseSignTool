// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Implementation of the certificate validation builder.
/// Collects certificate validators and builds a composite validator.
/// </summary>
internal sealed class CertificateValidationBuilder : ICertificateValidationBuilder
{
    private readonly List<IValidator<CoseSign1Message>> _validators = new();
    private bool _allowUnprotectedHeaders = false;

    public ICertificateValidationBuilder HasCommonName(string commonName)
    {
        _validators.Add(new CertificateCommonNameValidator(commonName, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder IsIssuedBy(string issuerName)
    {
        // TODO: Implement issuer validator
        throw new NotImplementedException("Issuer validation not yet implemented");
    }

    public ICertificateValidationBuilder NotExpired()
    {
        _validators.Add(new CertificateExpirationValidator(_allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder NotExpired(DateTime asOf)
    {
        _validators.Add(new CertificateExpirationValidator(asOf, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku)
    {
        _validators.Add(new CertificateKeyUsageValidator(eku, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid)
    {
        _validators.Add(new CertificateKeyUsageValidator(ekuOid, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage)
    {
        _validators.Add(new CertificateKeyUsageValidator(usage, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null)
    {
        _validators.Add(new CertificatePredicateValidator(predicate, failureMessage, _allowUnprotectedHeaders));
        return this;
    }

    public ICertificateValidationBuilder AllowUnprotectedHeaders(bool allow = true)
    {
        _allowUnprotectedHeaders = allow;
        return this;
    }

    /// <summary>
    /// Builds a composite validator from all configured certificate validators.
    /// </summary>
    internal IValidator<CoseSign1Message> Build()
    {
        if (_validators.Count == 0)
        {
            throw new InvalidOperationException("No certificate validators configured");
        }

        if (_validators.Count == 1)
        {
            return _validators[0];
        }

        return new CompositeValidator(_validators);
    }
}