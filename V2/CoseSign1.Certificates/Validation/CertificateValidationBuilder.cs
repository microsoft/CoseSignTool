// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Certificates.Interfaces;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Implementation of the certificate validation builder.
/// Collects certificate validators and builds a composite validator.
/// </summary>
internal sealed class CertificateValidationBuilder : ICertificateValidationBuilder
{
    private readonly List<IValidator<CoseSign1Message>> ValidatorsField = new();
    private bool AllowUnprotectedHeadersField = false;

    public ICertificateValidationBuilder HasCommonName(string commonName)
    {
        ValidatorsField.Add(new CertificateCommonNameValidator(commonName, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder IsIssuedBy(string issuerName)
    {
        // TODO: Implement issuer validator
        throw new NotImplementedException("Issuer validation not yet implemented");
    }

    public ICertificateValidationBuilder NotExpired()
    {
        ValidatorsField.Add(new CertificateExpirationValidator(AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder NotExpired(DateTime asOf)
    {
        ValidatorsField.Add(new CertificateExpirationValidator(asOf, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder HasEnhancedKeyUsage(Oid eku)
    {
        ValidatorsField.Add(new CertificateKeyUsageValidator(eku, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder HasEnhancedKeyUsage(string ekuOid)
    {
        ValidatorsField.Add(new CertificateKeyUsageValidator(ekuOid, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder HasKeyUsage(X509KeyUsageFlags usage)
    {
        ValidatorsField.Add(new CertificateKeyUsageValidator(usage, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder Matches(Func<X509Certificate2, bool> predicate, string? failureMessage = null)
    {
        ValidatorsField.Add(new CertificatePredicateValidator(predicate, failureMessage, AllowUnprotectedHeadersField));
        return this;
    }

    public ICertificateValidationBuilder AllowUnprotectedHeaders(bool allow = true)
    {
        AllowUnprotectedHeadersField = allow;
        return this;
    }

    /// <summary>
    /// Builds a composite validator from all configured certificate validators.
    /// </summary>
    internal IValidator<CoseSign1Message> Build()
    {
        if (ValidatorsField.Count == 0)
        {
            throw new InvalidOperationException("No certificate validators configured");
        }

        if (ValidatorsField.Count == 1)
        {
            return ValidatorsField[0];
        }

        return new CompositeValidator(ValidatorsField);
    }
}