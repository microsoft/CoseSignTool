// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate has the required key usage extensions.
/// </summary>
public sealed class CertificateKeyUsageValidator : IValidator<CoseSign1Message>
{
    private readonly X509KeyUsageFlags? _requiredKeyUsage;
    private readonly Oid? _requiredEku;
    private readonly bool _allowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate key usage flags.
    /// </summary>
    /// <param name="requiredKeyUsage">The required key usage flags.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateKeyUsageValidator(X509KeyUsageFlags requiredKeyUsage, bool allowUnprotectedHeaders = false)
    {
        _requiredKeyUsage = requiredKeyUsage;
        _requiredEku = null;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate enhanced key usage.
    /// </summary>
    /// <param name="requiredEku">The required enhanced key usage OID.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateKeyUsageValidator(Oid requiredEku, bool allowUnprotectedHeaders = false)
    {
        _requiredKeyUsage = null;
        _requiredEku = requiredEku ?? throw new ArgumentNullException(nameof(requiredEku));
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateKeyUsageValidator"/> class
    /// to validate enhanced key usage by OID value.
    /// </summary>
    /// <param name="requiredEkuOid">The required enhanced key usage OID value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateKeyUsageValidator(string requiredEkuOid, bool allowUnprotectedHeaders = false)
    {
        if (string.IsNullOrWhiteSpace(requiredEkuOid))
        {
            throw new ArgumentException("EKU OID cannot be null or whitespace.", nameof(requiredEkuOid));
        }

        _requiredKeyUsage = null;
        _requiredEku = new Oid(requiredEkuOid);
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var certificate, _allowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        if (_requiredKeyUsage.HasValue)
        {
            return ValidateKeyUsageFlags(certificate, _requiredKeyUsage.Value);
        }

        if (_requiredEku != null)
        {
            return ValidateEnhancedKeyUsage(certificate, _requiredEku);
        }

        return ValidationResult.Failure(
            nameof(CertificateKeyUsageValidator),
            "No key usage criteria specified",
            "NO_CRITERIA");
    }

    private ValidationResult ValidateKeyUsageFlags(X509Certificate2 certificate, X509KeyUsageFlags required)
    {
        var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();

        if (keyUsageExt == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                "Certificate does not have a key usage extension",
                "KEY_USAGE_NOT_FOUND");
        }

        if ((keyUsageExt.KeyUsages & required) != required)
        {
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                $"Certificate key usage '{keyUsageExt.KeyUsages}' does not include required '{required}'",
                "KEY_USAGE_MISMATCH");
        }

        return ValidationResult.Success(nameof(CertificateKeyUsageValidator), new Dictionary<string, object>
        {
            ["KeyUsage"] = keyUsageExt.KeyUsages.ToString(),
            ["CertificateThumbprint"] = certificate.Thumbprint
        });
    }

    private ValidationResult ValidateEnhancedKeyUsage(X509Certificate2 certificate, Oid requiredEku)
    {
        var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();

        if (ekuExt == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                "Certificate does not have an enhanced key usage extension",
                "EKU_NOT_FOUND");
        }

        bool found = ekuExt.EnhancedKeyUsages
            .Cast<Oid>()
            .Any(oid => oid.Value == requiredEku.Value);

        if (!found)
        {
            var ekuList = string.Join(", ", ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value ?? o.FriendlyName));
            return ValidationResult.Failure(
                nameof(CertificateKeyUsageValidator),
                $"Certificate does not have required EKU '{requiredEku.Value}'. Found: [{ekuList}]",
                "EKU_MISMATCH");
        }

        return ValidationResult.Success(nameof(CertificateKeyUsageValidator), new Dictionary<string, object>
        {
            ["EnhancedKeyUsage"] = requiredEku.Value ?? requiredEku.FriendlyName ?? "Unknown",
            ["CertificateThumbprint"] = certificate.Thumbprint
        });
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
