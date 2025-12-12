// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate has not expired and is currently valid.
/// </summary>
public sealed class CertificateExpirationValidator : IValidator<CoseSign1Message>
{
    private readonly DateTime? _validationTime;
    private readonly bool _allowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate is valid at the current time.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateExpirationValidator(bool allowUnprotectedHeaders = false)
    {
        _validationTime = null;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExpirationValidator"/> class.
    /// Validates the certificate was valid at the specified time.
    /// </summary>
    /// <param name="validationTime">The time at which to validate the certificate.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateExpirationValidator(DateTime validationTime, bool allowUnprotectedHeaders = false)
    {
        _validationTime = validationTime;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateExpirationValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var certificate, _allowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateExpirationValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        DateTime checkTime = _validationTime ?? DateTime.UtcNow;

        if (checkTime < certificate.NotBefore)
        {
            return ValidationResult.Failure(
                nameof(CertificateExpirationValidator),
                $"Certificate is not yet valid. NotBefore: {certificate.NotBefore:u}, ValidationTime: {checkTime:u}",
                "CERTIFICATE_NOT_YET_VALID");
        }

        if (checkTime > certificate.NotAfter)
        {
            return ValidationResult.Failure(
                nameof(CertificateExpirationValidator),
                $"Certificate has expired. NotAfter: {certificate.NotAfter:u}, ValidationTime: {checkTime:u}",
                "CERTIFICATE_EXPIRED");
        }

        var metadata = new Dictionary<string, object>
        {
            ["NotBefore"] = certificate.NotBefore,
            ["NotAfter"] = certificate.NotAfter,
            ["ValidationTime"] = checkTime,
            ["CertificateThumbprint"] = certificate.Thumbprint
        };

        return ValidationResult.Success(nameof(CertificateExpirationValidator), metadata);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}