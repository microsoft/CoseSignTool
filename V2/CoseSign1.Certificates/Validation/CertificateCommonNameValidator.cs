// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate's subject common name matches the expected value.
/// </summary>
public sealed class CertificateCommonNameValidator : IValidator<CoseSign1Message>
{
    private readonly string ExpectedCommonName;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateCommonNameValidator"/> class.
    /// </summary>
    /// <param name="expectedCommonName">The expected common name (CN) value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateCommonNameValidator(string expectedCommonName, bool allowUnprotectedHeaders = false)
    {
        if (string.IsNullOrWhiteSpace(expectedCommonName))
        {
            throw new ArgumentException("Expected common name cannot be null or whitespace.", nameof(expectedCommonName));
        }

        ExpectedCommonName = expectedCommonName;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateCommonNameValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var certificate, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateCommonNameValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        // Extract CN from subject name
        string? actualCN = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        if (string.IsNullOrEmpty(actualCN))
        {
            return ValidationResult.Failure(
                nameof(CertificateCommonNameValidator),
                "Certificate does not have a common name",
                "CN_NOT_FOUND");
        }

        if (!string.Equals(actualCN, ExpectedCommonName, StringComparison.OrdinalIgnoreCase))
        {
            return ValidationResult.Failure(
                nameof(CertificateCommonNameValidator),
                $"Certificate common name '{actualCN}' does not match expected '{ExpectedCommonName}'",
                "CN_MISMATCH");
        }

        var metadata = new Dictionary<string, object>
        {
            ["CommonName"] = actualCN,
            ["CertificateThumbprint"] = certificate.Thumbprint
        };

        return ValidationResult.Success(nameof(CertificateCommonNameValidator), metadata);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}