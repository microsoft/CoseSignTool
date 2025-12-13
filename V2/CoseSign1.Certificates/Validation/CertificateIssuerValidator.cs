// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate was issued by an issuer with the expected common name.
/// </summary>
public sealed class CertificateIssuerValidator : IValidator<CoseSign1Message>
{
    private readonly string ExpectedIssuerName;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateIssuerValidator"/> class.
    /// </summary>
    /// <param name="expectedIssuerName">The expected issuer common name (CN) value.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateIssuerValidator(string expectedIssuerName, bool allowUnprotectedHeaders = false)
    {
        ExpectedIssuerName = expectedIssuerName ?? throw new ArgumentNullException(nameof(expectedIssuerName));
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateIssuerValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var signingCert, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificateIssuerValidator),
                "Could not extract signing certificate from message",
                "CERTIFICATE_NOT_FOUND");
        }

        // Extract issuer CN from certificate
        string? issuerCn = ExtractCommonName(signingCert.Issuer);

        if (string.IsNullOrEmpty(issuerCn))
        {
            return ValidationResult.Failure(
                nameof(CertificateIssuerValidator),
                "Certificate issuer does not contain a Common Name (CN)",
                "ISSUER_CN_NOT_FOUND");
        }

        // Compare issuer CN with expected value (case-insensitive)
        if (!string.Equals(issuerCn, ExpectedIssuerName, StringComparison.OrdinalIgnoreCase))
        {
            return ValidationResult.Failure(
                nameof(CertificateIssuerValidator),
                $"Certificate issuer CN '{issuerCn}' does not match expected '{ExpectedIssuerName}'",
                "ISSUER_CN_MISMATCH");
        }

        return ValidationResult.Success(nameof(CertificateIssuerValidator), new Dictionary<string, object>
        {
            ["IssuerCN"] = issuerCn!,
            ["CertificateThumbprint"] = signingCert.Thumbprint
        });
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }

    /// <summary>
    /// Extracts the Common Name (CN) from a distinguished name string.
    /// </summary>
    private static string? ExtractCommonName(string distinguishedName)
    {
        if (string.IsNullOrEmpty(distinguishedName))
        {
            return null;
        }

        // Parse the distinguished name to find CN
        var parts = distinguishedName.Split(',');
        foreach (var part in parts)
        {
            var trimmedPart = part.Trim();
            if (trimmedPart.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmedPart.Substring(3).Trim();
            }
        }

        return null;
    }
}
