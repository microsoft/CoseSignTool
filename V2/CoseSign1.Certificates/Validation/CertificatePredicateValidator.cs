// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates a certificate using a custom predicate function.
/// </summary>
internal sealed class CertificatePredicateValidator : IValidator<CoseSign1Message>
{
    private readonly Func<X509Certificate2, bool> Predicate;
    private readonly string? FailureMessage;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificatePredicateValidator"/> class.
    /// </summary>
    /// <param name="predicate">The predicate function to validate the certificate.</param>
    /// <param name="failureMessage">The error message if validation fails.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificatePredicateValidator(
        Func<X509Certificate2, bool> predicate,
        string? failureMessage = null,
        bool allowUnprotectedHeaders = false)
    {
        Predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        FailureMessage = failureMessage;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificatePredicateValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (!input.TryGetSigningCertificate(out var cert, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificatePredicateValidator),
                "Certificate not found in message headers",
                "CERTIFICATE_NOT_FOUND");
        }

        if (Predicate(cert))
        {
            return ValidationResult.Success(
                nameof(CertificatePredicateValidator),
                new Dictionary<string, object>
                {
                    ["CertificateThumbprint"] = cert.Thumbprint
                });
        }

        return ValidationResult.Failure(
            nameof(CertificatePredicateValidator),
            FailureMessage ?? "Certificate does not match the specified predicate",
            "CERTIFICATE_PREDICATE_FAILED");
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}