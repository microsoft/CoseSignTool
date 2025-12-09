// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using System.Security.Cryptography.X509Certificates;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates a certificate using a custom predicate function.
/// </summary>
internal sealed class CertificatePredicateValidator : IValidator<CoseSign1Message>
{
    private readonly Func<X509Certificate2, bool> _predicate;
    private readonly string? _failureMessage;
    private readonly bool _allowUnprotectedHeaders;

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
        _predicate = predicate ?? throw new ArgumentNullException(nameof(predicate));
        _failureMessage = failureMessage;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
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

        if (!input.TryGetSigningCertificate(out var cert, _allowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                nameof(CertificatePredicateValidator),
                "Certificate not found in message headers",
                "CERTIFICATE_NOT_FOUND");
        }

        if (_predicate(cert))
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
            _failureMessage ?? "Certificate does not match the specified predicate",
            "CERTIFICATE_PREDICATE_FAILED");
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
