// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates a certificate using a custom predicate function.
/// </summary>
internal sealed class CertificatePredicateValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.KeyMaterialTrust };

    public IReadOnlyCollection<ValidationStage> Stages => StagesField;
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificatePredicateValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodePredicateFailed = "CERTIFICATE_PREDICATE_FAILED";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Certificate not found in message headers";
        public static readonly string ErrorMessagePredicateFailed = "Certificate does not match the specified predicate";

        // Metadata keys
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
    }

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

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!input.TryGetSigningCertificate(out var cert, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCertNotFound,
                ClassStrings.ErrorCodeCertNotFound);
        }

        if (Predicate(cert))
        {
            return ValidationResult.Success(
                ClassStrings.ValidatorName,
                new Dictionary<string, object>
                {
                    [ClassStrings.MetaKeyCertThumbprint] = cert.Thumbprint
                });
        }

        return ValidationResult.Failure(
            ClassStrings.ValidatorName,
            FailureMessage ?? ClassStrings.ErrorMessagePredicateFailed,
            ClassStrings.ErrorCodePredicateFailed);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}