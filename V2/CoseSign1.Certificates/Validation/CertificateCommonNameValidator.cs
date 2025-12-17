// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates that the signing certificate's subject common name matches the expected value.
/// </summary>
public sealed class CertificateCommonNameValidator : IValidator<CoseSign1Message>
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateCommonNameValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeCertNotFound = "CERTIFICATE_NOT_FOUND";
        public static readonly string ErrorCodeCnNotFound = "CN_NOT_FOUND";
        public static readonly string ErrorCodeCnMismatch = "CN_MISMATCH";

        // Error messages
        public static readonly string ErrorExpectedCommonNameNull = "Expected common name cannot be null or whitespace.";
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageCertNotFound = "Could not extract signing certificate from message";
        public static readonly string ErrorMessageCnNotFound = "Certificate does not have a common name";
        public static readonly string ErrorFormatCnMismatch = "Certificate common name '{0}' does not match expected '{1}'";

        // Metadata keys
        public static readonly string MetaKeyCommonName = "CommonName";
        public static readonly string MetaKeyCertThumbprint = "CertificateThumbprint";
    }

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
            throw new ArgumentException(ClassStrings.ErrorExpectedCommonNameNull, nameof(expectedCommonName));
        }

        ExpectedCommonName = expectedCommonName;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (!input.TryGetSigningCertificate(out var certificate, AllowUnprotectedHeaders))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCertNotFound,
                ClassStrings.ErrorCodeCertNotFound);
        }

        // Extract CN from subject name
        string? actualCN = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        if (string.IsNullOrEmpty(actualCN))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageCnNotFound,
                ClassStrings.ErrorCodeCnNotFound);
        }

        if (!string.Equals(actualCN, ExpectedCommonName, StringComparison.OrdinalIgnoreCase))
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                string.Format(ClassStrings.ErrorFormatCnMismatch, actualCN, ExpectedCommonName),
                ClassStrings.ErrorCodeCnMismatch);
        }

        var metadata = new Dictionary<string, object>
        {
            [ClassStrings.MetaKeyCommonName] = actualCN,
            [ClassStrings.MetaKeyCertThumbprint] = certificate.Thumbprint
        };

        return ValidationResult.Success(ClassStrings.ValidatorName, metadata);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}