// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates an embedded COSE signature using the certificate from x5t/x5chain headers.
/// For public use, prefer <see cref="CertificateSignatureValidator"/> which auto-detects embedded vs detached.
/// </summary>
internal sealed class CertificateEmbeddedSignatureValidator : IValidator<CoseSign1Message>
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateEmbeddedSignatureValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeDetachedNotSupported = "DETACHED_CONTENT_NOT_SUPPORTED";
        public static readonly string ErrorCodeSignatureInvalid = "SIGNATURE_INVALID";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageDetachedNotSupported = "Message has no embedded content";
        public static readonly string ErrorMessageSignatureInvalid = "Signature verification failed";
    }

    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateEmbeddedSignatureValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateEmbeddedSignatureValidator(bool allowUnprotectedHeaders = false)
    {
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

        // This validator only works with embedded signatures (Content != null)
        // For detached signatures, use CertificateDetachedSignatureValidator
        if (input.Content == null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageDetachedNotSupported,
                ClassStrings.ErrorCodeDetachedNotSupported);
        }

        bool isValid = input.VerifySignature(payload: null, AllowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageSignatureInvalid,
                ClassStrings.ErrorCodeSignatureInvalid);
        }

        return ValidationResult.Success(ClassStrings.ValidatorName);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}