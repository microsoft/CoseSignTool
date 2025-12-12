// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates the embedded COSE signature using the certificate from x5t/x5chain headers.
/// </summary>
public sealed class CertificateSignatureValidator : IValidator<CoseSign1Message>
{
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSignatureValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateSignatureValidator(bool allowUnprotectedHeaders = false)
    {
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        // This validator only works with embedded signatures (Content != null)
        // For detached signatures, use CertificateDetachedSignatureValidator
        if (input.Content == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateSignatureValidator),
                "Message has no embedded content. Use CertificateDetachedSignatureValidator for detached signatures.",
                "DETACHED_CONTENT_NOT_SUPPORTED");
        }

        bool isValid = input.VerifySignature(payload: null, AllowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                nameof(CertificateSignatureValidator),
                "Signature verification failed",
                "SIGNATURE_INVALID");
        }

        return ValidationResult.Success(nameof(CertificateSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}