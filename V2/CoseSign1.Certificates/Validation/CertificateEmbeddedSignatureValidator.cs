// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates an embedded COSE signature using the certificate from x5t/x5chain headers.
/// For public use, prefer <see cref="CertificateSignatureValidator"/> which auto-detects embedded vs detached.
/// </summary>
internal sealed class CertificateEmbeddedSignatureValidator : IValidator<CoseSign1Message>
{
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
                nameof(CertificateEmbeddedSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        // This validator only works with embedded signatures (Content != null)
        // For detached signatures, use CertificateDetachedSignatureValidator
        if (input.Content == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateEmbeddedSignatureValidator),
                "Message has no embedded content",
                "DETACHED_CONTENT_NOT_SUPPORTED");
        }

        bool isValid = input.VerifySignature(payload: null, AllowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                nameof(CertificateEmbeddedSignatureValidator),
                "Signature verification failed",
                "SIGNATURE_INVALID");
        }

        return ValidationResult.Success(nameof(CertificateEmbeddedSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}