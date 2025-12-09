// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;

namespace CoseSign1.Validation.Signature;

/// <summary>
/// Validates the embedded COSE signature using the certificate from x5t/x5chain headers.
/// </summary>
public sealed class SignatureValidator : IValidator<CoseSign1Message>
{
    private readonly bool _allowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public SignatureValidator(bool allowUnprotectedHeaders = false)
    {
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(SignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        bool isValid = input.VerifySignature(payload: null, _allowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                nameof(SignatureValidator),
                "Signature verification failed",
                "SIGNATURE_INVALID");
        }

        return ValidationResult.Success(nameof(SignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
