// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Validation;

/// <summary>
/// Validates a detached COSE signature with the provided payload.
/// </summary>
public sealed class DetachedSignatureValidator : IValidator<CoseSign1Message>
{
    private readonly ReadOnlyMemory<byte> _payload;
    private readonly bool _allowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="DetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public DetachedSignatureValidator(byte[] payload, bool allowUnprotectedHeaders = false)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        _payload = new ReadOnlyMemory<byte>(payload);
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public DetachedSignatureValidator(ReadOnlyMemory<byte> payload, bool allowUnprotectedHeaders = false)
    {
        _payload = payload;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (input.Content != null)
        {
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Message has embedded content but detached signature validator was used",
                "UNEXPECTED_EMBEDDED_CONTENT");
        }

        bool isValid = input.VerifySignature(_payload.ToArray(), _allowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Detached signature verification failed",
                "SIGNATURE_INVALID");
        }

        return ValidationResult.Success(nameof(DetachedSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
