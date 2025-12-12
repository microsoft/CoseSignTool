// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates a detached COSE signature using the certificate from x5t/x5chain headers.
/// </summary>
public sealed class CertificateDetachedSignatureValidator : IValidator<CoseSign1Message>
{
    private readonly ReadOnlyMemory<byte> Payload;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateDetachedSignatureValidator(byte[] payload, bool allowUnprotectedHeaders = false)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        Payload = new ReadOnlyMemory<byte>(payload);
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateDetachedSignatureValidator(ReadOnlyMemory<byte> payload, bool allowUnprotectedHeaders = false)
    {
        Payload = payload;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            return ValidationResult.Failure(
                nameof(CertificateDetachedSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (input.Content != null)
        {
            return ValidationResult.Failure(
                nameof(CertificateDetachedSignatureValidator),
                "Message has embedded content but detached signature validator was used",
                "UNEXPECTED_EMBEDDED_CONTENT");
        }

        bool isValid = input.VerifySignature(Payload.ToArray(), AllowUnprotectedHeaders);

        if (!isValid)
        {
            return ValidationResult.Failure(
                nameof(CertificateDetachedSignatureValidator),
                "Detached signature verification failed",
                "SIGNATURE_INVALID");
        }

        return ValidationResult.Success(nameof(CertificateDetachedSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}