// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Validation;

/// <summary>
/// Validates a COSE signature using the certificate from x5t/x5chain headers.
/// Automatically handles both embedded and detached signatures.
/// </summary>
/// <remarks>
/// For embedded signatures, the payload is taken from the message content.
/// For detached signatures, the payload must be provided via the constructor.
/// </remarks>
public sealed class CertificateSignatureValidator : IValidator<CoseSign1Message>
{
    private readonly byte[]? DetachedPayload;
    private readonly bool AllowUnprotectedHeaders;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSignatureValidator"/> class
    /// for embedded signature validation.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateSignatureValidator(bool allowUnprotectedHeaders = false)
    {
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        DetachedPayload = null;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSignatureValidator"/> class
    /// for detached signature validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes to use for signature verification.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateSignatureValidator(byte[] detachedPayload, bool allowUnprotectedHeaders = false)
    {
        DetachedPayload = detachedPayload ?? throw new ArgumentNullException(nameof(detachedPayload));
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateSignatureValidator"/> class
    /// for detached signature validation.
    /// </summary>
    /// <param name="detachedPayload">The detached payload bytes to use for signature verification.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    public CertificateSignatureValidator(ReadOnlyMemory<byte> detachedPayload, bool allowUnprotectedHeaders = false)
    {
        DetachedPayload = detachedPayload.ToArray();
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
    }

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message? input)
    {
        if (input is null)
        {
            return ValidationResult.Failure(
                nameof(CertificateSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        // Determine if the message is embedded or detached
        bool isEmbedded = input.Content != null;

        if (isEmbedded)
        {
            // Embedded signature - use embedded validator
            var embeddedValidator = new CertificateEmbeddedSignatureValidator(AllowUnprotectedHeaders);
            return embeddedValidator.Validate(input);
        }
        else
        {
            // Detached signature - need payload
            if (DetachedPayload == null)
            {
                return ValidationResult.Failure(
                    nameof(CertificateSignatureValidator),
                    "Message has detached content but no payload was provided. " +
                    "Use a constructor overload that accepts a payload for detached signatures.",
                    "MISSING_DETACHED_PAYLOAD");
            }

            var detachedValidator = new CertificateDetachedSignatureValidator(DetachedPayload, AllowUnprotectedHeaders);
            return detachedValidator.Validate(input);
        }
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(CoseSign1Message? input, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Validate(input));
    }
}