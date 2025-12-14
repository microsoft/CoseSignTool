// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Validates a detached COSE signature using the certificate from x5t/x5chain headers.
/// For public use, prefer <see cref="CertificateSignatureValidator"/> which auto-detects embedded vs detached.
/// </summary>
internal sealed class CertificateDetachedSignatureValidator : IValidator<CoseSign1Message>
{
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateDetachedSignatureValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeUnexpectedEmbedded = "UNEXPECTED_EMBEDDED_CONTENT";
        public static readonly string ErrorCodeSignatureInvalid = "SIGNATURE_INVALID";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageUnexpectedEmbedded = "Message has embedded content but detached signature validator was used";
        public static readonly string ErrorMessageSignatureInvalid = "Detached signature verification failed";
    }

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
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        if (input.Content != null)
        {
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageUnexpectedEmbedded,
                ClassStrings.ErrorCodeUnexpectedEmbedded);
        }

        bool isValid = input.VerifySignature(Payload.ToArray(), AllowUnprotectedHeaders);

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