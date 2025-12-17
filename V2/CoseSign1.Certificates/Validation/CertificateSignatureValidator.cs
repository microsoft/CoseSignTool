// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.Cose;
using CoseSign1.Abstractions;
using CoseSign1.Certificates;
using CoseSign1.Validation;

/// <summary>
/// Validates a COSE signature using the certificate from x5t/x5chain headers.
/// Automatically handles both embedded and detached signatures.
/// </summary>
/// <remarks>
/// For embedded signatures, the payload is taken from the message content.
/// For detached signatures, the payload must be provided via the constructor.
/// </remarks>
public sealed class CertificateSignatureValidator : IValidator<CoseSign1Message>, IConditionalValidator<CoseSign1Message>, ISignatureValidator
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        // Validator name
        public static readonly string ValidatorName = nameof(CertificateSignatureValidator);

        // Error codes
        public static readonly string ErrorCodeNullInput = "NULL_INPUT";
        public static readonly string ErrorCodeMissingDetachedPayload = "MISSING_DETACHED_PAYLOAD";

        // Error messages
        public static readonly string ErrorMessageNullInput = "Input message is null";
        public static readonly string ErrorMessageMissingDetachedPayload =
            "Message has detached content but no payload was provided. " +
            "Use a constructor overload that accepts a payload for detached signatures.";
    }

    private readonly byte[]? DetachedPayload;
    private readonly bool AllowUnprotectedHeaders;

    public bool IsApplicable(CoseSign1Message input)
    {
        if (input is null)
        {
            return false;
        }

        // Certificate-based validation requires x5t + x5chain.
        bool hasX5t = input.ProtectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T)
            || (AllowUnprotectedHeaders && input.UnprotectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5T));
        bool hasX5chain = input.ProtectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain)
            || (AllowUnprotectedHeaders && input.UnprotectedHeaders.ContainsKey(CertificateHeaderContributor.HeaderLabels.X5Chain));

        return hasX5t && hasX5chain;
    }

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
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
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
                    ClassStrings.ValidatorName,
                    ClassStrings.ErrorMessageMissingDetachedPayload,
                    ClassStrings.ErrorCodeMissingDetachedPayload);
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