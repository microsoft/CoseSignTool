// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using CoseSign1.Certificates.Extensions;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Validates an embedded COSE signature using the certificate from x5t/x5chain headers.
/// For public use, prefer <see cref="CertificateSignatureValidator"/> which auto-detects embedded vs detached.
/// </summary>
internal sealed class CertificateEmbeddedSignatureValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

    public IReadOnlyCollection<ValidationStage> Stages => StagesField;
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

        // Log message templates
        public static readonly string LogSignatureValidationStarted = "Starting embedded signature validation";
        public static readonly string LogSignatureValidationSucceeded = "Embedded signature validation succeeded in {ElapsedMs}ms";
        public static readonly string LogSignatureValidationFailed = "Embedded signature validation failed: {Reason}";
    }

    private readonly bool AllowUnprotectedHeaders;
    private readonly ILogger<CertificateEmbeddedSignatureValidator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateEmbeddedSignatureValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateEmbeddedSignatureValidator(
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateEmbeddedSignatureValidator>? logger = null)
    {
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateEmbeddedSignatureValidator>.Instance;
    }

    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        if (input == null)
        {
            Logger.LogWarning(LogEvents.SignatureValidationFailedEvent, ClassStrings.LogSignatureValidationFailed, ClassStrings.ErrorCodeNullInput);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageNullInput,
                ClassStrings.ErrorCodeNullInput);
        }

        // This validator only works with embedded signatures (Content != null)
        // For detached signatures, use CertificateDetachedSignatureValidator
        if (input.Content == null)
        {
            Logger.LogWarning(LogEvents.SignatureValidationFailedEvent, ClassStrings.LogSignatureValidationFailed, ClassStrings.ErrorCodeDetachedNotSupported);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageDetachedNotSupported,
                ClassStrings.ErrorCodeDetachedNotSupported);
        }

        var stopwatch = Stopwatch.StartNew();
        Logger.LogDebug(LogEvents.SignatureValidationStartedEvent, ClassStrings.LogSignatureValidationStarted);

        bool isValid = input.VerifySignature(payload: null, AllowUnprotectedHeaders);

        stopwatch.Stop();

        if (!isValid)
        {
            Logger.LogWarning(LogEvents.SignatureValidationFailedEvent, ClassStrings.LogSignatureValidationFailed, ClassStrings.ErrorCodeSignatureInvalid);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageSignatureInvalid,
                ClassStrings.ErrorCodeSignatureInvalid);
        }

        Logger.LogInformation(LogEvents.SignatureValidationSucceededEvent, ClassStrings.LogSignatureValidationSucceeded, stopwatch.ElapsedMilliseconds);
        return ValidationResult.Success(ClassStrings.ValidatorName);
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }
}