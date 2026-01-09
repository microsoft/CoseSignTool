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
/// Validates a detached COSE signature using the certificate from x5t/x5chain headers.
/// For public use, prefer <see cref="CertificateSignatureValidator"/> which auto-detects embedded vs detached.
/// </summary>
internal sealed class CertificateDetachedSignatureValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField = new[] { ValidationStage.Signature };

    public IReadOnlyCollection<ValidationStage> Stages => StagesField;
    [ExcludeFromCodeCoverage]
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

        // Log message templates
        public static readonly string LogSignatureValidationStarted = "Starting detached signature validation with {PayloadBytes} byte payload";
        public static readonly string LogSignatureValidationSucceeded = "Detached signature validation succeeded in {ElapsedMs}ms";
        public static readonly string LogSignatureValidationFailed = "Detached signature validation failed: {Reason}";
    }

    private readonly ReadOnlyMemory<byte> Payload;
    private readonly bool AllowUnprotectedHeaders;
    private readonly ILogger<CertificateDetachedSignatureValidator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateDetachedSignatureValidator(
        byte[] payload,
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateDetachedSignatureValidator>? logger = null)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        Payload = new ReadOnlyMemory<byte>(payload);
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateDetachedSignatureValidator>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateDetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public CertificateDetachedSignatureValidator(
        ReadOnlyMemory<byte> payload,
        bool allowUnprotectedHeaders = false,
        ILogger<CertificateDetachedSignatureValidator>? logger = null)
    {
        Payload = payload;
        AllowUnprotectedHeaders = allowUnprotectedHeaders;
        Logger = logger ?? NullLogger<CertificateDetachedSignatureValidator>.Instance;
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

        if (input.Content != null)
        {
            Logger.LogWarning(LogEvents.SignatureValidationFailedEvent, ClassStrings.LogSignatureValidationFailed, ClassStrings.ErrorCodeUnexpectedEmbedded);
            return ValidationResult.Failure(
                ClassStrings.ValidatorName,
                ClassStrings.ErrorMessageUnexpectedEmbedded,
                ClassStrings.ErrorCodeUnexpectedEmbedded);
        }

        var stopwatch = Stopwatch.StartNew();
        Logger.LogDebug(LogEvents.SignatureValidationStartedEvent, ClassStrings.LogSignatureValidationStarted, Payload.Length);

        bool isValid = input.VerifySignature(Payload.ToArray(), AllowUnprotectedHeaders);

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