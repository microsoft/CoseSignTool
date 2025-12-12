// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Logging;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Validation;

/// <summary>
/// Validates a detached COSE signature with the provided payload.
/// </summary>
public sealed class DetachedSignatureValidator : IValidator<CoseSign1Message>
{
    private readonly ReadOnlyMemory<byte> _payload;
    private readonly bool _allowUnprotectedHeaders;
    private readonly ILogger<DetachedSignatureValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public DetachedSignatureValidator(byte[] payload, bool allowUnprotectedHeaders = false, ILogger<DetachedSignatureValidator>? logger = null)
    {
        if (payload == null)
        {
            throw new ArgumentNullException(nameof(payload));
        }

        _payload = new ReadOnlyMemory<byte>(payload);
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _logger = logger ?? NullLogger<DetachedSignatureValidator>.Instance;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DetachedSignatureValidator"/> class.
    /// </summary>
    /// <param name="payload">The detached payload to verify against.</param>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public DetachedSignatureValidator(ReadOnlyMemory<byte> payload, bool allowUnprotectedHeaders = false, ILogger<DetachedSignatureValidator>? logger = null)
    {
        _payload = payload;
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _logger = logger ?? NullLogger<DetachedSignatureValidator>.Instance;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Detached signature validation failed: input message is null");
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        if (input.Content != null)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Detached signature validation failed: message has embedded content");
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Message has embedded content but detached signature validator was used",
                "UNEXPECTED_EMBEDDED_CONTENT");
        }

        _logger.LogTrace(
            new EventId(LogEvents.ValidationStarted, nameof(LogEvents.ValidationStarted)),
            "Starting detached signature validation. PayloadSize: {PayloadSize}, AllowUnprotectedHeaders: {AllowUnprotectedHeaders}",
            _payload.Length,
            _allowUnprotectedHeaders);

        bool isValid = input.VerifySignature(_payload.ToArray(), _allowUnprotectedHeaders);

        if (!isValid)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Detached signature verification failed");
            return ValidationResult.Failure(
                nameof(DetachedSignatureValidator),
                "Detached signature verification failed",
                "SIGNATURE_INVALID");
        }

        _logger.LogTrace(
            new EventId(LogEvents.ValidationCompleted, nameof(LogEvents.ValidationCompleted)),
            "Detached signature verification succeeded");
        return ValidationResult.Success(nameof(DetachedSignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
