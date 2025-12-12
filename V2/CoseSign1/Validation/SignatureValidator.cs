// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Logging;
using CoseSign1.Validation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace CoseSign1.Validation;

/// <summary>
/// Validates the embedded COSE signature using the certificate from x5t/x5chain headers.
/// </summary>
public sealed class SignatureValidator : IValidator<CoseSign1Message>
{
    private readonly bool _allowUnprotectedHeaders;
    private readonly ILogger<SignatureValidator> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="SignatureValidator"/> class.
    /// </summary>
    /// <param name="allowUnprotectedHeaders">Whether to allow unprotected headers for certificate lookup.</param>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public SignatureValidator(bool allowUnprotectedHeaders = false, ILogger<SignatureValidator>? logger = null)
    {
        _allowUnprotectedHeaders = allowUnprotectedHeaders;
        _logger = logger ?? NullLogger<SignatureValidator>.Instance;
    }

    public ValidationResult Validate(CoseSign1Message input)
    {
        if (input == null)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Signature validation failed: input message is null");
            return ValidationResult.Failure(
                nameof(SignatureValidator),
                "Input message is null",
                "NULL_INPUT");
        }

        _logger.LogTrace(
            new EventId(LogEvents.ValidationStarted, nameof(LogEvents.ValidationStarted)),
            "Starting signature validation. AllowUnprotectedHeaders: {AllowUnprotectedHeaders}",
            _allowUnprotectedHeaders);

        bool isValid = input.VerifySignature(payload: null, _allowUnprotectedHeaders);

        if (!isValid)
        {
            _logger.LogTrace(
                new EventId(LogEvents.ValidationFailed, nameof(LogEvents.ValidationFailed)),
                "Signature verification failed");
            return ValidationResult.Failure(
                nameof(SignatureValidator),
                "Signature verification failed",
                "SIGNATURE_INVALID");
        }

        _logger.LogTrace(
            new EventId(LogEvents.ValidationCompleted, nameof(LogEvents.ValidationCompleted)),
            "Signature verification succeeded");
        return ValidationResult.Success(nameof(SignatureValidator));
    }

    public Task<ValidationResult> ValidateAsync(CoseSign1Message input, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input));
    }
}
