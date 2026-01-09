// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSignTool.Validation;

using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// A no-op signature validator that satisfies the builder's requirement for a signature-stage
/// validator but does not perform actual cryptographic verification. This is used as a fallback
/// when no verification provider supplies a signature validator (e.g., in tests with mock providers).
/// </summary>
/// <remarks>
/// This validator logs a warning when used, indicating that no actual signature verification
/// occurred. It should only be used in scenarios where signature validation is intentionally
/// skipped or when no provider is configured to handle the signature type.
/// </remarks>
public sealed partial class NoOpSignatureValidator : IValidator
{
    private static readonly IReadOnlyCollection<ValidationStage> StagesField =
        new[] { ValidationStage.Signature };

    private readonly ILogger<NoOpSignatureValidator> Logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="NoOpSignatureValidator"/> class.
    /// </summary>
    /// <param name="logger">Optional logger for diagnostic output.</param>
    public NoOpSignatureValidator(ILogger<NoOpSignatureValidator>? logger = null)
    {
        Logger = logger ?? NullLogger<NoOpSignatureValidator>.Instance;
    }

    /// <inheritdoc/>
    public IReadOnlyCollection<ValidationStage> Stages => StagesField;

    /// <inheritdoc/>
    public ValidationResult Validate(CoseSign1Message input, ValidationStage stage)
    {
        LogNoSignatureValidation();
        return ValidationResult.Success(nameof(NoOpSignatureValidator));
    }

    /// <inheritdoc/>
    public Task<ValidationResult> ValidateAsync(
        CoseSign1Message input,
        ValidationStage stage,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(Validate(input, stage));
    }

    [LoggerMessage(
        Level = LogLevel.Warning,
        EventId = 6001,
        Message = "No signature validator was provided by any verification provider. " +
                  "Cryptographic signature verification was skipped.")]
    private partial void LogNoSignatureValidation();
}
