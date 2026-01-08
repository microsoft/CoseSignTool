// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Interfaces;

using CoseSign1.Validation.Results;

/// <summary>
/// Interface for validators that can validate a COSE Sign1 message and return a validation result.
/// </summary>
public interface IValidator
{
    /// <summary>
    /// Gets the validation stages this validator participates in.
    /// </summary>
    /// <remarks>
    /// A validator may participate in multiple stages. Orchestrators should select validators
    /// based on the current stage and pass that stage into <see cref="Validate"/> / <see cref="ValidateAsync"/>.
    /// </remarks>
    IReadOnlyCollection<ValidationStage> Stages { get; }

    /// <summary>
    /// Validates the input and returns a validation result.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <returns>The validation result.</returns>
    ValidationResult Validate(CoseSign1Message input, ValidationStage stage);

    /// <summary>
    /// Asynchronously validates the input and returns a validation result.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <param name="stage">The validation stage being executed.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous validation operation.</returns>
    Task<ValidationResult> ValidateAsync(CoseSign1Message input, ValidationStage stage, CancellationToken cancellationToken = default);
}