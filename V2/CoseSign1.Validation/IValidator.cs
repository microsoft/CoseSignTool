// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Interface for validators that can validate an input and return a validation result.
/// </summary>
/// <typeparam name="T">The type of input to validate.</typeparam>
public interface IValidator<in T>
{
    /// <summary>
    /// Validates the input and returns a validation result.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <returns>The validation result.</returns>
    ValidationResult Validate(T input);

    /// <summary>
    /// Asynchronously validates the input and returns a validation result.
    /// </summary>
    /// <param name="input">The input to validate.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous validation operation.</returns>
    Task<ValidationResult> ValidateAsync(T input, CancellationToken cancellationToken = default);
}
