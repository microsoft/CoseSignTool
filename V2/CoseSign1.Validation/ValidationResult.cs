// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

/// <summary>
/// Represents the result of a validation operation.
/// </summary>
public sealed class ValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the validation passed.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// Gets the name of the validator that produced this result.
    /// </summary>
    public string ValidatorName { get; init; } = string.Empty;

    /// <summary>
    /// Gets the list of validation failures. Empty if IsValid is true.
    /// </summary>
    public IReadOnlyList<ValidationFailure> Failures { get; init; } = Array.Empty<ValidationFailure>();

    /// <summary>
    /// Gets optional metadata associated with the validation result.
    /// Can be used to pass additional information from validators.
    /// </summary>
    public IReadOnlyDictionary<string, object> Metadata { get; init; } = new Dictionary<string, object>();

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    /// <param name="validatorName">The name of the validator.</param>
    /// <param name="metadata">Optional metadata to include with the result.</param>
    /// <returns>A successful validation result.</returns>
    public static ValidationResult Success(string validatorName, IDictionary<string, object>? metadata = null)
    {
        return new ValidationResult
        {
            IsValid = true,
            ValidatorName = validatorName,
            Metadata = metadata != null
                ? new Dictionary<string, object>(metadata)
                : new Dictionary<string, object>()
        };
    }

    /// <summary>
    /// Creates a failed validation result with multiple failures.
    /// </summary>
    /// <param name="validatorName">The name of the validator.</param>
    /// <param name="failures">The validation failures.</param>
    /// <returns>A failed validation result.</returns>
    public static ValidationResult Failure(string validatorName, params ValidationFailure[] failures)
    {
        return new ValidationResult
        {
            IsValid = false,
            ValidatorName = validatorName,
            Failures = failures
        };
    }

    /// <summary>
    /// Creates a failed validation result with a single failure message.
    /// </summary>
    /// <param name="validatorName">The name of the validator.</param>
    /// <param name="message">The failure message.</param>
    /// <param name="errorCode">Optional error code.</param>
    /// <returns>A failed validation result.</returns>
    public static ValidationResult Failure(string validatorName, string message, string? errorCode = null)
    {
        return new ValidationResult
        {
            IsValid = false,
            ValidatorName = validatorName,
            Failures = new[]
            {
                new ValidationFailure
                {
                    Message = message,
                    ErrorCode = errorCode
                }
            }
        };
    }
}
