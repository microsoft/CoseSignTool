// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Results;

/// <summary>
/// Represents the result of a validation operation.
/// </summary>
public sealed class ValidationResult
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string MetadataReasonKey = "Reason";
    }

    /// <summary>
    /// Gets the outcome kind of the validation.
    /// </summary>
    public ValidationResultKind Kind { get; init; }

    /// <summary>
    /// Gets a value indicating whether the validation passed.
    /// </summary>
    public bool IsValid => Kind == ValidationResultKind.Success;

    /// <summary>
    /// Gets a value indicating whether the validation passed.
    /// </summary>
    public bool IsSuccess => Kind == ValidationResultKind.Success;

    /// <summary>
    /// Gets a value indicating whether the validation failed.
    /// </summary>
    public bool IsFailure => Kind == ValidationResultKind.Failure;

    /// <summary>
    /// Gets a value indicating whether the validator did not apply.
    /// </summary>
    public bool IsNotApplicable => Kind == ValidationResultKind.NotApplicable;

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
            Kind = ValidationResultKind.Success,
            ValidatorName = validatorName,
            Metadata = metadata != null
                ? new Dictionary<string, object>(metadata)
                : new Dictionary<string, object>()
        };
    }

    /// <summary>
    /// Creates a not-applicable validation result.
    /// </summary>
    /// <param name="validatorName">The name of the validator.</param>
    /// <param name="reason">Optional reason for not-applicable.</param>
    /// <returns>A not-applicable validation result.</returns>
    public static ValidationResult NotApplicable(string validatorName, string? reason = null)
    {
        var metadata = new Dictionary<string, object>();
        if (!string.IsNullOrWhiteSpace(reason))
        {
            metadata[ClassStrings.MetadataReasonKey] = reason!;
        }

        return new ValidationResult
        {
            Kind = ValidationResultKind.NotApplicable,
            ValidatorName = validatorName,
            Failures = Array.Empty<ValidationFailure>(),
            Metadata = metadata
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
            Kind = ValidationResultKind.Failure,
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
            Kind = ValidationResultKind.Failure,
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