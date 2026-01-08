// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Results;

/// <summary>
/// Represents a validation failure with detailed information.
/// </summary>
public sealed class ValidationFailure
{
    /// <summary>
    /// Gets the failure message.
    /// </summary>
    public string Message { get; init; } = string.Empty;

    /// <summary>
    /// Gets an optional error code for programmatic handling.
    /// </summary>
    public string? ErrorCode { get; init; }

    /// <summary>
    /// Gets the name of the property that failed validation, if applicable.
    /// </summary>
    public string? PropertyName { get; init; }

    /// <summary>
    /// Gets the value that was attempted but failed validation, if applicable.
    /// </summary>
    public object? AttemptedValue { get; init; }

    /// <summary>
    /// Gets the exception that caused the failure, if applicable.
    /// </summary>
    public Exception? Exception { get; init; }
}