// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace CoseSign1.Abstractions.Transparency;

/// <summary>
/// Result of transparency proof verification.
/// </summary>
public sealed class TransparencyValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the transparency proof is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets validation errors if the proof is invalid.
    /// </summary>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Gets the transparency provider that performed the validation.
    /// </summary>
    public string? ProviderName { get; }

    /// <summary>
    /// Gets additional metadata from the transparency proof (e.g., log entry ID, timestamp).
    /// </summary>
    public IReadOnlyDictionary<string, object>? Metadata { get; }

    private TransparencyValidationResult(
        bool isValid,
        IReadOnlyList<string> errors,
        string? providerName = null,
        IReadOnlyDictionary<string, object>? metadata = null)
    {
        IsValid = isValid;
        Errors = errors ?? Array.Empty<string>();
        ProviderName = providerName;
        Metadata = metadata;
    }

    /// <summary>
    /// Creates a successful validation result.
    /// </summary>
    public static TransparencyValidationResult Success(
        string providerName,
        IReadOnlyDictionary<string, object>? metadata = null)
    {
        return new TransparencyValidationResult(
            isValid: true,
            errors: Array.Empty<string>(),
            providerName: providerName,
            metadata: metadata);
    }

    /// <summary>
    /// Creates a failed validation result.
    /// </summary>
    public static TransparencyValidationResult Failure(
        string providerName,
        params string[] errors)
    {
        return new TransparencyValidationResult(
            isValid: false,
            errors: errors,
            providerName: providerName);
    }

    /// <summary>
    /// Creates a failed validation result with multiple errors.
    /// </summary>
    public static TransparencyValidationResult Failure(
        string providerName,
        IEnumerable<string> errors)
    {
        return new TransparencyValidationResult(
            isValid: false,
            errors: new List<string>(errors),
            providerName: providerName);
    }
}
