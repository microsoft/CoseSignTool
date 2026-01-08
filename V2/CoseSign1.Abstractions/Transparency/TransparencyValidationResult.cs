// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Transparency;

/// <summary>
/// Result of transparency proof verification.
/// </summary>
public sealed class TransparencyValidationResult
{
    /// <summary>
    /// Gets a value indicating whether the transparency proof is valid.
    /// </summary>
    /// <value><see langword="true"/> if the transparency proof is valid; otherwise, <see langword="false"/>.</value>
    public bool IsValid { get; }

    /// <summary>
    /// Gets validation errors if the proof is invalid.
    /// </summary>
    /// <value>The validation errors, if any.</value>
    public IReadOnlyList<string> Errors { get; }

    /// <summary>
    /// Gets the transparency provider that performed the validation.
    /// </summary>
    /// <value>The transparency provider name, if available.</value>
    public string? ProviderName { get; }

    /// <summary>
    /// Gets additional metadata from the transparency proof (e.g., log entry ID, timestamp).
    /// </summary>
    /// <value>Additional metadata produced during transparency validation, if available.</value>
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
    /// <param name="providerName">The transparency provider that performed the validation.</param>
    /// <param name="metadata">Optional metadata returned by the provider.</param>
    /// <returns>A successful transparency validation result.</returns>
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
    /// <param name="providerName">The transparency provider that performed the validation.</param>
    /// <param name="errors">One or more validation errors describing why validation failed.</param>
    /// <returns>A failed transparency validation result.</returns>
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
    /// <param name="providerName">The transparency provider that performed the validation.</param>
    /// <param name="errors">A sequence of validation errors describing why validation failed.</param>
    /// <returns>A failed transparency validation result.</returns>
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