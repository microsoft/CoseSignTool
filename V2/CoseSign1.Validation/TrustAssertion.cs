// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Results;

/// <summary>
/// Represents a single boolean trust assertion emitted by a trust provider validator.
/// </summary>
public sealed class TrustAssertion
{
    /// <summary>
    /// Initializes a new instance of the <see cref="TrustAssertion"/> class.
    /// </summary>
    /// <param name="claimId">The claim identifier.</param>
    /// <param name="satisfied">Whether the claim is satisfied.</param>
    /// <param name="details">Optional human-readable details.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claimId"/> is null.</exception>
    public TrustAssertion(string claimId, bool satisfied, string? details = null)
    {
        ClaimId = claimId ?? throw new ArgumentNullException(nameof(claimId));
        Satisfied = satisfied;
        Details = details;
    }

    /// <summary>
    /// Gets the claim identifier.
    /// </summary>
    public string ClaimId { get; }

    /// <summary>
    /// Gets a value indicating whether the claim is satisfied.
    /// </summary>
    public bool Satisfied { get; }

    /// <summary>
    /// Gets optional details associated with the claim.
    /// </summary>
    public string? Details { get; }
}

/// <summary>
/// Standard metadata conventions for representing trust assertions.
/// </summary>
public static class TrustAssertionMetadata
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string AssertionsKey = "TrustAssertions";
    }

    /// <summary>
    /// Metadata key where validators store a list of <see cref="TrustAssertion"/>.
    /// </summary>
    public const string AssertionsKey = ClassStrings.AssertionsKey;

    /// <summary>
    /// Gets a list of trust assertions from a validation result's metadata, or an empty list when none are present.
    /// </summary>
    /// <param name="result">The validation result to read.</param>
    /// <returns>A list of trust assertions, or an empty list.</returns>
    public static IReadOnlyList<TrustAssertion> GetAssertionsOrEmpty(ValidationResult result)
    {
        if (result == null)
        {
            return Array.Empty<TrustAssertion>();
        }

        if (result.Metadata == null)
        {
            return Array.Empty<TrustAssertion>();
        }

        if (!result.Metadata.TryGetValue(AssertionsKey, out var value) || value is null)
        {
            return Array.Empty<TrustAssertion>();
        }

        if (value is IReadOnlyList<TrustAssertion> list)
        {
            return list;
        }

        if (value is IEnumerable<TrustAssertion> enumerable)
        {
            return enumerable.ToList();
        }

        return Array.Empty<TrustAssertion>();
    }
}
