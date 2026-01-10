// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Results;

/// <summary>
/// An immutable collection of strongly-typed signing key assertions with typed lookup helpers.
/// </summary>
public sealed class SigningKeyAssertionSet
{
    private readonly IReadOnlyList<ISigningKeyAssertion> AssertionsField;

    /// <summary>
    /// Gets an empty assertion set.
    /// </summary>
    public static SigningKeyAssertionSet Empty { get; } = new(Array.Empty<ISigningKeyAssertion>());

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningKeyAssertionSet"/> class.
    /// </summary>
    /// <param name="assertions">The assertions to include in the set.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="assertions"/> is null.</exception>
    public SigningKeyAssertionSet(IEnumerable<ISigningKeyAssertion> assertions)
    {
        AssertionsField = assertions?.ToList() ?? throw new ArgumentNullException(nameof(assertions));
    }

    /// <summary>
    /// Gets all assertions in this set.
    /// </summary>
    public IReadOnlyList<ISigningKeyAssertion> Assertions => AssertionsField;

    /// <summary>
    /// Gets the count of assertions.
    /// </summary>
    public int Count => AssertionsField.Count;

    /// <summary>
    /// Gets all assertions of a specific type.
    /// </summary>
    /// <typeparam name="T">The assertion type to filter by.</typeparam>
    /// <returns>All assertions of the specified type.</returns>
    public IEnumerable<T> OfType<T>() where T : ISigningKeyAssertion
    {
        return AssertionsField.OfType<T>();
    }

    /// <summary>
    /// Gets the single assertion of a specific type, or null if not found.
    /// </summary>
    /// <typeparam name="T">The assertion type to look for.</typeparam>
    /// <returns>The assertion if found and there's exactly one, null otherwise.</returns>
    /// <remarks>
    /// If multiple assertions of the type exist, returns the first one.
    /// Use <see cref="OfType{T}"/> if you need all matching assertions.
    /// </remarks>
    public T? Get<T>() where T : class, ISigningKeyAssertion
    {
        return AssertionsField.OfType<T>().FirstOrDefault();
    }

    /// <summary>
    /// Checks if any assertion of the specified type exists.
    /// </summary>
    /// <typeparam name="T">The assertion type to check for.</typeparam>
    /// <returns>True if at least one assertion of the type exists.</returns>
    public bool Has<T>() where T : ISigningKeyAssertion
    {
        return AssertionsField.OfType<T>().Any();
    }

    /// <summary>
    /// Gets all assertions for a specific domain.
    /// </summary>
    /// <param name="domain">The domain to filter by (e.g., "x509", "mst", "akv").</param>
    /// <returns>All assertions in the specified domain.</returns>
    public IEnumerable<ISigningKeyAssertion> ForDomain(string domain)
    {
        return AssertionsField.Where(a =>
            string.Equals(a.Domain, domain, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Combines this assertion set with another.
    /// </summary>
    /// <param name="other">The other assertion set to combine with.</param>
    /// <returns>A new assertion set containing all assertions from both sets.</returns>
    public SigningKeyAssertionSet Combine(SigningKeyAssertionSet other)
    {
        if (other == null || other.Count == 0)
        {
            return this;
        }

        if (Count == 0)
        {
            return other;
        }

        return new SigningKeyAssertionSet(AssertionsField.Concat(other.AssertionsField));
    }
}

/// <summary>
/// Standard metadata conventions for representing signing key assertions.
/// </summary>
public static class SigningKeyAssertionMetadata
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string AssertionsKey = "SigningKeyAssertions";
    }

    /// <summary>
    /// Metadata key where assertion providers store a list of <see cref="ISigningKeyAssertion"/>.
    /// </summary>
    public const string AssertionsKey = ClassStrings.AssertionsKey;

    /// <summary>
    /// Gets signing key assertions from a validation result's metadata, or an empty set when none are present.
    /// </summary>
    /// <param name="result">The validation result to read.</param>
    /// <returns>A SigningKeyAssertionSet containing all assertions found.</returns>
    public static SigningKeyAssertionSet GetAssertionSetOrEmpty(ValidationResult result)
    {
        if (result?.Metadata == null)
        {
            return SigningKeyAssertionSet.Empty;
        }

        if (!result.Metadata.TryGetValue(AssertionsKey, out var value) || value == null)
        {
            return SigningKeyAssertionSet.Empty;
        }

        if (value is IReadOnlyList<ISigningKeyAssertion> list)
        {
            return new SigningKeyAssertionSet(list);
        }

        if (value is IEnumerable<ISigningKeyAssertion> enumerable)
        {
            return new SigningKeyAssertionSet(enumerable);
        }

        return SigningKeyAssertionSet.Empty;
    }
}
