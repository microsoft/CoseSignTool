// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation;

using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// A simple claim-based signing key assertion.
/// </summary>
/// <remarks>
/// <para>
/// This assertion type provides a simple claim-based model for trust decisions.
/// It's suitable for legacy validators and simple trust scenarios.
/// </para>
/// <para>
/// For more complex scenarios, consider creating strongly-typed assertions that
/// implement <see cref="ISigningKeyAssertion"/> directly.
/// </para>
/// </remarks>
public sealed record SigningKeyAssertion : ISigningKeyAssertion
{
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ClaimDomain = "claim";
        public const string DescriptionFormatWithDetails = "{0}={1} ({2})";
        public const string DescriptionFormatWithoutDetails = "{0}={1}";
        public const string TrustPolicyFailureFormat = "Claim '{0}' must be satisfied";
    }

    /// <summary>
    /// Gets the domain for claim-based assertions.
    /// </summary>
    public const string ClaimDomain = ClassStrings.ClaimDomain;

    /// <summary>
    /// Gets the claim identifier.
    /// </summary>
    public string ClaimId { get; }

    /// <summary>
    /// Gets the boolean value of the claim.
    /// </summary>
    public bool AsBool { get; }

    /// <summary>
    /// Gets additional details about the claim.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClaimDomain;

    /// <inheritdoc/>
    public string Description => string.IsNullOrEmpty(Details)
        ? string.Format(ClassStrings.DescriptionFormatWithoutDetails, ClaimId, AsBool)
        : string.Format(ClassStrings.DescriptionFormatWithDetails, ClaimId, AsBool, Details);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => TrustPolicy.Require<SigningKeyAssertion>(
        a => a.ClaimId == ClaimId && a.AsBool,
        string.Format(ClassStrings.TrustPolicyFailureFormat, ClaimId));

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="SigningKeyAssertion"/> record.
    /// </summary>
    /// <param name="claimId">The claim identifier.</param>
    /// <param name="value">The boolean value of the claim.</param>
    /// <param name="details">Optional additional details.</param>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="claimId"/> is null.</exception>
    public SigningKeyAssertion(string claimId, bool value, string? details = null)
    {
        ClaimId = claimId ?? throw new ArgumentNullException(nameof(claimId));
        AsBool = value;
        Details = details;
    }
}
