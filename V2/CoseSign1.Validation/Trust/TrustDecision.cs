// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust;

/// <summary>
/// Represents the outcome of a trust policy evaluation.
/// </summary>
/// <remarks>
/// <para>
/// A <see cref="TrustDecision"/> indicates whether a signing key is trusted based on the
/// evaluation of a <see cref="TrustPolicy"/> against a collection of <see cref="Interfaces.ISigningKeyAssertion"/>.
/// </para>
/// <para>
/// When trust is denied, the <see cref="Reasons"/> property contains human-readable explanations
/// of why the policy was not satisfied. These reasons should be actionable—they help users
/// understand what assertions were missing or insufficient.
/// </para>
/// </remarks>
public sealed class TrustDecision
{
    private static readonly TrustDecision TrustedInstance = new(true, Array.Empty<string>());

    /// <summary>
    /// Gets a value indicating whether the signing key is trusted.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets the reasons why trust was denied.
    /// </summary>
    /// <remarks>
    /// Empty when <see cref="IsTrusted"/> is true. Contains human-readable explanations when false.
    /// </remarks>
    public IReadOnlyList<string> Reasons { get; }

    private TrustDecision(bool isTrusted, IReadOnlyList<string> reasons)
    {
        IsTrusted = isTrusted;
        Reasons = reasons;
    }

    /// <summary>
    /// Creates a trusted decision.
    /// </summary>
    /// <returns>A decision indicating trust.</returns>
    public static TrustDecision Trusted() => TrustedInstance;

    /// <summary>
    /// Creates an untrusted decision with reasons.
    /// </summary>
    /// <param name="reasons">The reasons why trust was denied.</param>
    /// <returns>A decision indicating distrust with explanations.</returns>
    public static TrustDecision Denied(params string[] reasons)
    {
        return new TrustDecision(false, reasons ?? Array.Empty<string>());
    }

    /// <summary>
    /// Creates an untrusted decision with reasons.
    /// </summary>
    /// <param name="reasons">The reasons why trust was denied.</param>
    /// <returns>A decision indicating distrust with explanations.</returns>
    public static TrustDecision Denied(IReadOnlyList<string> reasons)
    {
        return new TrustDecision(false, reasons ?? Array.Empty<string>());
    }
}
