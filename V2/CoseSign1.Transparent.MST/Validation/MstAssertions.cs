// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Assertion indicating whether an MST (Merkle Signature Tree) receipt is present on the message.
/// </summary>
/// <remarks>
/// <para>
/// This assertion is produced by MST validation providers when checking for the presence
/// of transparency receipts embedded in the COSE Sign1 message's unprotected headers.
/// </para>
/// <para>
/// The presence of a receipt alone does not indicate trust - it must be verified by
/// <see cref="MstReceiptTrustedAssertion"/> to establish cryptographic trust.
/// </para>
/// </remarks>
public sealed record MstReceiptPresentAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "mst";
        public const string DescriptionPresent = "MST receipt is present";
        public const string DescriptionAbsent = "MST receipt is not present";
        public const string DefaultPolicyFailureReason = "MST receipt must be present";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<MstReceiptPresentAssertion>(
        a => a.IsPresent,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether an MST receipt is present.
    /// </summary>
    public bool IsPresent { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsPresent ? ClassStrings.DescriptionPresent : ClassStrings.DescriptionAbsent;

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptPresentAssertion"/> record.
    /// </summary>
    /// <param name="isPresent">Whether an MST receipt is present.</param>
    public MstReceiptPresentAssertion(bool isPresent)
    {
        IsPresent = isPresent;
    }
}

/// <summary>
/// Assertion indicating whether an MST (Merkle Signature Tree) receipt has been cryptographically verified.
/// </summary>
/// <remarks>
/// <para>
/// This assertion is produced by MST validation providers after performing full receipt
/// proof validation against the configured transparency service's signing keys.
/// </para>
/// <para>
/// A trusted receipt indicates:
/// <list type="bullet">
/// <item><description>The receipt cryptographically binds the message to the transparency log</description></item>
/// <item><description>The receipt was signed by a key from an authorized issuer</description></item>
/// <item><description>The Merkle proof within the receipt is valid</description></item>
/// </list>
/// </para>
/// </remarks>
public sealed record MstReceiptTrustedAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "mst";
        public const string DescriptionTrustedFormat = "MST receipt is trusted";
        public const string DescriptionUntrustedFormat = "MST receipt is not trusted: {0}";
        public const string DefaultPolicyFailureReason = "MST receipt must be cryptographically verified";
        public const string UnknownDetails = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<MstReceiptTrustedAssertion>(
        a => a.IsTrusted,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the MST receipt was successfully verified.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets details about the verification result, particularly useful when verification failed.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsTrusted
        ? ClassStrings.DescriptionTrustedFormat
        : string.Format(ClassStrings.DescriptionUntrustedFormat, Details ?? ClassStrings.UnknownDetails);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="MstReceiptTrustedAssertion"/> record.
    /// </summary>
    /// <param name="isTrusted">Whether the MST receipt was successfully verified.</param>
    /// <param name="details">Optional details about the verification result.</param>
    public MstReceiptTrustedAssertion(bool isTrusted, string? details = null)
    {
        IsTrusted = isTrusted;
        Details = details;
    }
}
