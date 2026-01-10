// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Assertion indicating whether the signing key is from Azure Key Vault.
/// </summary>
public sealed record AkvKeyDetectedAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "akv";
        public const string DescriptionDetected = "Signing key is from Azure Key Vault";
        public const string DescriptionNotDetected = "Signing key is not from Azure Key Vault";
        public const string DefaultPolicyFailureReason = "Signing key must be from Azure Key Vault";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<AkvKeyDetectedAssertion>(
        a => a.IsAkvKey,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the key is from Azure Key Vault.
    /// </summary>
    public bool IsAkvKey { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsAkvKey ? ClassStrings.DescriptionDetected : ClassStrings.DescriptionNotDetected;

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AkvKeyDetectedAssertion"/> record.
    /// </summary>
    /// <param name="isAkvKey">Whether the key is from Azure Key Vault.</param>
    public AkvKeyDetectedAssertion(bool isAkvKey)
    {
        IsAkvKey = isAkvKey;
    }
}

/// <summary>
/// Assertion indicating whether the Azure Key Vault key identifier matches allowed patterns.
/// </summary>
public sealed record AkvKidAllowedAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "akv";
        public const string DescriptionAllowed = "Azure Key Vault key identifier is allowed";
        public const string DescriptionNotAllowedFormat = "Azure Key Vault key identifier is not allowed: {0}";
        public const string DefaultPolicyFailureReason = "Azure Key Vault key identifier must match allowed patterns";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<AkvKidAllowedAssertion>(
        a => a.IsAllowed,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the key identifier is allowed.
    /// </summary>
    public bool IsAllowed { get; }

    /// <summary>
    /// Gets details about why the key identifier was allowed or denied.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsAllowed
        ? ClassStrings.DescriptionAllowed
        : string.Format(ClassStrings.DescriptionNotAllowedFormat, Details ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="AkvKidAllowedAssertion"/> record.
    /// </summary>
    /// <param name="isAllowed">Whether the key identifier is allowed.</param>
    /// <param name="details">Optional details about the validation.</param>
    public AkvKidAllowedAssertion(bool isAllowed, string? details = null)
    {
        IsAllowed = isAllowed;
        Details = details;
    }
}
