// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

using System.Diagnostics.CodeAnalysis;
using CoseSign1.Abstractions;
using CoseSign1.Validation.Interfaces;
using CoseSign1.Validation.Trust;

/// <summary>
/// Assertion indicating whether the X.509 certificate chain is trusted.
/// </summary>
public sealed record X509ChainTrustedAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionTrusted = "X.509 certificate chain is trusted";
        public const string DescriptionUntrustedFormat = "X.509 certificate chain is not trusted: {0}";
        public const string DefaultPolicyFailureReason = "X.509 certificate chain must be trusted";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509ChainTrustedAssertion>(
        a => a.IsTrusted,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the certificate chain is trusted.
    /// </summary>
    public bool IsTrusted { get; }

    /// <summary>
    /// Gets details about the chain trust status.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsTrusted
        ? ClassStrings.DescriptionTrusted
        : string.Format(ClassStrings.DescriptionUntrustedFormat, Details ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ChainTrustedAssertion"/> record.
    /// </summary>
    /// <param name="isTrusted">Whether the certificate chain is trusted.</param>
    /// <param name="details">Optional details about the trust status.</param>
    public X509ChainTrustedAssertion(bool isTrusted, string? details = null)
    {
        IsTrusted = isTrusted;
        Details = details;
    }
}

/// <summary>
/// Assertion indicating whether the certificate's common name matches an expected value.
/// </summary>
public sealed record X509CommonNameAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionMatchedFormat = "Certificate CN matches: {0}";
        public const string DescriptionNotMatchedFormat = "Certificate CN does not match expected value: {0}";
        public const string DefaultPolicyFailureReason = "Certificate common name must match";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509CommonNameAssertion>(
        a => a.Matches,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the common name matches.
    /// </summary>
    public bool Matches { get; }

    /// <summary>
    /// Gets the actual common name found.
    /// </summary>
    public string? ActualCommonName { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => Matches
        ? string.Format(ClassStrings.DescriptionMatchedFormat, ActualCommonName ?? ClassStrings.UnknownValue)
        : string.Format(ClassStrings.DescriptionNotMatchedFormat, ActualCommonName ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CommonNameAssertion"/> record.
    /// </summary>
    /// <param name="matches">Whether the common name matches.</param>
    /// <param name="actualCommonName">The actual common name found.</param>
    public X509CommonNameAssertion(bool matches, string? actualCommonName = null)
    {
        Matches = matches;
        ActualCommonName = actualCommonName;
    }
}

/// <summary>
/// Assertion indicating whether the certificate issuer matches an expected value.
/// </summary>
public sealed record X509IssuerAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionMatchedFormat = "Certificate issuer matches: {0}";
        public const string DescriptionNotMatchedFormat = "Certificate issuer does not match: {0}";
        public const string DefaultPolicyFailureReason = "Certificate issuer must match";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509IssuerAssertion>(
        a => a.Matches,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the issuer matches.
    /// </summary>
    public bool Matches { get; }

    /// <summary>
    /// Gets the actual issuer found.
    /// </summary>
    public string? ActualIssuer { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => Matches
        ? string.Format(ClassStrings.DescriptionMatchedFormat, ActualIssuer ?? ClassStrings.UnknownValue)
        : string.Format(ClassStrings.DescriptionNotMatchedFormat, ActualIssuer ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuerAssertion"/> record.
    /// </summary>
    /// <param name="matches">Whether the issuer matches.</param>
    /// <param name="actualIssuer">The actual issuer found.</param>
    public X509IssuerAssertion(bool matches, string? actualIssuer = null)
    {
        Matches = matches;
        ActualIssuer = actualIssuer;
    }
}

/// <summary>
/// Assertion indicating whether the certificate is within its validity period.
/// </summary>
public sealed record X509ValidityAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionValid = "Certificate is within validity period";
        public const string DescriptionExpired = "Certificate has expired";
        public const string DescriptionNotYetValid = "Certificate is not yet valid";
        public const string DefaultPolicyFailureReason = "Certificate must be within validity period";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509ValidityAssertion>(
        a => a.IsValid,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the certificate is within its validity period.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets a value indicating whether the certificate is expired (as opposed to not yet valid).
    /// </summary>
    public bool IsExpired { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsValid
        ? ClassStrings.DescriptionValid
        : (IsExpired ? ClassStrings.DescriptionExpired : ClassStrings.DescriptionNotYetValid);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ValidityAssertion"/> record.
    /// </summary>
    /// <param name="isValid">Whether the certificate is valid.</param>
    /// <param name="isExpired">If invalid, whether it's expired (true) or not yet valid (false).</param>
    public X509ValidityAssertion(bool isValid, bool isExpired = false)
    {
        IsValid = isValid;
        IsExpired = isExpired;
    }
}

/// <summary>
/// Assertion indicating whether the certificate key usage is valid for signing.
/// </summary>
public sealed record X509KeyUsageAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionValid = "Certificate key usage is valid for signing";
        public const string DescriptionInvalidFormat = "Certificate key usage is invalid: {0}";
        public const string DefaultPolicyFailureReason = "Certificate key usage must be valid for signing";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509KeyUsageAssertion>(
        a => a.IsValid,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the key usage is valid.
    /// </summary>
    public bool IsValid { get; }

    /// <summary>
    /// Gets details about the key usage validation.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsValid
        ? ClassStrings.DescriptionValid
        : string.Format(ClassStrings.DescriptionInvalidFormat, Details ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509KeyUsageAssertion"/> record.
    /// </summary>
    /// <param name="isValid">Whether the key usage is valid.</param>
    /// <param name="details">Optional details about the validation.</param>
    public X509KeyUsageAssertion(bool isValid, string? details = null)
    {
        IsValid = isValid;
        Details = details;
    }
}

/// <summary>
/// Assertion indicating whether a custom certificate predicate was satisfied.
/// </summary>
public sealed record X509PredicateAssertion : ISigningKeyAssertion
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string Domain = "x509";
        public const string DescriptionSatisfied = "Certificate predicate is satisfied";
        public const string DescriptionNotSatisfiedFormat = "Certificate predicate is not satisfied: {0}";
        public const string DefaultPolicyFailureReason = "Certificate predicate must be satisfied";
        public const string UnknownValue = "unknown";
    }

    private static readonly TrustPolicy DefaultPolicy = TrustPolicy.Require<X509PredicateAssertion>(
        a => a.IsSatisfied,
        ClassStrings.DefaultPolicyFailureReason);

    /// <summary>
    /// Gets a value indicating whether the predicate is satisfied.
    /// </summary>
    public bool IsSatisfied { get; }

    /// <summary>
    /// Gets details about the predicate evaluation.
    /// </summary>
    public string? Details { get; }

    /// <inheritdoc/>
    public string Domain => ClassStrings.Domain;

    /// <inheritdoc/>
    public string Description => IsSatisfied
        ? ClassStrings.DescriptionSatisfied
        : string.Format(ClassStrings.DescriptionNotSatisfiedFormat, Details ?? ClassStrings.UnknownValue);

    /// <inheritdoc/>
    public TrustPolicy DefaultTrustPolicy => DefaultPolicy;

    /// <inheritdoc/>
    public ISigningKey? SigningKey { get; init; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509PredicateAssertion"/> record.
    /// </summary>
    /// <param name="isSatisfied">Whether the predicate is satisfied.</param>
    /// <param name="details">Optional details about the evaluation.</param>
    public X509PredicateAssertion(bool isSatisfied, string? details = null)
    {
        IsSatisfied = isSatisfied;
        Details = details;
    }
}
