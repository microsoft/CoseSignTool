// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Well-known trust-claim IDs emitted by X.509 trust providers.
/// </summary>
public static class X509TrustClaims
{
    internal static class ClassStrings
    {
        public const string ChainTrusted = "x509.chain.trusted";
        public const string CommonNameMatches = "x509.cn.matches";
        public const string IssuerMatches = "x509.issuer.matches";
        public const string NotExpired = "x509.validity.notexpired";
        public const string KeyUsageValid = "x509.keyusage.valid";
        public const string PredicateSatisfied = "x509.predicate.satisfied";
    }

    /// <summary>
    /// Indicates whether the signing certificate chain is strongly trusted.
    /// This should be false when trust was only accepted due to an allow-untrusted mode.
    /// </summary>
    public const string ChainTrusted = ClassStrings.ChainTrusted;

    /// <summary>
    /// Indicates whether the signing certificate common name matches the expected value.
    /// </summary>
    public const string CommonNameMatches = ClassStrings.CommonNameMatches;

    /// <summary>
    /// Indicates whether the signing certificate issuer matches the expected value.
    /// </summary>
    public const string IssuerMatches = ClassStrings.IssuerMatches;

    /// <summary>
    /// Indicates whether the signing certificate is within its validity period (not expired).
    /// </summary>
    public const string NotExpired = ClassStrings.NotExpired;

    /// <summary>
    /// Indicates whether the signing certificate has the required key usage.
    /// </summary>
    public const string KeyUsageValid = ClassStrings.KeyUsageValid;

    /// <summary>
    /// Indicates whether the signing certificate satisfies a custom predicate.
    /// </summary>
    public const string PredicateSatisfied = ClassStrings.PredicateSatisfied;
}
