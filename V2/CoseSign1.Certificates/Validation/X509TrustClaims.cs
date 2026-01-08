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
    }

    /// <summary>
    /// Indicates whether the signing certificate chain is strongly trusted.
    /// This should be false when trust was only accepted due to an allow-untrusted mode.
    /// </summary>
    public const string ChainTrusted = ClassStrings.ChainTrusted;
}
