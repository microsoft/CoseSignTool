// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation;

namespace CoseSign1.Certificates.Validation;

/// <summary>
/// Convenience helpers for building X.509 trust policies.
/// </summary>
public static class X509TrustPolicies
{
    /// <summary>
    /// Requires a strongly trusted X.509 chain.
    /// </summary>
    /// <returns>A trust policy requiring a strongly trusted X.509 chain.</returns>
    public static TrustPolicy RequireTrustedChain()
    {
        return TrustPolicy.Claim(X509TrustClaims.ChainTrusted);
    }
}
