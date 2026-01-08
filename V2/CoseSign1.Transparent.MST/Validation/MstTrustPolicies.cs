// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Validation;

namespace CoseSign1.Transparent.MST.Validation;

/// <summary>
/// Convenience helpers for building MST-related trust policies.
/// </summary>
public static class MstTrustPolicies
{
    /// <summary>
    /// Creates a trust policy requiring an MST receipt to be present.
    /// </summary>
    /// <returns>A trust policy requiring receipt presence.</returns>
    public static TrustPolicy RequireReceiptPresent()
    {
        return TrustPolicy.Claim(MstTrustClaims.ReceiptPresent);
    }

    /// <summary>
    /// Creates a trust policy requiring an MST receipt to be trusted.
    /// </summary>
    /// <returns>A trust policy requiring receipt trust.</returns>
    public static TrustPolicy RequireReceiptTrusted()
    {
        return TrustPolicy.Claim(MstTrustClaims.ReceiptTrusted);
    }

    /// <summary>
    /// Creates a trust policy requiring an MST receipt to be present and trusted.
    /// </summary>
    /// <returns>A trust policy requiring receipt presence and trust.</returns>
    public static TrustPolicy RequireReceiptPresentAndTrusted()
    {
        return TrustPolicy.And(
            RequireReceiptPresent(),
            RequireReceiptTrusted());
    }

    /// <summary>
    /// If a receipt is present, it must validate.
    /// </summary>
    /// <returns>A trust policy requiring that a present receipt is trusted.</returns>
    public static TrustPolicy IfReceiptPresentThenTrusted()
    {
        return TrustPolicy.Implies(RequireReceiptPresent(), RequireReceiptTrusted());
    }
}
