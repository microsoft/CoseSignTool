// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Validation;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Well-known trust-claim IDs emitted by MST trust providers.
/// </summary>
public static class MstTrustClaims
{
    /// <summary>
    /// Indicates whether an MST receipt is present on the message.
    /// </summary>
    public const string ReceiptPresent = ClassStrings.ReceiptPresent;

    /// <summary>
    /// Indicates whether the MST receipt(s) were verified successfully.
    /// </summary>
    public const string ReceiptTrusted = ClassStrings.ReceiptTrusted;

    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string ReceiptPresent = "mst.receipt.present";
        public const string ReceiptTrusted = "mst.receipt.trusted";
    }
}
