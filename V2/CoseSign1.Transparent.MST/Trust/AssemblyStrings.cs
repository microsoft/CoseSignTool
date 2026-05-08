// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Transparent.MST.Trust;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// String-literal pool for facts shipped from the MST transparent-statement trust pack.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class AssemblyStrings
{
    internal const string FactIdMstReceiptIssuerHost = "mst-receipt-issuer-host/v1";
    internal const string FactIdMstReceiptPresent = "mst-receipt-present/v1";
    internal const string FactIdMstReceiptTrusted = "mst-receipt-trusted/v1";
}
