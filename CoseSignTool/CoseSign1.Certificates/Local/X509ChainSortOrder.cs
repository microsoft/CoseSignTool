// ---------------------------------------------------------------------------
// <copyright file="X509ChainSortOrder.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation. All rights reserved.
// </copyright>
// ---------------------------------------------------------------------------

namespace CoseSign1.Certificates.Local;

/// <summary>
/// The sort order when the chain is returned.
/// </summary>
public enum X509ChainSortOrder
{
    /// <summary>
    /// When specified, the root will be the first element.
    /// </summary>
    RootFirst,
    /// <summary>
    /// When specified, the leaf will be the first element.
    /// </summary>
    LeafFirst
}
