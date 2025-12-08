// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Certificates;

/// <summary>
/// The sort order when the certificate chain is returned.
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
