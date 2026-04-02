// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Sort order for certificate chains — maps V2 X509ChainSortOrder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509ChainSortOrder {
    /// Leaf certificate first, root certificate last.
    LeafFirst,
    /// Root certificate first, leaf certificate last.
    RootFirst,
}


