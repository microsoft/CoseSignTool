// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate chain ordering — defines leaf-first vs root-first sort order
//! for X.509 certificate chains in COSE headers.

/// Sort order for certificate chains — maps V2 X509ChainSortOrder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509ChainSortOrder {
    /// Leaf certificate first, root certificate last.
    LeafFirst,
    /// Root certificate first, leaf certificate last.
    RootFirst,
}
