// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::chain_sort_order::X509ChainSortOrder;

#[test]
fn test_chain_sort_order_values() {
    let leaf_first = X509ChainSortOrder::LeafFirst;
    let root_first = X509ChainSortOrder::RootFirst;

    assert_eq!(leaf_first, X509ChainSortOrder::LeafFirst);
    assert_eq!(root_first, X509ChainSortOrder::RootFirst);
    assert_ne!(leaf_first, root_first);
}

#[test]
fn test_chain_sort_order_clone() {
    let original = X509ChainSortOrder::LeafFirst;
    let cloned = original;
    assert_eq!(original, cloned);
}

#[test]
fn test_chain_sort_order_debug() {
    let order = X509ChainSortOrder::LeafFirst;
    let debug_str = format!("{:?}", order);
    assert_eq!(debug_str, "LeafFirst");
}
