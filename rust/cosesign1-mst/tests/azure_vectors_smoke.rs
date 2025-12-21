// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MST native test-vector wiring smoke test.
//!
//! This test checks that (when present) native MST vectors are reachable from
//! the Rust workspace. It intentionally skips in environments that do not
//! include the native vector files.

use cosesign1_mst::{verify_transparent_statement_receipt, VerificationOptions};

#[test]
fn azure_sdk_vectors_exist_and_are_readable() {
    // Compute repo root from the crate's manifest directory.
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let receipt_path = repo_root.join("native/cosesign1-mst/tests/testdata/azure-sdk-for-net/receipt.cose");
    let statement_path =
        repo_root.join("native/cosesign1-mst/tests/testdata/azure-sdk-for-net/transparent_statement.cose");

    if !receipt_path.exists() || !statement_path.exists() {
        // Some checkouts/tasks may not include the native test vectors.
        // Skipping keeps `cargo test --workspace` reliable across environments.
        return;
    }

    let receipt = std::fs::read(&receipt_path).expect("receipt vector");
    let statement = std::fs::read(&statement_path).expect("statement vector");

    assert!(!receipt.is_empty());
    assert!(!statement.is_empty());

    let _ = VerificationOptions::default();

    // The verifier is intentionally not implemented yet; this is just a smoke test
    // to keep testdata wired.
    let res = verify_transparent_statement_receipt("MstReceipt", &receipt, &statement);
    assert!(!res.is_valid);
}
