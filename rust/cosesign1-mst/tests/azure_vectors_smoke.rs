// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MST test-vector wiring smoke test.
//!
//! This test checks that (when present) MST vectors are reachable from the Rust
//! workspace. It intentionally skips in environments that do not include the
//! vector files.

use cosesign1_mst::{verify_transparent_statement_receipt, JwksDocument, VerificationOptions};

#[test]
fn azure_sdk_vectors_exist_and_are_readable() {
    // Compute repo root from the crate's manifest directory.
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let receipt_path = repo_root.join("testdata/mst/azure-sdk-for-net/receipt.cose");
    let statement_path = repo_root.join("testdata/mst/azure-sdk-for-net/transparent_statement.cose");
    let jwks_kid_mismatch_path = repo_root.join("testdata/mst/azure-sdk-for-net/jwks_kid_mismatch.json");

    if !receipt_path.exists() || !statement_path.exists() || !jwks_kid_mismatch_path.exists() {
        // Some checkouts/tasks may not include the native test vectors.
        // Skipping keeps `cargo test --workspace` reliable across environments.
        return;
    }

    let receipt = std::fs::read(&receipt_path).expect("receipt vector");
    let statement = std::fs::read(&statement_path).expect("statement vector");
    let jwks_bytes = std::fs::read(&jwks_kid_mismatch_path).expect("jwks vector");

    assert!(!receipt.is_empty());
    assert!(!statement.is_empty());

    let _ = VerificationOptions::default();

    // This vector intentionally uses a JWKS with a KID mismatch.
    let doc: JwksDocument = serde_json::from_slice(&jwks_bytes).expect("parse jwks");
    let jwk = doc.keys.first().expect("jwk");
    let res = verify_transparent_statement_receipt("MstReceipt", jwk, &receipt, &statement);
    assert!(!res.is_valid);
}
