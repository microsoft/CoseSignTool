use cosesign1_mst::{verify_transparent_statement_receipt, VerificationOptions};

#[test]
fn azure_sdk_vectors_exist_and_are_readable() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let receipt = std::fs::read(
        repo_root.join("native/cosesign1-mst/tests/testdata/azure-sdk-for-net/receipt.cose"),
    )
    .expect("receipt vector");

    let statement = std::fs::read(
        repo_root.join(
            "native/cosesign1-mst/tests/testdata/azure-sdk-for-net/transparent_statement.cose",
        ),
    )
    .expect("statement vector");

    assert!(!receipt.is_empty());
    assert!(!statement.is_empty());

    let _ = VerificationOptions::default();

    // The verifier is intentionally not implemented yet; this is just a smoke test to keep testdata wired.
    let res = verify_transparent_statement_receipt("MstReceipt", &receipt, &statement);
    assert!(!res.is_valid);
}
