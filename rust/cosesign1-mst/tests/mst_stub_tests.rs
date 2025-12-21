use cosesign1_mst::{verify_transparent_statement, verify_transparent_statement_receipt, VerificationOptions};

#[test]
fn transparent_statement_is_currently_not_implemented() {
    let res = verify_transparent_statement("mst", b"", &VerificationOptions::default());
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("NOT_IMPLEMENTED"));
}

#[test]
fn transparent_statement_receipt_is_currently_not_implemented() {
    let res = verify_transparent_statement_receipt("mst", b"", b"");
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("NOT_IMPLEMENTED"));
}
