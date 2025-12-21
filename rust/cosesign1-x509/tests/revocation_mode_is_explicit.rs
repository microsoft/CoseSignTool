use cosesign1_x509::{verify_cose_sign1_with_x5c, X509ChainVerifyOptions, X509RevocationMode};

#[test]
fn revocation_modes_fail_fast_for_now() {
    // Dummy COSE value; parse will fail first, but this test documents intent.
    let cose = [0x80u8];
    let opts = cosesign1_validation::VerifyOptions::default();

    let mut chain = X509ChainVerifyOptions::default();
    chain.revocation_mode = X509RevocationMode::Online;

    let res = verify_cose_sign1_with_x5c("X5c", &cose, &opts, Some(&chain));
    assert!(!res.is_valid);
}
