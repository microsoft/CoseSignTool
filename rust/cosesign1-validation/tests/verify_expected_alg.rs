use cosesign1_validation::{verify_cose_sign1, CoseAlgorithm, VerifyOptions};
use minicbor::Encoder;

#[test]
fn expected_alg_mismatch_fails() {
    // Minimal COSE_Sign1 that will fail later, but mismatch should be caught first.
    let protected = {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.map(1).unwrap();
        enc.i64(1).unwrap();
        enc.i64(-7).unwrap();
        buf
    };

    let mut cose = Vec::new();
    let mut enc = Encoder::new(&mut cose);
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"payload").unwrap();
    enc.bytes(b"sig").unwrap();

    let opts = VerifyOptions {
        expected_alg: Some(CoseAlgorithm::PS256),
        public_key_bytes: Some(vec![1, 2, 3]),
        ..Default::default()
    };

    let res = verify_cose_sign1("Signature", &cose, &opts);
    assert!(!res.is_valid);
    assert_eq!(res.failures[0].error_code.as_deref(), Some("ALG_MISMATCH"));
}
