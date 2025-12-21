use cosesign1_common::{encode_signature1_sig_structure, parse_cose_sign1, ParsedCoseSign1};

#[test]
fn parse_rejects_empty_input() {
    let err = parse_cose_sign1(&[]).unwrap_err();
    assert!(err.contains("empty"));
}

#[test]
fn parse_accepts_empty_protected_headers_bstr() {
    // Empty protected headers is a valid encoding for "empty map".
    let mut sign1 = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut sign1);
    enc.array(4).unwrap();
    enc.bytes(&[]).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"p").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();

    let parsed = parse_cose_sign1(&sign1).unwrap();
    assert!(parsed.protected_headers.map().is_empty());
}

#[test]
fn signature1_sig_structure_view_exposes_expected_fields() {
    let mut msg = ParsedCoseSign1::default();
    msg.payload = Some(b"payload".to_vec());

    let view = msg.signature1_sig_structure_view();
    assert_eq!(view.context, cosesign1_common::cose_sign1::SIG_STRUCTURE_CONTEXT_SIGNATURE1);
    assert_eq!(view.external_aad, b"");
    assert_eq!(view.payload, Some(b"payload".as_slice()));
}

#[test]
fn encode_sig_structure_requires_external_payload_for_detached() {
    // Minimal COSE_Sign1 with detached payload (null) and alg header.
    let protected = vec![0xa1, 0x01, 0x26]; // {1: -7}

    let mut sign1 = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut sign1);
    enc.tag(minicbor::data::Tag::new(cosesign1_common::cose_sign1::COSE_SIGN1_TAG))
        .unwrap();
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.null().unwrap();
    enc.bytes(&[0u8; 64]).unwrap();

    let parsed = parse_cose_sign1(&sign1).unwrap();
    let err = encode_signature1_sig_structure(&parsed, None).unwrap_err();
    assert!(err.contains("detached payload"));
}
