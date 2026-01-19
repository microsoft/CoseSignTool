// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::CoseSign1;
use cose_sign1_validation_azure_key_vault::facts::{
    AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_validation_azure_key_vault::pack::{
    AzureKeyVaultTrustOptions, AzureKeyVaultTrustPack, KID_HEADER_LABEL,
};
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactSet};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::CoseSign1ParsedMessage;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

fn build_cose_sign1_with_kid(kid: &str) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7, 4: bstr(kid)})
    let mut hdr_buf = vec![0u8; 512];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(2).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    (KID_HEADER_LABEL).encode(&mut hdr_enc).unwrap();
    kid.as_bytes().encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload: embedded bstr
    b"payload".as_slice().encode(&mut enc).unwrap();

    // signature: b"sig"
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn main() {
    let kid = "https://example.vault.azure.net/keys/mykey/123";
    let cose_bytes = build_cose_sign1_with_kid(kid);

    // Build parsed message for the trust engine context.
    let cose = CoseSign1::from_cbor(&cose_bytes).expect("cose decode failed");
    let parsed = CoseSign1ParsedMessage::from_parts(
        cose.protected_header,
        cose.unprotected_header.as_ref(),
        cose.payload,
        cose.signature,
    )
    .expect("parsed message failed");

    let pack = Arc::new(AzureKeyVaultTrustPack::new(AzureKeyVaultTrustOptions {
        allowed_kid_patterns: vec!["https://*.vault.azure.net/keys/*".to_string()],
        require_azure_key_vault_kid: true,
    }));

    let engine = TrustFactEngine::new(vec![pack]).with_cose_sign1_message(Arc::new(parsed));
    let subject = TrustSubject::message(b"seed");

    let detected = engine
        .get_fact_set::<AzureKeyVaultKidDetectedFact>(&subject)
        .expect("fact eval failed");
    let allowed = engine
        .get_fact_set::<AzureKeyVaultKidAllowedFact>(&subject)
        .expect("fact eval failed");

    println!("detected: {:?}", detected);
    println!("allowed: {:?}", allowed);

    // Make it obvious if example unexpectedly stops producing facts.
    match (detected, allowed) {
        (TrustFactSet::Available(_), TrustFactSet::Available(_)) => {}
        _ => std::process::exit(2),
    }
}
