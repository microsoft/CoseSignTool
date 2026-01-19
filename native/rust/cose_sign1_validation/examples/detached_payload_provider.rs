// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;

fn main() {
    use std::io::Cursor;

    let testdata_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join("v1");

    let cose_bytes = std::fs::read(testdata_dir.join("UnitTestSignatureWithCRL.cose"))
        .expect("read cose testdata");
    let payload_bytes =
        std::fs::read(testdata_dir.join("UnitTestPayload.json")).expect("read payload testdata");

    let payload: std::sync::Arc<[u8]> = std::sync::Arc::from(payload_bytes.into_boxed_slice());

    // Provider opens a fresh reader each time.
    let provider = DetachedPayloadFnProvider::new({
        let payload = payload.clone();
        move || Ok(Box::new(Cursor::new(payload.to_vec())) as Box<dyn std::io::Read + Send>)
    })
    .with_len_hint(payload.len() as u64);

    let cert_pack = std::sync::Arc::new(
        cose_sign1_validation_certificates::pack::X509CertificateTrustPack::new(
            cose_sign1_validation_certificates::pack::CertificateTrustOptions {
                trust_embedded_chain_as_trusted: true,
                ..Default::default()
            },
        ),
    );
    let trust_packs: Vec<std::sync::Arc<dyn CoseSign1TrustPack>> = vec![cert_pack];

    let validator = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(std::sync::Arc::new(provider)));
        o.certificate_header_location = cose_sign1_validation_trust::CoseHeaderLocation::Any;
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = validator
        .validate_bytes(std::sync::Arc::from(cose_bytes.into_boxed_slice()))
        .expect("validation failed");

    assert!(
        result.signature.is_valid(),
        "signature invalid: {:#?}",
        result.signature
    );
    println!("OK: detached payload verified (provider)");
}
