// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::io::Cursor;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct AcceptAllSigningKey;

impl SigningKey for AcceptAllSigningKey {
    fn key_type(&self) -> &'static str {
        "AcceptAllSigningKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct ExampleSigningKeyResolver;

impl SigningKeyResolver for ExampleSigningKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult::success(Arc::new(AcceptAllSigningKey))
    }
}

fn build_minimal_cose_sign1_with_detached_payload() -> Vec<u8> {
    let mut buf = vec![0u8; 1024];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7}) (alg = ES256)
    let mut hdr_buf = vec![0u8; 64];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());
    hdr_enc.map(1).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    (-7i64).encode(&mut hdr_enc).unwrap();
    let used_hdr = hdr_len - hdr_enc.0.len();
    let protected_bytes = &hdr_buf[..used_hdr];
    protected_bytes.encode(&mut enc).unwrap();

    // unprotected header: empty map
    enc.map(0).unwrap();

    // payload: nil (detached)
    Option::<&[u8]>::None.encode(&mut enc).unwrap();

    // signature: arbitrary bstr
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

fn main() {
    let payload: Arc<[u8]> = Arc::from(b"this is the detached payload".as_slice());

    // Provider opens a fresh reader each time.
    let provider = DetachedPayloadFnProvider::new({
        let payload = payload.clone();
        move || Ok(Box::new(Cursor::new(payload.to_vec())) as Box<dyn std::io::Read + Send>)
    })
    .with_len_hint(payload.len() as u64);

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("example_signing_key")
            .with_signing_key_resolver(Arc::new(ExampleSigningKeyResolver)),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(Arc::new(provider)));
    });

    let cose = build_minimal_cose_sign1_with_detached_payload();
    let result = validator
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .expect("validation failed");

    assert!(result.overall.is_valid());
    println!("OK: detached payload verified (example signing key accepted signature)");
}
