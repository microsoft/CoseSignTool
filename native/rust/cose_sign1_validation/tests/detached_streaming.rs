// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::{
    CoseSign1TrustPack, CoseSign1ValidationOptions, CoseSign1Validator, DetachedPayload,
    DetachedPayloadProvider, SigningKey, SigningKeyResolutionResult, SigningKeyResolver,
    SimpleTrustPack, TrustPlanBuilder, ValidationResultKind,
};
use std::io::{Read, Result as IoResult};
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

struct FixedSigningKeyResolver {
    key: Arc<dyn SigningKey>,
}

impl SigningKeyResolver for FixedSigningKeyResolver {
    fn resolve(
        &self,
        _message: &cose_sign1_validation::CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        SigningKeyResolutionResult::success(self.key.clone())
    }
}

struct StreamingOnlySigningKey;

impl SigningKey for StreamingOnlySigningKey {
    fn key_type(&self) -> &'static str {
        "StreamingOnly"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Err("verify(bytes) should not be called".to_string())
    }

    fn verify_reader(
        &self,
        _alg: i64,
        sig_structure: &mut dyn Read,
        _signature: &[u8],
    ) -> Result<bool, String> {
        // Consume the stream to prove the validator can feed it without building a Vec.
        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;
        loop {
            let n = sig_structure
                .read(&mut buf)
                .map_err(|e| format!("read_failed: {e}"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
        }

        // Not asserting exact size here (CBOR overhead varies), just that we read something.
        if total == 0 {
            return Err("expected non-empty stream".to_string());
        }

        Ok(true)
    }
}

struct ZeroReader {
    remaining: u64,
}

impl Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }

        let n = std::cmp::min(self.remaining as usize, buf.len());
        buf[..n].fill(0);
        self.remaining -= n as u64;
        Ok(n)
    }
}

struct GeneratedPayloadProvider {
    len: u64,
}

impl DetachedPayloadProvider for GeneratedPayloadProvider {
    fn open(&self) -> Result<Box<dyn Read + Send>, String> {
        Ok(Box::new(ZeroReader {
            remaining: self.len,
        }))
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.len)
    }
}

fn build_cose_sign1(detached: bool) -> Vec<u8> {
    let mut buf = vec![0u8; 2048];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
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

    // payload: null for detached else bstr
    if detached {
        let payload: Option<&[u8]> = None;
        payload.encode(&mut enc).unwrap();
    } else {
        b"payload".as_slice().encode(&mut enc).unwrap();
    }

    // signature: dummy bytes
    b"sig".as_slice().encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf
}

#[test]
fn large_detached_payload_provider_uses_streaming_verify_path() {
    let cose = build_cose_sign1(true);

    let key: Arc<dyn SigningKey> = Arc::new(StreamingOnlySigningKey);

    let payload_len = CoseSign1Validator::LARGE_STREAM_THRESHOLD + 10_000;
    let provider: Arc<dyn DetachedPayloadProvider> =
        Arc::new(GeneratedPayloadProvider { len: payload_len });

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("fixed_signing_key")
            .with_signing_key_resolver(Arc::new(FixedSigningKeyResolver { key })),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(DetachedPayload::Provider(provider));
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = validator
        .validate_bytes(Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert!(result.overall.is_valid());
}
