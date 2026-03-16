// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use cose_sign1_validation_primitives::CoseSign1Message;
use std::io::{Read, Result as IoResult};
use std::sync::Arc;
use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;

struct FixedCoseKeyResolver {
    key: Arc<dyn CryptoVerifier>,
}

impl CoseKeyResolver for FixedCoseKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(self.key.clone())
    }
}

struct StreamingOnlyVerifier;

impl CryptoVerifier for StreamingOnlyVerifier {
    fn algorithm(&self) -> i64 { -7 }
    
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Err(CryptoError::VerificationFailed("verify(bytes) should not be called".to_string()))
    }
    
    fn supports_streaming(&self) -> bool {
        true
    }
    
    fn verify_init(&self, _signature: &[u8]) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingVerifyingContext { total: 0 }))
    }
}

struct StreamingVerifyingContext {
    total: u64,
}

impl crypto_primitives::VerifyingContext for StreamingVerifyingContext {
    fn update(&mut self, chunk: &[u8]) -> Result<(), CryptoError> {
        self.total += chunk.len() as u64;
        Ok(())
    }
    
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        // Not asserting exact size here (CBOR overhead varies), just that we read something.
        if self.total == 0 {
            return Err(CryptoError::VerificationFailed("expected non-empty stream".to_string()));
        }
        Ok(true)
    }
}

struct ZeroReader {
    remaining: u64,
    total: u64,
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

impl cose_sign1_primitives::sig_structure::SizedRead for ZeroReader {
    fn len(&self) -> IoResult<u64> {
        Ok(self.total)
    }
}

struct GeneratedPayloadProvider {
    len: u64,
}

impl StreamingPayload for GeneratedPayloadProvider {
    fn size(&self) -> u64 {
        self.len
    }

    fn open(&self) -> Result<Box<dyn cose_sign1_primitives::sig_structure::SizedRead + Send>, cose_sign1_primitives::error::PayloadError> {
        Ok(Box::new(ZeroReader {
            remaining: self.len,
            total: self.len,
        }))
    }
}

fn build_cose_sign1(detached: bool) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();

    enc.encode_array(4).unwrap();

    // protected header: bstr(CBOR map {1: -7})  (alg = ES256)
    let mut hdr_enc = p.encoder();
    hdr_enc.encode_map(1).unwrap();
    hdr_enc.encode_i64(1).unwrap();
    hdr_enc.encode_i64(-7).unwrap();
    let protected_bytes = hdr_enc.into_bytes();
    enc.encode_bstr(&protected_bytes).unwrap();

    // unprotected header: empty map
    enc.encode_map(0).unwrap();

    // payload: null for detached else bstr
    if detached {
        enc.encode_null().unwrap();
    } else {
        enc.encode_bstr(b"payload").unwrap();
    }

    // signature: dummy bytes
    enc.encode_bstr(b"sig").unwrap();

    enc.into_bytes()
}

#[test]
fn large_detached_payload_provider_uses_streaming_verify_path() {
    let cose = build_cose_sign1(true);

    let key: Arc<dyn CryptoVerifier> = Arc::new(StreamingOnlyVerifier);

    let payload_len = CoseSign1Validator::LARGE_STREAM_THRESHOLD + 10_000;

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("fixed_signing_key")
            .with_cose_key_resolver(Arc::new(FixedCoseKeyResolver { key })),
    )];

    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = Some(Payload::Streaming(Box::new(GeneratedPayloadProvider { len: payload_len })));
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert!(result.overall.is_valid());
}
