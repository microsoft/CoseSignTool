// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CoseSign1Builder including streaming signing.

use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::builder::CoseSign1Builder;
use cose_sign1_primitives::headers::CoseHeaderMap;
use cose_sign1_primitives::message::CoseSign1Message;
use cose_sign1_primitives::payload::MemoryPayload;
use cose_sign1_primitives::StreamingPayload;
use crypto_primitives::CryptoSigner;
use std::sync::Arc;

/// Mock key that produces deterministic signatures.
struct MockKey;

impl CryptoSigner for MockKey {
    fn key_id(&self) -> Option<&[u8]> {
        None
    }
    fn key_type(&self) -> &str {
        "EC2"
    }
    fn algorithm(&self) -> i64 {
        -7
    }
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, crypto_primitives::CryptoError> {
        Ok(vec![0xaa, 0xbb, 0xcc])
    }
}

#[test]
fn test_builder_sign_basic() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign(&MockKey, b"hello");

    assert!(result.is_ok());
    let bytes = result.unwrap();

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload(), Some(b"hello".as_slice()));
    assert_eq!(msg.signature(), &[0xaa, 0xbb, 0xcc][..]);
}

#[test]
fn test_builder_sign_detached() {
    let _provider = EverParseCborProvider;

    let result = CoseSign1Builder::new()
        .detached(true)
        .sign(&MockKey, b"payload");

    assert!(result.is_ok());
    let bytes = result.unwrap();

    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
}

#[test]
fn test_builder_sign_untagged() {
    let _provider = EverParseCborProvider;

    let result = CoseSign1Builder::new()
        .tagged(false)
        .sign(&MockKey, b"payload");

    assert!(result.is_ok());
    let bytes = result.unwrap();

    // Should not start with tag 18 (0xd2)
    assert_ne!(bytes[0], 0xd2);
}

#[test]
fn test_builder_sign_with_unprotected_headers() {
    let _provider = EverParseCborProvider;
    let mut unprotected = CoseHeaderMap::new();
    unprotected.set_kid(b"key-1".to_vec());

    let result = CoseSign1Builder::new()
        .unprotected(unprotected)
        .sign(&MockKey, b"payload");

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.unprotected_headers().kid(), Some(b"key-1".as_slice()));
}

#[test]
fn test_builder_sign_with_external_aad() {
    let result = CoseSign1Builder::new()
        .external_aad(b"aad data".to_vec())
        .sign(&MockKey, b"payload");

    assert!(result.is_ok());
}

#[test]
fn test_builder_sign_empty_protected() {
    let _provider = EverParseCborProvider;

    let result = CoseSign1Builder::new().sign(&MockKey, b"payload");

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.protected_headers().is_empty());
}

#[test]
fn test_builder_sign_streaming_with_protected() {
    let _provider = EverParseCborProvider;
    let mut protected = CoseHeaderMap::new();
    protected.set_alg(-7);

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"streaming payload".to_vec()));

    let result = CoseSign1Builder::new()
        .protected(protected)
        .sign_streaming(&MockKey, payload);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert_eq!(msg.alg(), Some(-7));
    assert_eq!(msg.payload(), Some(b"streaming payload".as_slice()));
}

#[test]
fn test_builder_sign_streaming_detached() {
    let _provider = EverParseCborProvider;

    let payload: Arc<dyn StreamingPayload> =
        Arc::new(MemoryPayload::new(b"detached streaming".to_vec()));

    let result = CoseSign1Builder::new()
        .detached(true)
        .sign_streaming(&MockKey, payload);

    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
}

#[test]
fn test_builder_sign_streaming_empty_protected() {
    let payload: Arc<dyn StreamingPayload> = Arc::new(MemoryPayload::new(b"data".to_vec()));

    let result = CoseSign1Builder::new().sign_streaming(&MockKey, payload);

    assert!(result.is_ok());
}

#[test]
fn test_builder_sign_streaming_read_error_non_detached() {
    use cose_sign1_primitives::error::PayloadError;
    use cose_sign1_primitives::{SizedRead, SizedReader};
    use std::io::Read;

    struct FailOnSecondOpen {
        first_call: std::sync::Mutex<bool>,
        data: Vec<u8>,
    }

    impl StreamingPayload for FailOnSecondOpen {
        fn size(&self) -> u64 {
            self.data.len() as u64
        }
        fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
            let mut first = self.first_call.lock().unwrap();
            if *first {
                *first = false;
                Ok(Box::new(std::io::Cursor::new(self.data.clone())))
            } else {
                // Return a reader that fails
                struct FailReader;
                impl Read for FailReader {
                    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "second read failed",
                        ))
                    }
                }
                Ok(Box::new(SizedReader::new(FailReader, 0)))
            }
        }
    }

    let payload: Arc<dyn StreamingPayload> = Arc::new(FailOnSecondOpen {
        first_call: std::sync::Mutex::new(true),
        data: b"test data".to_vec(),
    });

    // Non-detached mode: the builder now reuses the buffered payload from the
    // first open() instead of re-reading, so this succeeds even though a
    // second open() would fail.
    let result = CoseSign1Builder::new().sign_streaming(&MockKey, payload);

    assert!(
        result.is_ok(),
        "should succeed without a second open(): {:?}",
        result.err()
    );
}

#[test]
fn test_builder_default() {
    let builder = CoseSign1Builder::default();
    // Default builder should produce a valid tagged message
    let result = builder.sign(&MockKey, b"test");
    assert!(result.is_ok());
}

#[test]
fn test_builder_clone() {
    let builder = CoseSign1Builder::new().tagged(false).detached(true);
    let cloned = builder.clone();
    let _provider = EverParseCborProvider;
    let result = cloned.sign(&MockKey, b"test");
    assert!(result.is_ok());
    let bytes = result.unwrap();
    let msg = CoseSign1Message::parse(&bytes).expect("parse");
    assert!(msg.is_detached());
}
