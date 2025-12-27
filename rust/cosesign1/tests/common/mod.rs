// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for `cosesign1` integration tests.
//!
//! The integration tests in `rust/cosesign1/tests/*.rs` focus on exercising
//! production code paths and error mapping. To keep each test file small and
//! aligned with the module under test, common CBOR encoding helpers, small
//! synthetic readers, and signing/certificate helpers live here.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use minicbor::data::Tag;
use p256::pkcs8::DecodePrivateKey as _;
use signature::Signer as _;
use std::io::SeekFrom;

/// A `Read + Seek` implementation that always fails.
///
/// Used to exercise IO error handling in reader-based parsing/verification APIs.
pub(crate) struct ErrorReadSeek {
    /// Error message returned by both `read` and `seek`.
    pub(crate) err: &'static str,
}

impl std::io::Read for ErrorReadSeek {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, self.err))
    }
}

impl std::io::Seek for ErrorReadSeek {
    fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
        Err(std::io::Error::new(std::io::ErrorKind::Other, self.err))
    }
}

/// A seekable reader with a virtual length.
///
/// The reader always returns EOF, but still supports seeking over a declared
/// length. This is used to hit CBOR bstr-length-prefix branches without
/// allocating large payloads.
pub(crate) struct VirtualLenEofReader {
    pub(crate) len: u64,
    pub(crate) pos: u64,
}

impl std::io::Read for VirtualLenEofReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl std::io::Seek for VirtualLenEofReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos_i128: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(off) => (self.len as i128).saturating_add(off as i128),
            SeekFrom::Current(off) => (self.pos as i128).saturating_add(off as i128),
        };

        if new_pos_i128 < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid seek",
            ));
        }

        self.pos = new_pos_i128 as u64;
        Ok(self.pos)
    }
}

/// Minimal set of CBOR key types used by these tests.
#[derive(Clone, Debug)]
pub(crate) enum TestCborKey {
    Int(i64),
    Text(&'static str),
}

impl TestCborKey {
    /// Encode this key to a CBOR encoder.
    pub(crate) fn encode(&self, enc: &mut minicbor::Encoder<Vec<u8>>) {
        match self {
            TestCborKey::Int(i) => {
                enc.i64(*i).unwrap();
            }
            TestCborKey::Text(s) => {
                enc.str(s).unwrap();
            }
        }
    }
}

/// Minimal set of CBOR value types used by these tests.
#[derive(Clone, Debug)]
pub(crate) enum TestCborValue {
    Int(i64),
    Bool(bool),
    Null,
    Bytes(Vec<u8>),
    Text(&'static str),
    Array(Vec<TestCborValue>),
    Map(Vec<(TestCborKey, TestCborValue)>),
}

impl TestCborValue {
    /// Encode this value to a CBOR encoder.
    pub(crate) fn encode(&self, enc: &mut minicbor::Encoder<Vec<u8>>) {
        match self {
            TestCborValue::Int(i) => {
                enc.i64(*i).unwrap();
            }
            TestCborValue::Bool(b) => {
                enc.bool(*b).unwrap();
            }
            TestCborValue::Null => {
                enc.null().unwrap();
            }
            TestCborValue::Bytes(b) => {
                enc.bytes(b).unwrap();
            }
            TestCborValue::Text(s) => {
                enc.str(s).unwrap();
            }
            TestCborValue::Array(items) => {
                enc.array(items.len() as u64).unwrap();
                for it in items {
                    it.encode(enc);
                }
            }
            TestCborValue::Map(entries) => {
                enc.map(entries.len() as u64).unwrap();
                for (k, v) in entries {
                    k.encode(enc);
                    v.encode(enc);
                }
            }
        }
    }
}

/// Encodes a protected header map as CBOR bytes.
pub(crate) fn encode_protected_header_bytes(entries: &[(i64, TestCborValue)]) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(entries.len() as u64).unwrap();
    for (k, v) in entries {
        enc.i64(*k).unwrap();
        v.encode(&mut enc);
    }
    enc.into_writer()
}

fn encode_unprotected_map(enc: &mut minicbor::Encoder<Vec<u8>>, entries: &[(TestCborKey, TestCborValue)]) {
    enc.map(entries.len() as u64).unwrap();
    for (k, v) in entries {
        k.encode(enc);
        v.encode(enc);
    }
}

/// Encodes a COSE_Sign1 message from components.
///
/// This is a focused test helper, not a general-purpose COSE encoder.
pub(crate) fn encode_cose_sign1(
    include_tag_18: bool,
    protected_bstr_contents: &[u8],
    unprotected_entries: &[(TestCborKey, TestCborValue)],
    payload: Option<&[u8]>,
    signature: &[u8],
) -> Vec<u8> {
    let mut enc = minicbor::Encoder::new(Vec::new());

    if include_tag_18 {
        enc.tag(Tag::new(18)).unwrap();
    }

    enc.array(4).unwrap();
    enc.bytes(protected_bstr_contents).unwrap();
    encode_unprotected_map(&mut enc, unprotected_entries);
    match payload {
        Some(p) => enc.bytes(p).unwrap(),
        None => enc.null().unwrap(),
    };
    enc.bytes(signature).unwrap();

    enc.into_writer()
}

/// Creates a self-signed P-256 certificate and matching signing key.
pub(crate) fn make_self_signed_p256_cert_and_key() -> (Vec<u8>, p256::ecdsa::SigningKey) {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    // rcgen generates a key pair; for generate_simple_self_signed this is P-256.
    let key_der = certified.key_pair.serialize_der();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der).unwrap();

    (cert_der, signing_key)
}

/// Extracts the SPKI bytes from a certificate DER.
pub(crate) fn extract_spki_from_cert_der(cert_der: &[u8]) -> Vec<u8> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    cert.tbs_certificate.subject_pki.raw.to_vec()
}

/// Builds an MST `JwkEcPublicKey` from a P-256 signing key.
pub(crate) fn make_p256_jwk(
    kid: &str,
    signing_key: &p256::ecdsa::SigningKey,
) -> cosesign1_mst::JwkEcPublicKey {
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let x = point.x().unwrap();
    let y = point.y().unwrap();

    cosesign1_mst::JwkEcPublicKey {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(x),
        y: URL_SAFE_NO_PAD.encode(y),
        kid: kid.to_string(),
    }
}

/// Signs a detached payload with ES256 and embeds the signature into COSE_Sign1.
pub(crate) fn sign_es256_detached_with_key(
    external_payload: &[u8],
    protected_entries: &[(i64, TestCborValue)],
    unprotected_entries: &[(TestCborKey, TestCborValue)],
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    sign_es256(
        false,
        None,
        Some(external_payload),
        protected_entries,
        unprotected_entries,
        signing_key,
    )
}

/// Signs a message with ES256 and embeds the signature into COSE_Sign1.
///
/// If `payload` is `None`, the message is detached and the `Sig_structure` is
/// constructed using `external_payload_for_sig_structure`.
pub(crate) fn sign_es256(
    include_tag_18: bool,
    payload: Option<&[u8]>,
    external_payload_for_sig_structure: Option<&[u8]>,
    protected_entries: &[(i64, TestCborValue)],
    unprotected_entries: &[(TestCborKey, TestCborValue)],
    signing_key: &p256::ecdsa::SigningKey,
) -> Vec<u8> {
    // Build placeholder COSE_Sign1 with empty signature.
    let protected_bytes = encode_protected_header_bytes(protected_entries);
    let placeholder = encode_cose_sign1(include_tag_18, &protected_bytes, unprotected_entries, payload, &[]);
    let parsed = cosesign1::parse_cose_sign1(&placeholder).unwrap();

    let sig_structure =
        cosesign1::encode_signature1_sig_structure(&parsed, external_payload_for_sig_structure).unwrap();
    let sig: p256::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    // Re-encode with real signature.
    encode_cose_sign1(
        include_tag_18,
        &protected_bytes,
        unprotected_entries,
        payload,
        AsRef::<[u8]>::as_ref(&sig_bytes),
    )
}

/// Constructs an unprotected header map that contains an `x5c` chain.
///
/// Extra header values are included to exercise `HeaderMap` decoding branches.
pub(crate) fn x5c_unprotected_header(cert_der: Vec<u8>) -> Vec<(TestCborKey, TestCborValue)> {
    vec![
        // x5c (label 33): array of bstr certs.
        (
            TestCborKey::Int(33),
            TestCborValue::Array(vec![TestCborValue::Bytes(cert_der)]),
        ),
        // Add a couple extra header value types to exercise header-map decoding.
        (TestCborKey::Text("example"), TestCborValue::Text("value")),
        (TestCborKey::Int(99), TestCborValue::Bool(true)),
        (
            TestCborKey::Int(100),
            TestCborValue::Map(vec![(TestCborKey::Text("nested"), TestCborValue::Int(1))]),
        ),
    ]
}
