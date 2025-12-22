// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1::common::{
    encode_signature1_sig_structure,
    parse_cose_sign1,
    parse_cose_sign1_from_reader,
    parse_cose_sign1_from_reader_with_max_len,
};
use cosesign1::validation::{verify_cose_sign1, verify_sig_structure, CoseAlgorithm, VerifyOptions};
use cosesign1::{CoseSign1, VerificationSettings};
use cosesign1_abstractions::{MessageValidatorId, SigningKeyProviderId};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use minicbor::data::Tag;
use p256::pkcs8::DecodePrivateKey as _;
use rsa::pkcs8::EncodePublicKey as _;
use rand_core::OsRng;
use signature::Signer as _;
use std::io::SeekFrom;

struct ErrorReadSeek {
    err: &'static str,
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
/// Used to hit CBOR bstr-length-prefix branches without allocating huge payloads.
struct VirtualLenEofReader {
    len: u64,
    pos: u64,
}

impl std::io::Read for VirtualLenEofReader {
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        // Return EOF immediately.
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

        let new_pos = new_pos_i128 as u64;
        self.pos = new_pos;
        Ok(self.pos)
    }
}

fn encode_protected_header_bytes(entries: &[(i64, TestCborValue)]) -> Vec<u8> {
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

fn encode_cose_sign1(
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

#[test]
fn parse_rejects_empty_and_rejects_unexpected_tag_and_trailing_bytes() {
    assert!(parse_cose_sign1(&[]).unwrap_err().contains("empty input"));

    // Unexpected tag (not 18).
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.tag(Tag::new(19)).unwrap();
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let msg = enc.into_writer();
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unexpected CBOR tag"));

    // Trailing bytes after a valid COSE_Sign1.
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let mut msg_with_trailing = msg.clone();
    msg_with_trailing.push(0x00);
    let err = parse_cose_sign1(&msg_with_trailing).unwrap_err();
    assert!(err.contains("trailing bytes after COSE_Sign1"));
}

#[test]
fn parse_from_reader_variants_work_and_enforce_max_len() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);

    let parsed = parse_cose_sign1_from_reader(std::io::Cursor::new(msg.clone())).unwrap();
    assert_eq!(parsed.payload.as_deref(), Some(b"hello".as_slice()));

    let parsed = parse_cose_sign1_from_reader_with_max_len(std::io::Cursor::new(msg.clone()), msg.len()).unwrap();
    assert_eq!(parsed.payload.as_deref(), Some(b"hello".as_slice()));

    let err = parse_cose_sign1_from_reader_with_max_len(std::io::Cursor::new(msg), 1).unwrap_err();
    assert!(err.contains("exceeded max length"));
}

#[test]
fn parse_from_reader_reports_io_errors() {
    let err = parse_cose_sign1_from_reader(ErrorReadSeek { err: "boom" }).unwrap_err();
    assert!(err.contains("failed to read COSE_Sign1 bytes"));
}

#[test]
fn header_map_rejects_unsupported_key_and_value_types() {
    // Unsupported key type (bytes) inside protected header map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.bytes(b"k").unwrap();
    enc.i64(1).unwrap();
    let protected = enc.into_writer();

    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header key type"));

    // Unsupported value type (tag) inside protected header map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.tag(Tag::new(1)).unwrap();
    enc.null().unwrap();
    let protected = enc.into_writer();

    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("unsupported header value type"));
}

#[test]
fn verify_signature_with_payload_reader_exercises_hash_envelope_errors_and_mismatch() {
    use sha2::Digest as _;

    // Empty embedded digest is invalid.
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(-16)),
    ]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b""), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"abc".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));

    // Digest mismatch.
    let digest = sha2::Sha256::digest(b"expected");
    let msg = encode_cose_sign1(false, &protected, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"different".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));

    // Unprotected header must not contain payload-hash-alg.
    let unprotected = [(TestCborKey::Int(258), TestCborValue::Int(-16))];
    let msg = encode_cose_sign1(false, &protected, &unprotected, Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"expected".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));

    // Unsupported payload-hash-alg value.
    let protected_unsupported = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),
        (258, TestCborValue::Int(12345)),
    ]);
    let msg = encode_cose_sign1(false, &protected_unsupported, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"expected".to_vec());
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));

    // Payload read error.
    let msg = encode_cose_sign1(false, &protected, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = ErrorReadSeek { err: "read-fail" };
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_READ_ERROR")));
}

#[test]
fn streaming_detached_payload_reports_missing_public_key_when_no_provider_matches() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"payload".to_vec());

    let res = cose.verify_signature_with_payload_reader(&mut payload, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

#[test]
fn streaming_detached_payload_reports_seek_error() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    let mut payload = ErrorReadSeek { err: "seek-fail" };
    let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

#[test]
fn detached_streaming_hits_cbor_bstr_header_length_branches() {
    use cosesign1::validation::verify_parsed_cose_sign1_detached_payload_reader;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[]);
    let parsed = parse_cose_sign1(&msg).unwrap();

    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };

    for len in [0u64, 24u64, 256u64, 70_000u64, (u32::MAX as u64) + 1] {
        let mut payload = VirtualLenEofReader { len, pos: 0 };
        let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
        assert!(!res.is_valid);
        // Expect a key or signature-related failure (we supplied an invalid public key).
        assert!(res
            .failures
            .iter()
            .any(|f| matches!(f.error_code.as_deref(), Some("INVALID_PUBLIC_KEY") | Some("BAD_SIGNATURE") | Some("SIGSTRUCT_ERROR"))));
    }
}

#[test]
fn detached_streaming_rejects_when_payload_is_embedded() {
    use cosesign1::validation::verify_parsed_cose_sign1_detached_payload_reader;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"embedded"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&msg).unwrap();
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let mut payload = std::io::Cursor::new(b"payload".to_vec());
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

#[test]
fn parse_rejects_protected_header_map_with_trailing_bytes() {
    // Protected headers are a bstr containing a CBOR map.
    // Here we encode an empty map (0xA0), then add a trailing byte (0x00) to force
    // the "trailing bytes after header map" error.
    let protected_with_trailing = vec![0xA0, 0x00];
    let msg = encode_cose_sign1(
        false,
        &protected_with_trailing,
        &[],
        Some(b"hello"),
        &[0u8; 64],
    );

    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("trailing bytes after header map"));
}

#[test]
fn parse_reports_non_bstr_protected_headers_and_non_bstr_signature() {
    // Protected headers must be a bstr.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.null().unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let msg = enc.into_writer();
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read protected headers (bstr)"));

    // Signature must be a bstr.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.null().unwrap();
    let msg = enc.into_writer();
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read signature (bstr)"));
}

#[test]
fn parse_reports_protected_header_bytes_that_are_not_a_cbor_map() {
    // Protected header bstr contents must decode as a CBOR map.
    // 0x01 is CBOR unsigned integer 1, not a map.
    let protected_is_not_map = vec![0x01];
    let msg = encode_cose_sign1(false, &protected_is_not_map, &[], Some(b"hello"), &[0u8; 64]);
    let err = parse_cose_sign1(&msg).unwrap_err();
    assert!(err.contains("failed to read map"));
}

#[test]
fn verify_sig_structure_reports_bad_es384_and_es512_signature_bytes() {
    use p384::pkcs8::EncodePublicKey as _;

    let msg = b"sig_structure";

    // ES384: produce a valid signature, then corrupt it to hit the vk.verify() failure branch.
    let sk384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let vk384 = sk384.verifying_key();
    let spki384 = vk384.to_public_key_der().unwrap();
    let sig384: p384::ecdsa::Signature = sk384.sign(msg);
    let mut sig384_bytes = sig384.to_bytes();
    sig384_bytes[0] ^= 0x01;
    let err = verify_sig_structure(
        CoseAlgorithm::ES384,
        spki384.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&sig384_bytes),
    )
    .unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");

    // ES512: same, but we build SPKI DER from the verifying key.
    let sk521 = p521::ecdsa::SigningKey::random(&mut OsRng);
    let vk521 = p521::ecdsa::VerifyingKey::from(&sk521);
    let point = vk521.to_encoded_point(false);
    let pk521 = p521::PublicKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let spki521 = pk521.to_public_key_der().unwrap();

    let sig521: p521::ecdsa::Signature = sk521.sign(msg);
    let mut sig521_bytes = sig521.to_bytes();
    sig521_bytes[0] ^= 0x01;
    let err = verify_sig_structure(
        CoseAlgorithm::ES512,
        spki521.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&sig521_bytes),
    )
    .unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");
}

fn find_mldsa44_public_key_len_that_reaches_signature_parsing() -> usize {
    // We don't assume an exact key size for the `ml_dsa` crate version; instead,
    // probe a small set of known ML-DSA public key sizes and pick the one that
    // gets past public-key parsing (i.e., we reach signature parsing).
    let msg = b"mldsa";
    let bad_sig = [0u8; 1];

    // Common ML-DSA (Dilithium) public key sizes.
    for n in [1312usize, 1952, 2592, 1024, 2048, 4096] {
        let pk = vec![0u8; n];
        let err = verify_sig_structure(CoseAlgorithm::MLDsa44, &pk, msg, &bad_sig).unwrap_err();
        if err.0 == "BAD_SIGNATURE" {
            return n;
        }
    }

    panic!("could not find an ML-DSA-44 public key length that reaches signature parsing");
}

#[test]
fn verify_sig_structure_reports_mldsa_oid_mismatch_for_non_mldsa_cert() {
    // Provide a real X.509 certificate for a *non* ML-DSA key.
    // The ML-DSA verifier should parse it as a certificate, extract the SPKI OID,
    // and reject it as an OID mismatch.
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    let err = verify_sig_structure(CoseAlgorithm::MLDsa44, &cert_der, b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("unexpected public key algorithm OID"));
}

#[test]
fn verify_sig_structure_reports_bad_mldsa_public_key_bytes() {
    // Raw bytes that are not a cert/SPKI should be treated as raw ML-DSA public key bytes.
    // Using an obviously wrong length should hit the "bad ML-DSA public key bytes" mapping.
    let err = verify_sig_structure(CoseAlgorithm::MLDsa44, &[0u8; 1], b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("bad ML-DSA public key bytes"));
}

#[test]
fn verify_sig_structure_reports_bad_mldsa_signature_bytes() {
    // Find a public key length that passes key parsing, then supply an invalid-length signature.
    let pk_len = find_mldsa44_public_key_len_that_reaches_signature_parsing();
    let pk = vec![0u8; pk_len];

    let err = verify_sig_structure(CoseAlgorithm::MLDsa44, &pk, b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");
    assert!(err.1.contains("bad ML-DSA signature bytes"));
}

#[test]
fn verify_sig_structure_reports_mldsa_signature_verification_failed() {
    // Use deterministic key generation + signing from the ml-dsa crate, then verify against
    // a *different* message to ensure we hit the vk.verify() failure mapping.
    use ml_dsa::{KeyGen as _, MlDsa44};
    use ml_dsa::signature::Signer as _;

    let seed: ml_dsa::B32 = [42u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);

    let msg_signed = b"signed";
    let msg_verified = b"verified";
    let sig = kp.signing_key().sign(msg_signed);

    let public_key = kp.verifying_key().encode();
    let signature = sig.encode();

    let err = verify_sig_structure(
        CoseAlgorithm::MLDsa44,
        public_key.as_ref(),
        msg_verified,
        signature.as_ref(),
    )
    .unwrap_err();
    assert_eq!(err.0, "BAD_SIGNATURE");
    assert!(err.1.contains("signature verification failed"));
}

#[test]
fn cose_hash_envelope_supports_sha384_and_sha512() {
    use sha2::Digest as _;

    let preimage = b"hello-hash-envelope";

    // SHA-384
    let digest384 = sha2::Sha384::digest(preimage);
    let protected384 = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),    // ES256
        (258, TestCborValue::Int(-43)), // payload-hash-alg = SHA-384
    ]);
    let msg384 = encode_cose_sign1(
        false,
        &protected384,
        &[],
        Some(AsRef::<[u8]>::as_ref(&digest384)),
        &[0u8; 64],
    );
    let cose384 = CoseSign1::from_bytes(&msg384).unwrap();
    let res384 = cose384.verify_signature(Some(preimage), Some(b"bad-key"));
    assert!(!res384.is_valid);

    // SHA-512
    let digest512 = sha2::Sha512::digest(preimage);
    let protected512 = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),    // ES256
        (258, TestCborValue::Int(-44)), // payload-hash-alg = SHA-512
    ]);
    let msg512 = encode_cose_sign1(
        false,
        &protected512,
        &[],
        Some(AsRef::<[u8]>::as_ref(&digest512)),
        &[0u8; 64],
    );
    let cose512 = CoseSign1::from_bytes(&msg512).unwrap();
    let res512 = cose512.verify_signature(Some(preimage), Some(b"bad-key"));
    assert!(!res512.is_valid);
}

#[test]
fn cose_hash_envelope_without_payload_to_verify_skips_digest_check() {
    use sha2::Digest as _;

    let preimage = b"hello-hash-envelope";
    let digest = sha2::Sha256::digest(preimage);

    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),   // ES256
        (258, TestCborValue::Int(-16)), // payload-hash-alg = SHA-256
    ]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    // No payload_to_verify means we do not attempt to check the embedded digest.
    let res = cose.verify_signature(None, Some(b"bad-key"));
    assert!(!res.is_valid);
    assert!(!res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
}

#[test]
fn verify_signature_reports_missing_public_key_when_no_provider_matches() {
    // No public key override, and no provider-specific headers (e.g., x5c).
    // This should exercise the NoProviderMatched -> MISSING_PUBLIC_KEY path.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    let res = cose.verify_signature(None, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

#[test]
fn verify_signature_reports_provider_error_when_x5c_header_is_malformed() {
    // Add an x5c header (33) but make it invalid: array element is not bstr.
    // This should exercise the provider-error -> PUBLIC_KEY_PROVIDER_ERROR path.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let unprotected = [(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Null]),
    )];
    let msg = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    let res = cose.verify_signature(None, None);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("PUBLIC_KEY_PROVIDER_ERROR")));
}

#[test]
fn verify_pipeline_returns_early_when_signature_required_and_invalid() {
    use p256::pkcs8::EncodePublicKey as _;

    // Create a COSE_Sign1 with ES256 but an invalid signature.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    // Provide a real P-256 public key so signature verification gets far enough to fail.
    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let spki = vk.to_public_key_der().unwrap();

    let settings = VerificationSettings::default();
    let res = cose.verify(None, Some(spki.as_bytes()), &settings);

    assert!(!res.is_valid);
    assert_eq!(res.metadata.get("signature.verified").map(|s| s.as_str()), Some("true"));
}

#[test]
fn cose_hash_envelope_with_matching_digest_does_not_short_circuit() {
    // Construct a COSE Hash Envelope where the embedded payload is the SHA-256 digest
    // of a provided preimage payload. This should pass the hash match check and then
    // continue into signature verification (which we expect to fail due to a bogus key).
    use sha2::Digest as _;

    let preimage = b"hello-hash-envelope";
    let digest = sha2::Sha256::digest(preimage);

    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(-7)),   // ES256
        (258, TestCborValue::Int(-16)), // payload-hash-alg = SHA-256
    ]);

    let msg = encode_cose_sign1(false, &protected, &[], Some(AsRef::<[u8]>::as_ref(&digest)), &[0u8; 64]);
    let cose = CoseSign1::from_bytes(&msg).unwrap();

    let res = cose.verify_signature(Some(preimage), Some(b"definitely-not-a-public-key"));
    assert!(!res.is_valid);
    assert_ne!(
        res.failures
            .first()
            .and_then(|f| f.error_code.as_deref()),
        Some("PAYLOAD_MISMATCH")
    );
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some("override")
    );
}

#[derive(Clone, Debug)]
enum TestCborKey {
    Int(i64),
    Text(&'static str),
}

impl TestCborKey {
    fn encode(&self, enc: &mut minicbor::Encoder<Vec<u8>>) {
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

#[derive(Clone, Debug)]
enum TestCborValue {
    Int(i64),
    Bool(bool),
    Null,
    Bytes(Vec<u8>),
    Text(&'static str),
    Array(Vec<TestCborValue>),
    Map(Vec<(TestCborKey, TestCborValue)>),
}

impl TestCborValue {
    fn encode(&self, enc: &mut minicbor::Encoder<Vec<u8>>) {
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

fn make_self_signed_p256_cert_and_key() -> (Vec<u8>, p256::ecdsa::SigningKey) {
    let certified = rcgen::generate_simple_self_signed(["example.test".to_string()]).unwrap();
    let cert_der = certified.cert.der().to_vec();

    // rcgen generates a key pair; for generate_simple_self_signed this is P-256.
    let key_der = certified.key_pair.serialize_der();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_der).unwrap();

    (cert_der, signing_key)
}

fn extract_spki_from_cert_der(cert_der: &[u8]) -> Vec<u8> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
    cert.tbs_certificate.subject_pki.raw.to_vec()
}

fn make_p256_jwk(kid: &str, signing_key: &p256::ecdsa::SigningKey) -> cosesign1_mst::JwkEcPublicKey {
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

fn sign_es256_detached_with_key(
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

fn sign_es256(
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
    let parsed = parse_cose_sign1(&placeholder).unwrap();

    let sig_structure = encode_signature1_sig_structure(&parsed, external_payload_for_sig_structure).unwrap();

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

fn x5c_unprotected_header(cert_der: Vec<u8>) -> Vec<(TestCborKey, TestCborValue)> {
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

#[test]
fn verify_signature_succeeds_via_x5c_provider() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(true, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, None);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some(cosesign1_x509::X5C_PROVIDER_NAME)
    );
}

#[test]
fn verify_pipeline_with_required_signature_can_succeed_without_validators() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(true, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify(None, None, &VerificationSettings::default());
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn signature1_sig_structure_requires_external_payload_for_detached_messages() {
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = parse_cose_sign1(&msg).unwrap();

    // Detached payload (null) requires external payload bytes to construct Sig_structure.
    assert!(encode_signature1_sig_structure(&parsed, None).is_err());
}

#[test]
fn parsed_view_and_header_map_helpers_are_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);

    let msg = CoseSign1::from_bytes(&cose).unwrap();
    let view = msg.parsed.signature1_sig_structure_view();
    assert_eq!(view.context, cosesign1_abstractions::SIG_STRUCTURE_CONTEXT_SIGNATURE1);

    // Exercise header-map accessors and clear().
    assert_eq!(msg.parsed.protected_headers.get_i64(1), Some(-7));
    assert!(msg.parsed.unprotected_headers.get_array(33).is_some());
    let mut hm = msg.parsed.unprotected_headers.clone();
    hm.clear();
    assert!(hm.map().is_empty());
}

#[test]
fn verify_signature_succeeds_with_public_key_override() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(None, Some(cert_der.as_slice()));
    assert!(res.is_valid, "{res:?}");
    assert_eq!(
        res.metadata.get("signing_key.provider").map(|s| s.as_str()),
        Some("override")
    );
}

#[test]
fn verify_detached_payload_requires_external_payload() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![];

    let cose = sign_es256_detached_with_key(b"detached", &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    // Missing external payload should fail early.
    let res = msg.verify_signature(None, Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MISSING_PAYLOAD")));

    // Providing external payload allows signature verification to proceed (it will still fail
    // due to missing public key if we don't provide one).
    let res2 = msg.verify_signature(Some(b"detached"), Some(&[0u8; 1]));
    assert!(!res2.is_valid);
    assert!(res2.failures.iter().any(|f| f.error_code.as_deref() == Some("INVALID_PUBLIC_KEY")));
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![];

    let payload = b"this is a detached payload";
    let cose = sign_es256_detached_with_key(payload, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(cert_der.as_slice()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_es384() {
    use p384::pkcs8::EncodePublicKey as _;
    use signature::Signer as _;

    let signing_key = p384::ecdsa::SigningKey::random(&mut OsRng);
    let public_key_der = signing_key
        .verifying_key()
        .to_public_key_der()
        .unwrap();

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES384 as i64))]);
    let payload = b"es384-detached";

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig: p384::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    let cose = encode_cose_sign1(false, &protected, &[], None, AsRef::<[u8]>::as_ref(&sig_bytes));
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key_der.as_bytes()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_es512() {
    use p521::pkcs8::EncodePublicKey as _;
    use signature::Signer as _;

    let signing_key = p521::ecdsa::SigningKey::random(&mut OsRng);
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let point = verifying_key.to_encoded_point(false);
    let pk = p521::PublicKey::from_sec1_bytes(point.as_bytes()).unwrap();
    let public_key_der = pk.to_public_key_der().unwrap();

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES512 as i64))]);
    let payload = b"es512-detached";

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig: p521::ecdsa::Signature = signing_key.sign(&sig_structure);
    let sig_bytes = sig.to_bytes();

    let cose = encode_cose_sign1(false, &protected, &[], None, AsRef::<[u8]>::as_ref(&sig_bytes));
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key_der.as_bytes()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_rs256() {
    use rsa::pkcs1v15::SigningKey as RsaPkcs1SigningKey;
    use rsa::signature::RandomizedSigner as _;
    use rsa::signature::SignatureEncoding as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::RS256 as i64))]);
    let payload = b"rsa-detached";

    // Build Sig_structure bytes by parsing a temporary detached message.
    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let signer = RsaPkcs1SigningKey::<sha2::Sha256>::new(rsa_priv);
    let signature = signer.sign_with_rng(&mut rng, &sig_structure);
    let signature_bytes = signature.to_vec();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature_bytes.as_slice());
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(rsa_spki.as_bytes()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_ps256() {
    use rsa::pss::SigningKey as RsaPssSigningKey;
    use rsa::signature::RandomizedSigner as _;
    use rsa::signature::SignatureEncoding as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::PS256 as i64))]);
    let payload = b"pss-detached";

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let signer = RsaPssSigningKey::<sha2::Sha256>::new(rsa_priv);
    let signature = signer.sign_with_rng(&mut rng, &sig_structure);
    let signature_bytes = signature.to_vec();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature_bytes.as_slice());
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(rsa_spki.as_bytes()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_mldsa44() {
    use ml_dsa::{KeyGen as _, MlDsa44};
    use ml_dsa::signature::Signer as _;

    let seed: ml_dsa::B32 = [7u8; 32].into();
    let kp = MlDsa44::key_gen_internal(&seed);
    let public_key = kp.verifying_key().encode();

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::MLDsa44 as i64))]);
    let payload = b"mldsa-detached";

    let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
    let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
    let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
    let sig = kp.signing_key().sign(&sig_structure);
    let signature = sig.encode();

    let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut rdr = std::io::Cursor::new(payload);
    let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
    assert!(res.is_valid, "{res:?}");
}

#[test]
fn verify_detached_payload_with_streaming_reader_succeeds_mldsa65_and_87() {
    use ml_dsa::{KeyGen as _, MlDsa65, MlDsa87};
    use ml_dsa::signature::Signer as _;

    // ML-DSA-65
    {
        let seed: ml_dsa::B32 = [9u8; 32].into();
        let kp = MlDsa65::key_gen_internal(&seed);
        let public_key = kp.verifying_key().encode();

        let alg = CoseAlgorithm::MLDsa65;
        let payload = b"mldsa65-detached";
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

        let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
        let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
        let sig = kp.signing_key().sign(&sig_structure);
        let signature = sig.encode();

        let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
        let msg = CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(payload);
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
        assert!(res.is_valid, "{alg:?} failed: {res:?}");
    }

    // ML-DSA-87
    {
        let seed: ml_dsa::B32 = [10u8; 32].into();
        let kp = MlDsa87::key_gen_internal(&seed);
        let public_key = kp.verifying_key().encode();

        let alg = CoseAlgorithm::MLDsa87;
        let payload = b"mldsa87-detached";
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);

        let tmp = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let parsed_for_sig = parse_cose_sign1(&tmp).unwrap();
        let sig_structure = encode_signature1_sig_structure(&parsed_for_sig, Some(payload)).unwrap();
        let sig = kp.signing_key().sign(&sig_structure);
        let signature = sig.encode();

        let cose = encode_cose_sign1(false, &protected, &[], None, signature.as_ref());
        let msg = CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(payload);
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(public_key.as_ref()));
        assert!(res.is_valid, "{alg:?} failed: {res:?}");
    }
}

#[test]
fn detached_streaming_reports_expected_alg_mismatch_missing_alg_and_missing_public_key_bytes() {
    use cosesign1::validation::verify_parsed_cose_sign1_detached_payload_reader;

    // expected_alg mismatch
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES256 as i64))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: Some(CoseAlgorithm::ES384),
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("ALG_MISMATCH")));

    // missing alg header
    let protected = encode_protected_header_bytes(&[]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_OR_INVALID_ALG")));

    // missing public key bytes (this is the detached-streaming verifier's own branch)
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES256 as i64))]);
    let msg = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = parse_cose_sign1(&msg).unwrap();
    let mut payload = std::io::Cursor::new(b"p".to_vec());
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: None,
        expected_alg: None,
    };
    let res = verify_parsed_cose_sign1_detached_payload_reader("Signature", &parsed, &mut payload, &opts);
    assert!(!res.is_valid);
    assert!(res
        .failures
        .iter()
        .any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));
}

#[test]
fn verify_signature_with_payload_reader_hash_envelope_sha384_and_sha512_match_executes_signature_step() {
    use sha2::Digest as _;

    for (hash_alg_header, digest_bytes) in [
        (-43i64, sha2::Sha384::digest(b"preimage").to_vec()),
        (-44i64, sha2::Sha512::digest(b"preimage").to_vec()),
    ] {
        let protected = encode_protected_header_bytes(&[
            (1, TestCborValue::Int(-7)),
            (258, TestCborValue::Int(hash_alg_header)),
        ]);
        let msg = encode_cose_sign1(false, &protected, &[], Some(digest_bytes.as_slice()), &[0u8; 64]);
        let cose = CoseSign1::from_bytes(&msg).unwrap();

        let mut payload = std::io::Cursor::new(b"preimage".to_vec());
        let res = cose.verify_signature_with_payload_reader(&mut payload, Some(b"bad-key"));
        assert!(!res.is_valid);
        // Crucially: digest check passed, so we should not report PAYLOAD_MISMATCH.
        assert!(!res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
    }
}

#[test]
fn rsa_detached_streaming_maps_bad_signature_bytes_in_prehash_verifiers() {
    use rsa::pkcs8::EncodePublicKey as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    for alg in [CoseAlgorithm::RS256, CoseAlgorithm::PS256] {
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg as i64))]);
        let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 1]);
        let msg = CoseSign1::from_bytes(&cose).unwrap();

        let mut rdr = std::io::Cursor::new(b"".to_vec());
        let res = msg.verify_signature_with_payload_reader(&mut rdr, Some(rsa_spki.as_bytes()));
        assert!(!res.is_valid);
        assert!(res
            .failures
            .iter()
            .any(|f| f.error_code.as_deref() == Some("BAD_SIGNATURE")));
    }
}

#[test]
fn mldsa_verifier_exercises_spki_parsing_branch() {
    // Provide an SPKI DER (not a certificate) for a non-ML-DSA key.
    // This should hit the SubjectPublicKeyInfo::from_der branch.
    use rsa::pkcs8::EncodePublicKey as _;

    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();

    let err = verify_sig_structure(CoseAlgorithm::MLDsa44, rsa_spki.as_bytes(), b"msg", &[0u8; 1]).unwrap_err();
    assert_eq!(err.0, "INVALID_PUBLIC_KEY");
    assert!(err.1.contains("unexpected public key algorithm OID"));
}

#[test]
fn verify_pipeline_records_validator_not_run_when_it_returns_none() {
    // Configure the pipeline to skip signature verification, and enable MST.
    // With no MST options configured, MST should return Ok(None) and we should record ran=false.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator(cosesign1_mst::MST_VALIDATOR_ID);

    let res = msg.verify(None, None, &settings);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(res.metadata.get("signature.verified").map(|s| s.as_str()), Some("false"));
    assert_eq!(res.metadata.get("validator.mst.ran").map(|s| s.as_str()), Some("false"));
}

#[test]
fn cose_sign1_parse_error_paths_are_exercised() {
    // Empty input.
    assert!(parse_cose_sign1(&[]).is_err());

    // Wrong array length.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(3).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    let wrong_len = enc.into_writer();
    assert!(parse_cose_sign1(&wrong_len).is_err());

    // Unprotected headers not a map.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.array(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_unprotected = enc.into_writer();
    assert!(parse_cose_sign1(&wrong_unprotected).is_err());

    // Payload wrong type.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.i64(1).unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_payload = enc.into_writer();
    assert!(parse_cose_sign1(&wrong_payload).is_err());

    // Protected header map contains trailing bytes.
    let mut protected_with_trailing = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    protected_with_trailing.extend_from_slice(&[0x00]);
    let bad = encode_cose_sign1(false, &protected_with_trailing, &[], Some(b"hello"), &[0u8; 64]);
    assert!(parse_cose_sign1(&bad).is_err());

    // Protected header map uses an unsupported key type.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.bytes(b"not allowed").unwrap();
    enc.i64(1).unwrap();
    let protected_bad_key = enc.into_writer();
    let bad2 = encode_cose_sign1(false, &protected_bad_key, &[], Some(b"hello"), &[0u8; 64]);
    assert!(parse_cose_sign1(&bad2).is_err());
}

#[test]
fn verify_hash_envelope_mismatch_is_rejected() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    // payload-hash-alg (258) = -16 (SHA-256). Payload bytes are the expected digest.
    let protected = [
        (1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64)),
        (258i64, TestCborValue::Int(-16)),
    ];
    let unprotected = x5c_unprotected_header(cert_der);

    let embedded_digest = vec![1u8; 32];
    let cose = sign_es256(false, Some(embedded_digest.as_slice()), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"not the preimage"), None);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("PAYLOAD_MISMATCH")));
}

#[test]
fn verify_hash_envelope_rejects_unprotected_payload_hash_alg() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(258), TestCborValue::Int(-16))];

    let cose = sign_es256(false, Some(&[1u8; 32]), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"anything"), None);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

#[test]
fn verify_hash_envelope_rejects_empty_digest_bytes() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [
        (1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64)),
        (258i64, TestCborValue::Int(-16)),
    ];
    let unprotected: Vec<(TestCborKey, TestCborValue)> = vec![];

    let cose = sign_es256(false, Some(&[]), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"preimage"), Some(&[0u8; 1]));
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

#[test]
fn verification_pipeline_runs_x5c_chain_validator() {
    // Ensure the validator is linked/registered.
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der];

    let settings = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

    let res = msg.verify(None, None, &settings);
    assert!(res.is_valid, "{res:?}");
    assert_eq!(res.metadata.get("signature.verified").map(|s| s.as_str()), Some("true"));
}

#[test]
fn x5c_chain_validator_skips_when_signature_not_run_or_failed_or_options_missing() {
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];

    // Signature not run -> validator not applicable.
    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain.clone()));
    let res = msg.verify(None, None, &settings);
    assert_eq!(res.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()), Some("false"));

    // Options missing -> validator not applicable even if signature succeeds.
    let settings2 = VerificationSettings::default().with_validator(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID);
    let res2 = msg.verify(None, None, &settings2);
    assert_eq!(res2.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()), Some("false"));

    // Signature fails -> validator not applicable.
    let mut tampered = cose.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let tampered = CoseSign1::from_bytes(&tampered).unwrap();
    let settings3 = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));
    let res3 = tampered.verify(None, None, &settings3);
    // Signature required and failed -> verify() returns early before recording validator ran-state.
    assert!(res3.metadata.get("validator.x5c_chain.ran").is_none());
}

#[test]
fn x5c_chain_validator_error_paths_are_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    // Wrong options type.
    let settings = VerificationSettings::default().with_validator_options((
        cosesign1_x509::X5C_CHAIN_VALIDATOR_ID,
        cosesign1_abstractions::OpaqueOptions::new(()),
    ));
    let res = msg.verify(None, Some(cert_der.as_slice()), &settings);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));

    // Missing x5c header after a successful signature -> validator not applicable.
    let unprotected_no_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(99), TestCborValue::Int(1))];
    let cose2 = sign_es256(false, Some(b"hello"), None, &protected, &unprotected_no_x5c, &signing_key);
    let msg2 = CoseSign1::from_bytes(&cose2).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];

    let settings2 = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));
    let res2 = msg2.verify(None, Some(cert_der.as_slice()), &settings2);
    assert_eq!(res2.metadata.get("validator.x5c_chain.ran").map(|s| s.as_str()), Some("false"));

    // x5c has a non-bstr element.
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Int(1)]),
    )];
    let cose3 = sign_es256(false, Some(b"hello"), None, &protected, &unprotected_bad_x5c, &signing_key);
    let msg3 = CoseSign1::from_bytes(&cose3).unwrap();

    let mut chain = cosesign1_x509::X509ChainVerifyOptions::default();
    chain.trust_mode = cosesign1_x509::X509TrustMode::CustomRoots;
    chain.revocation_mode = cosesign1_x509::X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![cert_der.clone()];
    let settings3 = VerificationSettings::default().with_validator_options(cosesign1_x509::x5c_chain_validation_options(chain));

    let res3 = msg3.verify(None, Some(cert_der.as_slice()), &settings3);
    assert!(!res3.is_valid);
    assert!(res3.failures.iter().any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

#[test]
fn verification_pipeline_reports_missing_validator_as_error() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let bogus = MessageValidatorId(uuid::uuid!("11111111-1111-1111-1111-111111111111"));
    let settings = VerificationSettings::default().with_validator(bogus);

    let res = msg.verify(None, Some(cert_der.as_slice()), &settings);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

#[test]
fn verification_pipeline_can_skip_signature_and_run_mst_validator() {
    // Ensure the MST validator is linked/registered.
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);

    // Valid COSE signature bytes, but MST validator operates on statement receipts; this message
    // won’t have receipts so MST validation should fail, which is fine for coverage.
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator_options(cosesign1_mst::mst_message_validation_options(
            Default::default(),
            Default::default(),
        ));

    let res = msg.verify(None, None, &settings);
    assert_eq!(res.metadata.get("signature.verified").map(|s| s.as_str()), Some("false"));
    assert!(!res.is_valid);
}

#[test]
fn mst_validator_skips_when_unconfigured_and_errors_on_wrong_options_type() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der);
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    // Enabled but not configured -> validator should report ran=false.
    let settings = VerificationSettings::default()
        .without_cose_signature()
        .with_validator(cosesign1_mst::MST_VALIDATOR_ID);
    let res = msg.verify(None, None, &settings);
    assert_eq!(res.metadata.get("validator.mst.ran").map(|s| s.as_str()), Some("false"));

    // Wrong options type -> message validator error.
    let settings2 = VerificationSettings::default()
        .without_cose_signature()
        .with_validator_options((cosesign1_mst::MST_VALIDATOR_ID, cosesign1_abstractions::OpaqueOptions::new(())));
    let res2 = msg.verify(None, None, &settings2);
    assert!(!res2.is_valid);
    assert!(res2.failures.iter().any(|f| f.error_code.as_deref() == Some("MESSAGE_VALIDATOR_ERROR")));
}

#[test]
fn key_provider_registry_and_x5c_provider_error_paths_are_exercised() {
    let _provider_id: SigningKeyProviderId = cosesign1_x509::X5C_PROVIDER_ID;

    // Provider name lookup.
    assert_eq!(
        cosesign1_abstractions::provider_name(cosesign1_x509::X5C_PROVIDER_ID),
        Some(cosesign1_x509::X5C_PROVIDER_NAME)
    );
    assert!(cosesign1_abstractions::provider_name(SigningKeyProviderId(uuid::uuid!("22222222-2222-2222-2222-222222222222"))).is_none());

    // Exercise providers_ordered sorting path.
    let regs = cosesign1_abstractions::providers_ordered();
    assert!(!regs.is_empty());

    // ResolvedSigningKey constructors.
    let _ = cosesign1_abstractions::ResolvedSigningKey::new(vec![1, 2, 3]);
    let _ = cosesign1_abstractions::ResolvedSigningKey::with_material(vec![1, 2, 3], Box::new(vec![4u8]));

    // No x5c -> no provider matched.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::NoProviderMatched) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected NoProviderMatched"),
    }

    // Bad x5c element type -> provider failed.
    let unprotected_bad_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Int(1)]),
    )];
    let cose2 = encode_cose_sign1(false, &protected, &unprotected_bad_x5c, Some(b"hello"), &[0u8; 64]);
    let parsed2 = parse_cose_sign1(&cose2).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed2) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }

    // Empty x5c array.
    let unprotected_empty_x5c: Vec<(TestCborKey, TestCborValue)> = vec![(TestCborKey::Int(33), TestCborValue::Array(vec![]))];
    let cose3 = encode_cose_sign1(false, &protected, &unprotected_empty_x5c, Some(b"hello"), &[0u8; 64]);
    let parsed3 = parse_cose_sign1(&cose3).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed3) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }

    // Empty leaf bytes.
    let unprotected_empty_leaf: Vec<(TestCborKey, TestCborValue)> = vec![(
        TestCborKey::Int(33),
        TestCborValue::Array(vec![TestCborValue::Bytes(vec![])]),
    )];
    let cose4 = encode_cose_sign1(false, &protected, &unprotected_empty_leaf, Some(b"hello"), &[0u8; 64]);
    let parsed4 = parse_cose_sign1(&cose4).unwrap();
    match cosesign1_abstractions::resolve_signing_key(&parsed4) {
        Err(cosesign1_abstractions::ResolvePublicKeyError::ProviderFailed { .. }) => {}
        Err(e) => panic!("unexpected error: {e}"),
        Ok(_) => panic!("expected ProviderFailed"),
    }
}

#[test]
fn mst_verifier_reads_receipt_issuer_from_map_and_bstr() {
    // Receipt 1: protected header CWT map (label 15) is wrapped in a bstr.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.str("issuer.example").unwrap();
    let cwt_map_bytes = enc.into_writer();

    let receipt1_protected = encode_protected_header_bytes(&[
        (15, TestCborValue::Bytes(cwt_map_bytes)),
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt1 = encode_cose_sign1(true, &receipt1_protected, &[], None, &[]);

    // Receipt 2: protected header CWT map is a map, but iss is not a text string => issuer becomes unknown.
    let receipt2_protected = encode_protected_header_bytes(&[
        (
            15,
            TestCborValue::Map(vec![(TestCborKey::Int(1), TestCborValue::Int(123))]),
        ),
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt2 = encode_cose_sign1(true, &receipt2_protected, &[], None, &[]);

    // Transparent statement with embedded receipts in unprotected header label 394.
    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![
        (
            TestCborKey::Int(394),
            TestCborValue::Array(vec![TestCborValue::Bytes(receipt1), TestCborValue::Bytes(receipt2)]),
        ),
    ];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    // No authorized domains + FailIfPresent => we should hit the issuer parsing paths and fail fast.
    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let options = cosesign1_mst::VerificationOptions::default();
    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_UNAUTHORIZED_RECEIPT")));
}

#[test]
fn mst_verifier_reports_inclusion_parse_error_for_invalid_cbor_in_vdp() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![ (
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(TestCborKey::Int(-1), TestCborValue::Bytes(vec![0xff, 0x00]))]),
    ) ];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);

    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_INCLUSION_PARSE_ERROR")));
}

#[test]
fn mst_verifier_reports_path_parse_error_for_malformed_proof_path() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    // Inclusion proof map: { 2: [ [ true ] ] }  (path element length != 2)
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.map(1).unwrap();
    enc.i64(2).unwrap();
    enc.array(1).unwrap();
    enc.array(1).unwrap();
    enc.bool(true).unwrap();
    let inclusion_map_bytes = enc.into_writer();

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![ (
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes)]),
        )]),
    ) ];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);

    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_PATH_PARSE_ERROR")));
}

#[test]
fn mst_jwks_parsing_and_key_store_add_paths() {
    // Invalid JSON hits the error formatting branch.
    assert!(cosesign1_mst::parse_jwks(b"not-json").is_err());

        let jwks = r#"{
            "keys": [
                {"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","kid":"k1"},
                {"kty":"EC","crv":"P-999","x":"AA","y":"AA","kid":"skip-curve"},
                {"kty":"RSA","crv":"P-256","x":"AA","y":"AA","kid":"skip-kty"}
            ]
        }"#;
    let doc = cosesign1_mst::parse_jwks(jwks.as_bytes()).unwrap();
    let mut store = cosesign1_mst::OfflineEcKeyStore::default();

    // First key is syntactically valid JSON but not a valid EC point; add_issuer_keys should error.
    assert!(cosesign1_mst::add_issuer_keys(&mut store, "issuer.example", &doc).is_err());
}

#[test]
fn header_map_getters_return_none_for_wrong_value_types() {
    // Key 42 is a text value; ensure the typed getters return None and hit the `_ => None` branches.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES256 as i64))]);
    let unprotected = vec![(TestCborKey::Int(42), TestCborValue::Text("not-an-int-or-bytes-or-array"))];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();

    assert!(parsed.unprotected_headers.get_i64(42).is_none());
    assert!(parsed.unprotected_headers.get_bytes(42).is_none());
    assert!(parsed.unprotected_headers.get_array(42).is_none());
}

#[test]
fn mst_message_validator_validate_returns_none_when_unconfigured() {
    // Ensure the MST validator is linked/registered.
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;

    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(CoseAlgorithm::ES256 as i64))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let ctx = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: Some(&sig_ok),
    };

    // No options passed => validator should return Ok(None).
    let res = cosesign1_abstractions::run_validator_by_id(cosesign1_mst::MST_VALIDATOR_ID, &ctx, None).unwrap();
    assert!(res.is_none());
}

#[test]
fn x5c_chain_message_validator_early_returns_are_exercised() {
    // Ensure the x509 crate is linked so its inventory registrations are present.
    let _validator_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let sig_bad = cosesign1_abstractions::ValidationResult::failure_message("Signature", "bad", Some("BAD".to_string()));

    // signature_result missing => Ok(None)
    let ctx_none = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: None,
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_none, None)
        .unwrap()
        .is_none());

    // signature_result present but invalid => Ok(None)
    let ctx_bad = cosesign1_abstractions::MessageValidationContext {
        signature_result: Some(&sig_bad),
        ..ctx_none
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_bad, None)
        .unwrap()
        .is_none());

    // signature_result valid but no options => Ok(None)
    let ctx_ok = cosesign1_abstractions::MessageValidationContext {
        signature_result: Some(&sig_ok),
        ..ctx_none
    };
    assert!(cosesign1_abstractions::run_validator_by_id(cosesign1_x509::X5C_CHAIN_VALIDATOR_ID, &ctx_ok, None)
        .unwrap()
        .is_none());
}

#[test]
fn mst_verifier_accepts_embedded_receipts_array_wrapped_in_bstr() {
    // Wrap the embedded receipts array itself in a bstr to hit the decoder branch.
    let receipt_protected = encode_protected_header_bytes(&[
        (395, TestCborValue::Int(2)),
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
    ]);
    let receipt = encode_cose_sign1(true, &receipt_protected, &[], None, &[]);

    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(1).unwrap();
    enc.bytes(&receipt).unwrap();
    let receipts_array_cbor = enc.into_writer();

    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![(TestCborKey::Int(394), TestCborValue::Bytes(receipts_array_cbor))];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let mut options = cosesign1_mst::VerificationOptions::default();
    options.unauthorized_receipt_behavior = cosesign1_mst::UnauthorizedReceiptBehavior::VerifyAll;
    options.authorized_receipt_behavior = cosesign1_mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
}

#[test]
fn mst_add_issuer_keys_inserts_supported_keys_and_skips_unsupported() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let good = make_p256_jwk("kid1", &signing_key);

    let doc = cosesign1_mst::JwksDocument {
        keys: vec![
            good.clone(),
            cosesign1_mst::JwkEcPublicKey {
                kty: "EC".to_string(),
                crv: "P-999".to_string(),
                x: "AA".to_string(),
                y: "AA".to_string(),
                kid: "skip-curve".to_string(),
            },
            cosesign1_mst::JwkEcPublicKey {
                kty: "RSA".to_string(),
                crv: "P-256".to_string(),
                x: "AA".to_string(),
                y: "AA".to_string(),
                kid: "skip-kty".to_string(),
            },
        ],
    };

    let mut store = cosesign1_mst::OfflineEcKeyStore::default();
    let inserted = cosesign1_mst::add_issuer_keys(&mut store, "issuer.example", &doc).unwrap();
    assert_eq!(inserted, 1);
    assert!(store.resolve("issuer.example", "kid1").is_some());
}

#[test]
fn cose_parse_reports_top_level_not_array_and_truncated_tag() {
    // Not an array.
    assert!(parse_cose_sign1(&[0x01]).is_err());

    // Truncated tag header (tag with 1-byte argument but missing that byte).
    assert!(parse_cose_sign1(&[0xD8]).is_err());
}

#[test]
fn cose_parse_reports_wrong_item_types_for_protected_and_signature() {
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    // protected should be bstr, but here it's int
    enc.i64(1).unwrap();
    enc.map(0).unwrap();
    enc.null().unwrap();
    enc.bytes(&[]).unwrap();
    let bad_protected = enc.into_writer();
    assert!(parse_cose_sign1(&bad_protected).is_err());

    let protected = encode_protected_header_bytes(&[]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    // signature should be bstr, but here it's int
    enc.i64(1).unwrap();
    let bad_sig = enc.into_writer();
    assert!(parse_cose_sign1(&bad_sig).is_err());
}

#[test]
fn header_map_decodes_null_and_rejects_unsupported_value_types() {
    // Null value in unprotected headers should decode.
    let protected = encode_protected_header_bytes(&[]);
    let unprotected = vec![(TestCborKey::Int(9), TestCborValue::Null)];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 1]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    assert!(matches!(
        parsed.unprotected_headers.map().get(&cosesign1_abstractions::HeaderKey::Int(9)),
        Some(cosesign1_abstractions::HeaderValue::Null)
    ));

    // Unsupported header value type: float.
    let protected = encode_protected_header_bytes(&[]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(1).unwrap();
    enc.i64(1).unwrap();
    enc.f64(1.0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 1]).unwrap();
    let bad = enc.into_writer();
    assert!(parse_cose_sign1(&bad).is_err());
}

#[test]
fn mst_verifier_reports_non_bstr_element_in_receipts_wrapped_array() {
    // Wrap receipts array in bstr but make element non-bstr.
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.array(1).unwrap();
    enc.i64(1).unwrap();
    let receipts_array_cbor = enc.into_writer();

    let statement_protected = encode_protected_header_bytes(&[]);
    let statement_unprotected = vec![(TestCborKey::Int(394), TestCborValue::Bytes(receipts_array_cbor))];
    let statement = encode_cose_sign1(true, &statement_protected, &statement_unprotected, Some(b"statement"), &[]);

    let store = cosesign1_mst::OfflineEcKeyStore::default();
    let options = cosesign1_mst::VerificationOptions::default();
    let res = cosesign1_mst::verify_transparent_statement("Mst", &statement, &store, &options);
    assert!(!res.is_valid);
}

#[test]
fn mst_verifier_path_bytes_branch_and_leaf_missing_are_exercised() {
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let jwk = make_p256_jwk("kid1", &signing_key);

    // Path encoded as a bstr containing a CBOR array, but malformed (inner length != 2).
    let mut path_enc = minicbor::Encoder::new(Vec::new());
    path_enc.array(1).unwrap();
    path_enc.array(1).unwrap();
    path_enc.bool(true).unwrap();
    let bad_path_bytes = path_enc.into_writer();

    let mut map_enc = minicbor::Encoder::new(Vec::new());
    map_enc.map(1).unwrap();
    map_enc.i64(2).unwrap();
    map_enc.bytes(&bad_path_bytes).unwrap();
    let inclusion_map_bytes = map_enc.into_writer();

    let receipt_protected = encode_protected_header_bytes(&[
        (4, TestCborValue::Bytes(b"kid1".to_vec())),
        (395, TestCborValue::Int(2)),
    ]);
    let receipt_unprotected = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes)]),
        )]),
    )];
    let receipt = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected, None, &[]);
    let res = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt, b"claims");
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_PATH_PARSE_ERROR")));

    // Path parses successfully, but leaf is missing => MST_LEAF_MISSING.
    let mut ok_path_enc = minicbor::Encoder::new(Vec::new());
    ok_path_enc.array(1).unwrap();
    ok_path_enc.array(2).unwrap();
    ok_path_enc.bool(true).unwrap();
    ok_path_enc.bytes(&[1u8]).unwrap();
    let ok_path = ok_path_enc.into_writer();

    let mut map_enc = minicbor::Encoder::new(Vec::new());
    map_enc.map(1).unwrap();
    map_enc.i64(2).unwrap();
    // Inline array (not wrapped) this time.
    {
        let mut dec = minicbor::Decoder::new(&ok_path);
        // Copy the already-encoded path array bytes into the map value by decoding then re-encoding.
        // (Keeps this test small without manual CBOR byte hacking.)
        let _ = dec.array().unwrap();
    }
    // Re-encode as value: [[true, h]]
    map_enc.array(1).unwrap();
    map_enc.array(2).unwrap();
    map_enc.bool(true).unwrap();
    map_enc.bytes(&[1u8]).unwrap();
    let inclusion_map_bytes2 = map_enc.into_writer();

    let receipt_unprotected2 = vec![(
        TestCborKey::Int(396),
        TestCborValue::Map(vec![(
            TestCborKey::Int(-1),
            TestCborValue::Array(vec![TestCborValue::Bytes(inclusion_map_bytes2)]),
        )]),
    )];
    let receipt2 = encode_cose_sign1(true, &receipt_protected, &receipt_unprotected2, None, &[]);
    let res2 = cosesign1_mst::verify_transparent_statement_receipt("Mst", &jwk, &receipt2, b"claims");
    assert!(!res2.is_valid);
    assert!(res2.failures.iter().any(|f| f.error_code.as_deref() == Some("MST_LEAF_MISSING")));
}

#[test]
fn validator_name_methods_are_exercised() {
    let _mst_id: MessageValidatorId = cosesign1_mst::MST_VALIDATOR_ID;
    let _x5c_id: MessageValidatorId = cosesign1_x509::X5C_CHAIN_VALIDATOR_ID;

    let regs = cosesign1_abstractions::validators_ordered();
    assert!(regs.iter().any(|r| r.validator.name() == cosesign1_mst::MST_VALIDATOR_NAME));
    assert!(regs.iter().any(|r| r.validator.name() == cosesign1_x509::X5C_CHAIN_VALIDATOR_NAME));
}

#[test]
fn header_map_rejects_indefinite_length_maps_and_arrays() {
    // Unprotected headers as an indefinite-length map should be rejected.
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected: bstr(1) containing empty map (0xA0)
        0xBF, 0xFF, // unprotected: map(*) ... break
        0x40, // payload: empty bstr
        0x40, // signature: empty bstr
    ];
    assert!(parse_cose_sign1(&cose).is_err());

    // Indefinite-length array nested as a header value should be rejected.
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected
        0xA1, // map(1)
        0x01, // key: 1
        0x9F, 0xFF, // value: array(*) ... break
        0x40, // payload
        0x40, // signature
    ];
    assert!(parse_cose_sign1(&cose).is_err());
}

#[test]
fn header_map_rejects_unsupported_key_types() {
    // Unprotected header map with a boolean key (unsupported).
    let cose = vec![
        0x84, // array(4)
        0x41, 0xA0, // protected
        0xA1, // map(1)
        0xF5, // key: true
        0x01, // value: 1
        0x40, // payload
        0x40, // signature
    ];
    assert!(parse_cose_sign1(&cose).is_err());
}

#[test]
fn verify_cose_sign1_covers_more_alg_header_values() {
    let msg = b"hello";
    let sig = vec![0u8; 1];

    for alg in [-7i64, -35, -36, -48, -49, -50, -37, -257] {
        let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(alg))]);
        let cose = encode_cose_sign1(false, &protected, &[], Some(msg), &sig);
        let opts = VerifyOptions {
            external_payload: None,
            public_key_bytes: Some(vec![1u8]),
            expected_alg: None,
        };
        let res = verify_cose_sign1("Signature", &cose, &opts);
        assert!(!res.is_valid);
    }
}

#[test]
fn verify_ml_dsa_raw_key_path_is_exercised() {
    // Raw non-DER key bytes should take the "raw" branch and then fail decoding.
    let r = verify_sig_structure(CoseAlgorithm::MLDsa44, b"raw", b"msg", b"sig");
    assert!(r.is_err());
}

#[test]
fn cose_hash_envelope_rejects_unsupported_hash_alg_value() {
    // protected header 258 = unsupported value, with embedded digest payload.
    let protected = encode_protected_header_bytes(&[
        (1, TestCborValue::Int(CoseAlgorithm::ES256 as i64)),
        (258, TestCborValue::Int(-999)),
    ]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"digest"), &[0u8; 64]);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let res = msg.verify_signature(Some(b"payload"), Some(b"pk"));
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("INVALID_INDIRECT_SIGNATURE")));
}

#[test]
fn verify_sig_structure_succeeds_for_es256_with_spki_and_cert_inputs() {
    // Generate a P-256 key and sign an arbitrary message.
    let (_cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let pk = p256::PublicKey::from(&verifying_key);
    let spki = pk.to_public_key_der().unwrap();

    let msg = b"message";
    let sig: p256::ecdsa::Signature = signing_key.sign(msg);
    let sig_bytes = sig.to_bytes();

    // SPKI DER works.
    assert!(verify_sig_structure(
        CoseAlgorithm::ES256,
        spki.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&sig_bytes)
    )
    .is_ok());

    // Cert DER also works via SPKI extraction.
    let (cert_der, cert_signing_key) = make_self_signed_p256_cert_and_key();
    let cert_verifying_key = p256::ecdsa::VerifyingKey::from(&cert_signing_key);
    let cert_pk = p256::PublicKey::from(&cert_verifying_key);
    let cert_spki = cert_pk.to_public_key_der().unwrap();
    let cert_sig: p256::ecdsa::Signature = cert_signing_key.sign(msg);
    let cert_sig_bytes = cert_sig.to_bytes();
    assert!(verify_sig_structure(
        CoseAlgorithm::ES256,
        cert_spki.as_bytes(),
        msg,
        AsRef::<[u8]>::as_ref(&cert_sig_bytes)
    )
    .is_ok());

    // Also exercise passing a full cert as the key bytes (SPKI extracted internally).
    assert!(verify_sig_structure(
        CoseAlgorithm::ES256,
        cert_der.as_slice(),
        msg,
        AsRef::<[u8]>::as_ref(&cert_sig_bytes)
    )
    .is_ok());
}

#[test]
fn run_validator_by_id_error_variant_is_exercised() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();
    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());
    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let msg = CoseSign1::from_bytes(&cose).unwrap();

    let sig_ok = cosesign1_abstractions::ValidationResult::success("Signature", Default::default());
    let ctx = cosesign1_abstractions::MessageValidationContext {
        cose_bytes: &msg.bytes,
        parsed: &msg.parsed,
        payload_to_verify: None,
        signature_result: Some(&sig_ok),
    };

    let err = cosesign1_abstractions::run_validator_by_id(
        cosesign1_x509::X5C_CHAIN_VALIDATOR_ID,
        &ctx,
        Some(&cosesign1_abstractions::OpaqueOptions::new(())),
    )
    .unwrap_err();
    assert!(matches!(err, cosesign1_abstractions::RunValidatorError::ValidatorFailed { .. }));
}

#[test]
fn x5c_verifier_windows_error_paths_are_exercised() {
    use cosesign1_x509::{validate_x5c_chain, X509ChainVerifyOptions, X509RevocationMode, X509TrustMode};

    // Invalid leaf DER.
    let chain = X509ChainVerifyOptions::default();
    let res = validate_x5c_chain("X509Chain", &[vec![1, 2, 3]], &chain);
    assert!(!res.is_valid);

    // Custom roots but no trust anchors.
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    let res = validate_x5c_chain("X509Chain", &[vec![1, 2, 3]], &chain);
    assert!(!res.is_valid);

    // Custom roots but a bad root DER fails to add.
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![vec![1, 2, 3]];
    let (leaf_cert, _sk) = make_self_signed_p256_cert_and_key();
    let res = validate_x5c_chain("X509Chain", &[leaf_cert.clone()], &chain);
    assert!(!res.is_valid);

    // Custom roots but not an exact trust anchor.
    let (other_root, _sk2) = make_self_signed_p256_cert_and_key();
    let mut chain = X509ChainVerifyOptions::default();
    chain.trust_mode = X509TrustMode::CustomRoots;
    chain.revocation_mode = X509RevocationMode::NoCheck;
    chain.trusted_roots_der = vec![other_root];
    let res = validate_x5c_chain("X509Chain", &[leaf_cert], &chain);
    assert!(!res.is_valid);
}

#[test]
fn parse_rejects_wrong_tag_and_trailing_bytes() {
    // Wrong tag.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let mut enc = minicbor::Encoder::new(Vec::new());
    enc.tag(Tag::new(19)).unwrap();
    enc.array(4).unwrap();
    enc.bytes(&protected).unwrap();
    enc.map(0).unwrap();
    enc.bytes(b"hello").unwrap();
    enc.bytes(&[0u8; 64]).unwrap();
    let wrong_tag = enc.into_writer();
    assert!(parse_cose_sign1(&wrong_tag).is_err());

    // Trailing bytes.
    let mut good = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    good.extend_from_slice(&[0x00, 0x01]);
    assert!(parse_cose_sign1(&good).is_err());
}

#[test]
fn verify_sig_structure_exercises_algorithm_dispatch_paths() {
    let msg = b"sig_structure";
    let sig = b"sig";

    for alg in [
        CoseAlgorithm::ES256,
        CoseAlgorithm::ES384,
        CoseAlgorithm::ES512,
        CoseAlgorithm::RS256,
        CoseAlgorithm::PS256,
        CoseAlgorithm::MLDsa44,
        CoseAlgorithm::MLDsa65,
        CoseAlgorithm::MLDsa87,
    ] {
        let r = verify_sig_structure(alg, &[], msg, sig);
        assert!(r.is_err());
    }
}

#[test]
fn verify_sig_structure_exercises_deeper_key_and_signature_parsing_paths() {
    // ECDSA: valid key, invalid signature bytes.
    let (_cert_der, sk) = make_self_signed_p256_cert_and_key();
    let vk = p256::ecdsa::VerifyingKey::from(&sk);
    let pk = p256::PublicKey::from(&vk);
    let spki = pk.to_public_key_der().unwrap();
    let msg = b"sig_structure";
    let r = verify_sig_structure(CoseAlgorithm::ES256, spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // P-384 and P-521: generate keys and feed invalid signature bytes.
    let sk384 = p384::ecdsa::SigningKey::random(&mut OsRng);
    let vk384 = p384::ecdsa::VerifyingKey::from(&sk384);
    let pk384 = p384::PublicKey::from(&vk384);
    let spki384 = pk384.to_public_key_der().unwrap();
    let r = verify_sig_structure(CoseAlgorithm::ES384, spki384.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    let sk521 = p521::SecretKey::random(&mut OsRng);
    let pk521 = sk521.public_key();
    let spki521 = pk521.to_public_key_der().unwrap();
    let r = verify_sig_structure(CoseAlgorithm::ES512, spki521.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // RSA: valid key, invalid signature bytes to hit signature parsing errors.
    let mut rng = rand::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);
    let rsa_spki = rsa_pub.to_public_key_der().unwrap();
    let r = verify_sig_structure(CoseAlgorithm::RS256, rsa_spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());
    let r = verify_sig_structure(CoseAlgorithm::PS256, rsa_spki.as_bytes(), msg, b"bad");
    assert!(r.is_err());

    // ML-DSA: force OID mismatch by passing a P-256 cert and SPKI.
    let (cert_der, _sk2) = make_self_signed_p256_cert_and_key();
    let r = verify_sig_structure(CoseAlgorithm::MLDsa44, cert_der.as_slice(), msg, b"bad");
    assert!(r.is_err());
    let spki_der = extract_spki_from_cert_der(&cert_der);
    let r = verify_sig_structure(CoseAlgorithm::MLDsa44, spki_der.as_slice(), msg, b"bad");
    assert!(r.is_err());
}

#[test]
fn verify_parsed_cose_sign1_error_paths_are_exercised() {
    // Missing alg.
    let protected = encode_protected_header_bytes(&[]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = cosesign1::validation::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);

    // Unsupported alg.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-999))]);
    let cose = encode_cose_sign1(false, &protected, &[], Some(b"hello"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    let res = cosesign1::validation::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);

    // alg in unprotected map.
    let protected = encode_protected_header_bytes(&[]);
    let unprotected = vec![(TestCborKey::Int(1), TestCborValue::Int(-7))];
    let cose = encode_cose_sign1(false, &protected, &unprotected, Some(b"hello"), &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    let opts2 = VerifyOptions { public_key_bytes: None, ..opts.clone() };
    let res = cosesign1::validation::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts2);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("MISSING_PUBLIC_KEY")));

    // Sig_structure error for detached payload without external payload.
    let protected = encode_protected_header_bytes(&[(1, TestCborValue::Int(-7))]);
    let cose = encode_cose_sign1(false, &protected, &[], None, &[0u8; 64]);
    let parsed = parse_cose_sign1(&cose).unwrap();
    let res = cosesign1::validation::verify_parsed_cose_sign1("Signature", &parsed, None, &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("SIGSTRUCT_ERROR")));
}

#[test]
fn verify_cose_sign1_reports_parse_error_for_garbage() {
    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(vec![0u8; 1]),
        expected_alg: None,
    };
    let res = verify_cose_sign1("Signature", &[0xff, 0xff, 0xff], &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("COSE_PARSE_ERROR")));
}

#[test]
fn verify_expected_alg_mismatch_is_reported() {
    let (cert_der, signing_key) = make_self_signed_p256_cert_and_key();

    let protected = [(1i64, TestCborValue::Int(CoseAlgorithm::ES256 as i64))];
    let unprotected = x5c_unprotected_header(cert_der.clone());

    let cose = sign_es256(false, Some(b"hello"), None, &protected, &unprotected, &signing_key);
    let parsed = parse_cose_sign1(&cose).unwrap();

    let opts = VerifyOptions {
        external_payload: None,
        public_key_bytes: Some(cert_der),
        expected_alg: Some(CoseAlgorithm::RS256),
    };

    let res = cosesign1::validation::verify_parsed_cose_sign1("Signature", &parsed, parsed.payload.as_deref(), &opts);
    assert!(!res.is_valid);
    assert!(res.failures.iter().any(|f| f.error_code.as_deref() == Some("ALG_MISMATCH")));
}
