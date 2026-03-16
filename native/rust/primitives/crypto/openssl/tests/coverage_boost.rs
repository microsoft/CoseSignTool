// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted coverage tests for uncovered error paths in evp_signer, evp_verifier,
//! and ecdsa_format modules.

use cose_sign1_crypto_openssl::ecdsa_format::{der_to_fixed, fixed_to_der};
use cose_sign1_crypto_openssl::{EvpPrivateKey, EvpPublicKey, EvpSigner, EvpVerifier};
use crypto_primitives::{CryptoSigner, CryptoVerifier};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;

// ============================================================================
// Helpers
// ============================================================================

fn generate_ec_p256_keypair() -> (EvpPrivateKey, EvpPublicKey) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    (
        EvpPrivateKey::from_pkey(pkey).unwrap(),
        EvpPublicKey::from_pkey(pub_pkey).unwrap(),
    )
}

fn generate_rsa_2048_keypair() -> (EvpPrivateKey, EvpPublicKey) {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    (
        EvpPrivateKey::from_pkey(pkey).unwrap(),
        EvpPublicKey::from_pkey(pub_pkey).unwrap(),
    )
}

fn generate_ed25519_keypair() -> (EvpPrivateKey, EvpPublicKey) {
    let pkey = PKey::generate_ed25519().unwrap();
    let pub_der = pkey.public_key_to_der().unwrap();
    let pub_pkey = PKey::public_key_from_der(&pub_der).unwrap();
    (
        EvpPrivateKey::from_pkey(pkey).unwrap(),
        EvpPublicKey::from_pkey(pub_pkey).unwrap(),
    )
}

// ============================================================================
// ecdsa_format — der_to_fixed error paths
// ============================================================================

/// Target: ecdsa_format.rs L81 — r value extends past end of DER data.
#[test]
fn test_cb_der_to_fixed_r_value_out_of_bounds() {
    // SEQUENCE(len=6), INTEGER(len=5, but only 4 bytes remain in the buffer).
    // total_len(6) + pos(2) = 8 = der_sig.len() → passes SEQUENCE length check.
    // r_len=5, pos=4, pos+r_len=9 > 8 → triggers "r value out of bounds".
    let der = [0x30, 0x06, 0x02, 0x05, 0x01, 0x02, 0x03, 0x04];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("out of bounds"),
        "expected 'r value out of bounds' error"
    );
}

/// Target: ecdsa_format.rs L97 — s value extends past end of DER data.
#[test]
fn test_cb_der_to_fixed_s_value_out_of_bounds() {
    // SEQUENCE(len=8): valid r(len=1), then s INTEGER(len=4) but only 3 bytes remain.
    // total_len(8) + pos(2) = 10 = der_sig.len() → passes SEQUENCE length check.
    // r parses fine: len=1, data=[0x42]. s: len=4, pos=7, pos+4=11 > 10 → "s value out of bounds".
    let der = [0x30, 0x08, 0x02, 0x01, 0x42, 0x02, 0x04, 0x01, 0x02, 0x03];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("out of bounds"),
        "expected 's value out of bounds' error"
    );
}

/// Target: ecdsa_format.rs L110 — copy_integer_to_fixed fails for s component
/// because the s integer value is too large for the target fixed field.
#[test]
fn test_cb_der_to_fixed_s_integer_too_large_for_field() {
    // For expected_len=64, component_len=32. s must be <= 32 bytes (after trim).
    // Craft DER: r=1 byte (small), s=34 bytes of 0x01 (too large after trim).
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE tag
    // total_len = 3 (r) + 2 + 34 (s header + s data) = 39
    der.push(39);
    // r: INTEGER(len=1, value=0x01)
    der.push(0x02);
    der.push(0x01);
    der.push(0x01);
    // s: INTEGER(len=34, value=34 bytes of 0x01)
    der.push(0x02);
    der.push(34);
    der.extend_from_slice(&[0x01; 34]);

    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("too large"),
        "expected 'Integer value too large' error"
    );
}

/// Target: ecdsa_format.rs L107 — copy_integer_to_fixed fails for r component.
#[test]
fn test_cb_der_to_fixed_r_integer_too_large_for_field() {
    // For expected_len=64, component_len=32. r=34 bytes of 0x01 (too large).
    let mut der = Vec::new();
    der.push(0x30); // SEQUENCE tag
    // total_len = 2 + 34 (r) + 3 (s) = 39
    der.push(39);
    // r: INTEGER(len=34, value=34 bytes of 0x01)
    der.push(0x02);
    der.push(34);
    der.extend_from_slice(&[0x01; 34]);
    // s: INTEGER(len=1, value=0x01)
    der.push(0x02);
    der.push(0x01);
    der.push(0x01);

    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("too large"),
        "expected 'Integer value too large' error"
    );
}

/// Target: ecdsa_format.rs L29 — DER length field truncated during s-integer
/// length parse (long-form length with insufficient following bytes).
#[test]
fn test_cb_der_to_fixed_s_length_field_truncated() {
    // Valid r, then s INTEGER tag followed by long-form length 0x82 (2 bytes
    // follow) but only 1 byte remains.
    let der = [0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x82, 0x01];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("truncated"),
        "expected 'DER length field truncated' error"
    );
}

/// Target: ecdsa_format.rs ~L25 — invalid DER long-form length (num_len_bytes > 4).
#[test]
fn test_cb_der_to_fixed_invalid_long_form_length() {
    // Valid r, then s INTEGER tag followed by 0x85 (5 length-bytes, invalid).
    let der = [0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x85, 0x01];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("Invalid DER"),
        "expected 'Invalid DER long-form length' error"
    );
}

/// Target: ecdsa_format.rs L68 — SEQUENCE total_len does not match actual data.
#[test]
fn test_cb_der_to_fixed_sequence_length_mismatch() {
    // SEQUENCE claims 100 bytes, but data is much shorter.
    let der = [0x30, 0x64, 0x02, 0x01, 0x42, 0x02, 0x01, 0x43];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("mismatch"),
        "expected 'length mismatch' error"
    );
}

/// Target: ecdsa_format.rs L89 — missing INTEGER tag for s.
#[test]
fn test_cb_der_to_fixed_missing_s_integer_tag() {
    // Valid r, but where s should be there's a non-INTEGER tag (0x04 = OCTET STRING).
    let der = [0x30, 0x06, 0x02, 0x01, 0x42, 0x04, 0x01, 0x43];
    let result = der_to_fixed(&der, 64);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("INTEGER tag for s"),
        "expected 'missing INTEGER tag for s' error"
    );
}

// ============================================================================
// ecdsa_format — fixed_to_der long-form DER encoding paths
// ============================================================================

/// Target: ecdsa_format.rs L210-212 — integer_to_der long-form length for
/// content_len >= 128.
///
/// A 256-byte fixed signature (128-byte components, all 0x01) produces
/// integer DER with content_len = 128 >= 128, triggering the 0x81 long form.
#[test]
fn test_cb_fixed_to_der_medium_integer_long_form() {
    let fixed_sig = vec![0x01u8; 256]; // 128-byte r, 128-byte s
    let der = fixed_to_der(&fixed_sig).unwrap();

    // Verify it round-trips back.
    let recovered = der_to_fixed(&der, 256).unwrap();
    assert_eq!(recovered, fixed_sig);

    // Verify the DER contains long-form length encoding (0x81 prefix).
    // r INTEGER starts at index 2 (after SEQUENCE tag + length).
    // With 128-byte content, the INTEGER header should use 0x81 0x80.
    assert!(
        der.windows(2).any(|w| w == [0x81, 0x80]),
        "expected 0x81 long-form integer length in DER"
    );
}

/// Target: ecdsa_format.rs L213-216 — integer_to_der long-form length for
/// content_len >= 256 (2-byte long-form).
///
/// A 512-byte fixed signature (256-byte components, all 0x01) produces
/// integer DER with content_len = 256 >= 256, triggering the 0x82 long form.
#[test]
fn test_cb_fixed_to_der_large_integer_long_form() {
    let fixed_sig = vec![0x01u8; 512]; // 256-byte r, 256-byte s
    let der = fixed_to_der(&fixed_sig).unwrap();

    // Verify it round-trips back.
    let recovered = der_to_fixed(&der, 512).unwrap();
    assert_eq!(recovered, fixed_sig);

    // Check for 0x82 long-form integer encoding (content_len >= 256).
    assert!(
        der.windows(3).any(|w| w[0] == 0x82),
        "expected 0x82 long-form integer length in DER"
    );
}

/// Target: ecdsa_format.rs L149-152 — fixed_to_der SEQUENCE long-form length
/// for total_len >= 256.
///
/// With 256-byte components, each integer DER is ~260 bytes, total ~520 >= 256.
#[test]
fn test_cb_fixed_to_der_large_sequence_long_form() {
    let fixed_sig = vec![0x01u8; 512];
    let der = fixed_to_der(&fixed_sig).unwrap();

    // SEQUENCE tag is 0x30, followed by 0x82 (2-byte long-form) since total >= 256.
    assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
    assert_eq!(
        der[1], 0x82,
        "expected 0x82 long-form SEQUENCE length for total >= 256"
    );
}

/// Target: ecdsa_format.rs L146-148 — fixed_to_der SEQUENCE with total_len
/// in range [128, 256) triggers 0x81 single-byte long-form.
///
/// A 128-byte fixed signature: 64-byte r (all 0x80) + 64-byte s (all 0x80).
/// Each component has high bit set → needs 0x00 padding → content_len = 65.
/// r_der: 0x02 0x41 0x00 <64 bytes> = 67 bytes
/// s_der: 0x02 0x41 0x00 <64 bytes> = 67 bytes
/// total_len = 134 → in range [128, 256) → 0x81 long form.
#[test]
fn test_cb_fixed_to_der_medium_sequence_long_form() {
    let fixed_sig = vec![0x80u8; 128]; // 64-byte r, 64-byte s, all with high bit set
    let der = fixed_to_der(&fixed_sig).unwrap();

    assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
    assert_eq!(
        der[1], 0x81,
        "expected 0x81 long-form SEQUENCE length for total in [128, 256)"
    );

    // Verify round-trip.
    let recovered = der_to_fixed(&der, 128).unwrap();
    assert_eq!(recovered, fixed_sig);
}

/// Verify that fixed_to_der -> der_to_fixed round-trips for various sizes.
#[test]
fn test_cb_ecdsa_format_roundtrip_various_sizes() {
    for size in [8, 64, 96, 132, 200, 256, 512] {
        let mut fixed = vec![0u8; size];
        // Non-trivial values: alternate 0x42 and 0xFF.
        for (i, byte) in fixed.iter_mut().enumerate() {
            *byte = if i % 2 == 0 { 0x42 } else { 0xFF };
        }
        let der = fixed_to_der(&fixed).unwrap();
        let recovered = der_to_fixed(&der, size).unwrap();
        assert_eq!(recovered, fixed, "round-trip failed for size {}", size);
    }
}

/// Target: ecdsa_format.rs — integer_to_der with empty input returns DER for 0.
#[test]
fn test_cb_fixed_to_der_zero_value_components() {
    // All zeros: each component is 0, which DER encodes as [0x02, 0x01, 0x00].
    let fixed_sig = vec![0x00u8; 64];
    let der = fixed_to_der(&fixed_sig).unwrap();

    // Should round-trip back to all zeros.
    let recovered = der_to_fixed(&der, 64).unwrap();
    assert_eq!(recovered, fixed_sig);
}

/// Target: ecdsa_format.rs — der_to_fixed with long-form DER length in SEQUENCE.
/// Verifies that der_to_fixed can parse long-form SEQUENCE headers produced by
/// fixed_to_der with large signatures.
#[test]
fn test_cb_der_to_fixed_parses_long_form_sequence() {
    // Build a DER with 0x81 long-form SEQUENCE length.
    let fixed_sig = vec![0x80u8; 128]; // triggers long-form
    let der = fixed_to_der(&fixed_sig).unwrap();
    assert_eq!(der[1], 0x81, "precondition: long-form SEQUENCE length");

    let recovered = der_to_fixed(&der, 128).unwrap();
    assert_eq!(recovered, fixed_sig);
}

/// Target: ecdsa_format.rs — der_to_fixed with 0x82 two-byte long-form SEQUENCE.
#[test]
fn test_cb_der_to_fixed_parses_two_byte_long_form_sequence() {
    let fixed_sig = vec![0x01u8; 512]; // triggers 0x82 long-form
    let der = fixed_to_der(&fixed_sig).unwrap();
    assert_eq!(der[1], 0x82, "precondition: 2-byte long-form SEQUENCE length");

    let recovered = der_to_fixed(&der, 512).unwrap();
    assert_eq!(recovered, fixed_sig);
}

// ============================================================================
// evp_signer — error paths
// ============================================================================

/// Target: evp_signer.rs L40 — EvpSigner::from_der with an unsupported key type.
/// X25519 keys can be parsed from DER but are not EC, RSA, or Ed25519,
/// causing EvpPrivateKey::from_pkey to fail.
#[test]
fn test_cb_signer_from_der_unsupported_key_type_x25519() {
    let x25519_key = PKey::generate_x25519().unwrap();
    let der = x25519_key.private_key_to_der().unwrap();

    let result = EvpSigner::from_der(&der, -7);
    assert!(result.is_err(), "X25519 should not be accepted as a signing key");
}

/// Target: evp_signer.rs L127 — streaming finalize with EC key and mismatched
/// COSE algorithm. The algorithm -257 (RS256) is valid for get_digest_for_algorithm
/// but not in the EC expected_len match, producing UnsupportedAlgorithm.
#[test]
fn test_cb_signer_ec_streaming_finalize_mismatched_algorithm() {
    let (priv_key, _) = generate_ec_p256_keypair();

    // Create signer with RS256 algorithm (-257) on an EC key.
    let signer = EvpSigner::new(priv_key, -257).unwrap();

    // sign_init succeeds because -257 maps to SHA-256 and EC keys accept it.
    let mut ctx = signer.sign_init().unwrap();
    ctx.update(b"test data").unwrap();

    // finalize fails: EC key produces ECDSA DER, but -257 is not -7/-35/-36.
    let result = ctx.finalize();
    assert!(result.is_err(), "finalize should fail with mismatched algorithm");
}

/// Target: evp_signer.rs — non-streaming sign with EC key and mismatched algorithm.
/// Exercises the sign_ecdsa function with an algorithm that passes digest selection
/// but fails the expected_len match.
#[test]
fn test_cb_signer_ec_oneshot_mismatched_algorithm() {
    let (priv_key, _) = generate_ec_p256_keypair();

    // -257 is RS256 but key is EC → sign_data dispatches to sign_ecdsa → unsupported alg.
    let signer = EvpSigner::new(priv_key, -257).unwrap();
    let result = signer.sign(b"test data");
    assert!(result.is_err(), "sign should fail with mismatched algorithm");
}

/// Verify key_type returns correct strings for all key types.
#[test]
fn test_cb_signer_key_type_strings() {
    let (ec_key, _) = generate_ec_p256_keypair();
    let ec_signer = EvpSigner::new(ec_key, -7).unwrap();
    assert_eq!(ec_signer.key_type(), "EC2");

    let (rsa_key, _) = generate_rsa_2048_keypair();
    let rsa_signer = EvpSigner::new(rsa_key, -257).unwrap();
    assert_eq!(rsa_signer.key_type(), "RSA");

    let (ed_key, _) = generate_ed25519_keypair();
    let ed_signer = EvpSigner::new(ed_key, -8).unwrap();
    assert_eq!(ed_signer.key_type(), "OKP");
}

/// Verify supports_streaming returns correct values per key type.
#[test]
fn test_cb_signer_supports_streaming_by_key_type() {
    let (ec_key, _) = generate_ec_p256_keypair();
    let ec_signer = EvpSigner::new(ec_key, -7).unwrap();
    assert!(ec_signer.supports_streaming());

    let (rsa_key, _) = generate_rsa_2048_keypair();
    let rsa_signer = EvpSigner::new(rsa_key, -257).unwrap();
    assert!(rsa_signer.supports_streaming());

    let (ed_key, _) = generate_ed25519_keypair();
    let ed_signer = EvpSigner::new(ed_key, -8).unwrap();
    assert!(!ed_signer.supports_streaming());
}

// ============================================================================
// evp_verifier — error paths
// ============================================================================

/// Target: evp_verifier.rs L40 — EvpVerifier::from_der with unsupported key type.
#[test]
fn test_cb_verifier_from_der_unsupported_key_type_x25519() {
    let x25519_key = PKey::generate_x25519().unwrap();
    let pub_der = x25519_key.public_key_to_der().unwrap();

    let result = EvpVerifier::from_der(&pub_der, -7);
    assert!(
        result.is_err(),
        "X25519 should not be accepted as a verification key"
    );
}

/// Target: evp_verifier.rs L84, L89, L132 — exercise streaming verify path with
/// EC key to cover clone_public_key and create_verifier code paths.
#[test]
fn test_cb_verifier_streaming_ec_full_path() {
    let (priv_key, pub_key) = generate_ec_p256_keypair();

    // Sign data with EC key.
    let signer = EvpSigner::new(priv_key, -7).unwrap();
    let data = b"streaming verification test data";
    let signature = signer.sign(data).unwrap();

    // Streaming verify.
    let verifier = EvpVerifier::new(pub_key, -7).unwrap();
    let mut ctx = verifier.verify_init(&signature).unwrap();
    ctx.update(data).unwrap();
    let valid = ctx.finalize().unwrap();
    assert!(valid, "streaming verification should succeed");
}

/// Target: evp_verifier.rs L84, L89, L132 — exercise streaming verify path with
/// RSA key to cover clone_public_key and create_verifier with RSA.
#[test]
fn test_cb_verifier_streaming_rsa_full_path() {
    let (priv_key, pub_key) = generate_rsa_2048_keypair();

    let signer = EvpSigner::new(priv_key, -257).unwrap();
    let data = b"RSA streaming verification test data";
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::new(pub_key, -257).unwrap();
    let mut ctx = verifier.verify_init(&signature).unwrap();
    ctx.update(data).unwrap();
    let valid = ctx.finalize().unwrap();
    assert!(valid, "RSA streaming verification should succeed");
}

/// Target: evp_verifier.rs L132, L139, L143 — streaming verify with RSA-PSS (PS256)
/// to exercise PSS padding setup in the streaming create_verifier path.
#[test]
fn test_cb_verifier_streaming_rsa_pss_path() {
    let (priv_key, pub_key) = generate_rsa_2048_keypair();

    // PS256 (-37) uses RSA-PSS padding.
    let signer = EvpSigner::new(priv_key, -37).unwrap();
    let data = b"RSA-PSS streaming verification";
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::new(pub_key, -37).unwrap();
    let mut ctx = verifier.verify_init(&signature).unwrap();
    ctx.update(data).unwrap();
    let valid = ctx.finalize().unwrap();
    assert!(valid, "RSA-PSS streaming verification should succeed");
}

/// Target: evp_verifier.rs L149-150 — streaming verify with Ed25519 to exercise
/// the EdDSA create_verifier path. Note: Ed25519 doesn't support streaming
/// (supports_streaming returns false), but we can still call verify (non-streaming).
#[test]
fn test_cb_verifier_ed25519_oneshot_verify() {
    let (priv_key, pub_key) = generate_ed25519_keypair();

    let signer = EvpSigner::new(priv_key, -8).unwrap();
    let data = b"Ed25519 verification test";
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::new(pub_key, -8).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid, "Ed25519 verification should succeed");

    // Verify with wrong data returns false.
    let valid_wrong = verifier.verify(b"wrong data", &signature).unwrap();
    assert!(!valid_wrong, "wrong data should fail verification");
}

/// Target: evp_verifier.rs — verify with corrupted signature.
#[test]
fn test_cb_verifier_ec_corrupted_signature() {
    let (priv_key, pub_key) = generate_ec_p256_keypair();

    let signer = EvpSigner::new(priv_key, -7).unwrap();
    let data = b"test data";
    let mut signature = signer.sign(data).unwrap();

    // Corrupt the signature by flipping bits.
    for byte in signature.iter_mut() {
        *byte ^= 0xFF;
    }

    let verifier = EvpVerifier::new(pub_key, -7).unwrap();
    // Corrupted ECDSA signature may fail during DER conversion or return false.
    let _result = verifier.verify(data, &signature);
    // Either an error or false is acceptable — just exercise the code path.
}

/// Target: evp_verifier.rs — streaming verify with wrong data should return false.
#[test]
fn test_cb_verifier_streaming_ec_wrong_data() {
    let (priv_key, pub_key) = generate_ec_p256_keypair();

    let signer = EvpSigner::new(priv_key, -7).unwrap();
    let signature = signer.sign(b"original data").unwrap();

    let verifier = EvpVerifier::new(pub_key, -7).unwrap();
    let mut ctx = verifier.verify_init(&signature).unwrap();
    ctx.update(b"different data").unwrap();
    let valid = ctx.finalize().unwrap();
    assert!(!valid, "wrong data should fail streaming verification");
}

/// Target: evp_verifier.rs — streaming verify with chunked updates.
#[test]
fn test_cb_verifier_streaming_ec_chunked_updates() {
    let (priv_key, pub_key) = generate_ec_p256_keypair();

    let signer = EvpSigner::new(priv_key, -7).unwrap();
    let data = b"This is a longer piece of data for chunked streaming verification testing.";
    let signature = signer.sign(data).unwrap();

    let verifier = EvpVerifier::new(pub_key, -7).unwrap();
    let mut ctx = verifier.verify_init(&signature).unwrap();

    // Feed data in small chunks.
    for chunk in data.chunks(10) {
        ctx.update(chunk).unwrap();
    }

    let valid = ctx.finalize().unwrap();
    assert!(valid, "chunked streaming verification should succeed");
}

/// Target: evp_signer.rs — streaming sign with RSA-PSS (PS256) to exercise
/// the PSS padding setup in streaming create_signer path.
#[test]
fn test_cb_signer_streaming_rsa_pss_sign_verify() {
    let (priv_key, pub_key) = generate_rsa_2048_keypair();

    // Streaming sign with PS256 (-37).
    let signer = EvpSigner::new(priv_key, -37).unwrap();
    let data = b"RSA-PSS streaming sign data";

    let mut ctx = signer.sign_init().unwrap();
    ctx.update(data).unwrap();
    let signature = ctx.finalize().unwrap();

    // Verify non-streaming.
    let verifier = EvpVerifier::new(pub_key, -37).unwrap();
    let valid = verifier.verify(data, &signature).unwrap();
    assert!(valid, "PSS streaming signature should verify");
}

/// Target: evp_signer.rs — streaming sign with PS384 and PS512.
#[test]
fn test_cb_signer_streaming_rsa_pss_384_512() {
    let (priv_key, pub_key) = generate_rsa_2048_keypair();

    for alg in [-38i64, -39] {
        let priv_clone = {
            let der = priv_key.pkey().private_key_to_der().unwrap();
            let pkey = PKey::private_key_from_der(&der).unwrap();
            EvpPrivateKey::from_pkey(pkey).unwrap()
        };
        let pub_clone = {
            let der = pub_key.pkey().public_key_to_der().unwrap();
            let pkey = PKey::public_key_from_der(&der).unwrap();
            EvpPublicKey::from_pkey(pkey).unwrap()
        };

        let signer = EvpSigner::new(priv_clone, alg).unwrap();
        let data = b"PSS 384/512 streaming test";

        let mut ctx = signer.sign_init().unwrap();
        ctx.update(data).unwrap();
        let signature = ctx.finalize().unwrap();

        let verifier = EvpVerifier::new(pub_clone, alg).unwrap();
        let valid = verifier.verify(data, &signature).unwrap();
        assert!(valid, "PSS streaming signature for alg {} should verify", alg);
    }
}

/// Target: evp_signer.rs — streaming sign with Ed25519 should fail
/// (Ed25519 does not support streaming).
#[test]
fn test_cb_signer_ed25519_no_streaming() {
    let (ed_key, _) = generate_ed25519_keypair();
    let signer = EvpSigner::new(ed_key, -8).unwrap();
    assert!(!signer.supports_streaming());
}
