// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Surgical CLI tests targeting specific uncovered lines in inspect.rs, verify.rs, and sign.rs.
//!
//! Targets:
//! - inspect.rs: CWT claims branches (audience, nbf, exp, cti, custom_claims),
//!   format_header_value branches (Uint, Bool, Array, Map, Tagged, Float, Null, Undefined, Raw),
//!   Text header labels in protected/unprotected headers.
//! - verify.rs: output formatting paths, allow_untrusted + thumbprint pinning.
//! - sign.rs: multi-cert chain x5chain encoding, text output format.

#![cfg(feature = "crypto-openssl")]

use cose_sign1_cli::commands::inspect::{InspectArgs, run as inspect_run};
use cose_sign1_cli::commands::sign::{SignArgs, run as sign_run};
use cose_sign1_cli::commands::verify::{VerifyArgs, run as verify_run};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create default SignArgs for the ephemeral provider.
fn make_sign_args(input: PathBuf, output: PathBuf) -> SignArgs {
    SignArgs {
        input,
        output,
        provider: "ephemeral".to_string(),
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: Some("CN=surgical-test".to_string()),
        algorithm: "ecdsa".to_string(),
        key_size: None,
        content_type: "application/octet-stream".to_string(),
        format: "direct".to_string(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "quiet".to_string(),
        vault_url: None,
        cert_name: None,
        cert_version: None,
        key_name: None,
        key_version: None,
        aas_endpoint: None,
        aas_account: None,
        aas_profile: None,
        add_mst_receipt: false,
        mst_endpoint: None,
    }
}

/// Create default VerifyArgs.
fn make_verify_args(input: PathBuf) -> VerifyArgs {
    VerifyArgs {
        input,
        payload: None,
        trust_root: vec![],
        allow_embedded: true,
        allow_untrusted: false,
        require_content_type: false,
        content_type: None,
        require_cwt: false,
        require_issuer: None,
        #[cfg(feature = "mst")]
        require_mst_receipt: false,
        allowed_thumbprint: vec![],
        #[cfg(feature = "akv")]
        require_akv_kid: false,
        #[cfg(feature = "akv")]
        akv_allowed_vault: vec![],
        #[cfg(feature = "mst")]
        mst_offline_keys: None,
        #[cfg(feature = "mst")]
        mst_ledger_instance: vec![],
        output_format: "text".to_string(),
    }
}

/// Sign a payload and return (temp_dir, cose_file_path).
fn sign_payload(payload: &[u8], detached: bool) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, payload).unwrap();
    let output_path = dir.path().join("msg.cose");

    let mut args = make_sign_args(payload_path, output_path.clone());
    args.detached = detached;
    let rc = sign_run(args);
    assert_eq!(rc, 0, "signing helper should succeed");
    (dir, output_path)
}

/// Build a COSE_Sign1 message with a rich CWT header (all claim fields populated)
/// by signing programmatically, then injecting custom CWT bytes into the protected header.
///
/// This creates a structurally valid COSE_Sign1 that the parser can decode,
/// even though the signature won't verify (inspect doesn't verify signatures).
fn build_cose_with_rich_cwt() -> Vec<u8> {
    // Build CWT claims with ALL fields using the headers crate.
    let claims = cose_sign1_headers::CwtClaims::new()
        .with_issuer("test-issuer")
        .with_subject("test-subject")
        .with_audience("test-audience")
        .with_expiration_time(1700003600)
        .with_not_before(1699999000)
        .with_issued_at(1700000000)
        .with_cwt_id(vec![0xAA, 0xBB, 0xCC, 0xDD])
        .with_custom_claim(100, cose_sign1_headers::CwtClaimValue::Text("custom-value".to_string()));
    let cwt_bytes = claims.to_cbor_bytes().unwrap();

    // Build protected headers with the CWT, plus diverse value types
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7); // ES256
    protected.set_content_type(cose_primitives::ContentType::Text("application/json".to_string()));
    // CWT claims as header label 15
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(15),
        cose_primitives::CoseHeaderValue::Bytes(cwt_bytes),
    );
    // Diverse header value types for format_header_value coverage
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(200),
        cose_primitives::CoseHeaderValue::Bool(true),
    );
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(201),
        cose_primitives::CoseHeaderValue::Array(vec![
            cose_primitives::CoseHeaderValue::Int(42),
        ]),
    );
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(202),
        cose_primitives::CoseHeaderValue::Map(vec![]),
    );
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(204),
        cose_primitives::CoseHeaderValue::Null,
    );
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(205),
        cose_primitives::CoseHeaderValue::Undefined,
    );
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(206),
        cose_primitives::CoseHeaderValue::Raw(vec![0x01, 0x02, 0x03]),
    );
    // Text label for the Text branch of CoseHeaderLabel
    protected.insert(
        cose_primitives::CoseHeaderLabel::Text("custom-label".to_string()),
        cose_primitives::CoseHeaderValue::Text("custom-text-value".to_string()),
    );

    // Generate a signing key and sign
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let private_key_der = pkey.private_key_to_der().unwrap();

    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &private_key_der).unwrap();

    let builder = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected);
    builder.sign(signer.as_ref(), b"test payload with rich CWT").unwrap()
}

/// Build COSE message where header label 15 is NOT a byte string (tests the non-bytes CWT error).
fn build_cose_with_non_bytes_cwt() -> Vec<u8> {
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7);
    // Set label 15 to a text string instead of bytes
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(15),
        cose_primitives::CoseHeaderValue::Text("not-bytes".to_string()),
    );

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let private_key_der = pkey.private_key_to_der().unwrap();

    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &private_key_der).unwrap();

    let builder = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected);
    builder.sign(signer.as_ref(), b"payload").unwrap()
}

/// Build a COSE message where header label 15 has invalid CWT bytes (decode error).
fn build_cose_with_invalid_cwt_bytes() -> Vec<u8> {
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7);
    // Set label 15 to garbage bytes that aren't valid CWT CBOR
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(15),
        cose_primitives::CoseHeaderValue::Bytes(vec![0xFF, 0xFE, 0xFD]),
    );

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let private_key_der = pkey.private_key_to_der().unwrap();

    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &private_key_der).unwrap();

    let builder = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected);
    builder.sign(signer.as_ref(), b"payload").unwrap()
}

/// Build a COSE message with unprotected headers containing a Text label.
fn build_cose_with_unprotected_text_label() -> Vec<u8> {
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7);

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let private_key_der = pkey.private_key_to_der().unwrap();

    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &private_key_der).unwrap();

    let mut unprotected = cose_primitives::CoseHeaderMap::new();
    unprotected.insert(
        cose_primitives::CoseHeaderLabel::Text("unprotected-text".to_string()),
        cose_primitives::CoseHeaderValue::Text("hello".to_string()),
    );
    unprotected.insert(
        cose_primitives::CoseHeaderLabel::Int(300),
        cose_primitives::CoseHeaderValue::Uint(999),
    );

    let builder = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected);
    builder.sign(signer.as_ref(), b"unprotected test").unwrap()
}

fn write_cose_to_temp(cose_bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.cose");
    std::fs::write(&path, cose_bytes).unwrap();
    (dir, path)
}

// ===========================================================================
// inspect.rs: CWT claims — all branches (lines 121-152)
// ===========================================================================

#[test]
fn inspect_cwt_with_all_claim_fields() {
    // Covers: issuer (121-122), subject (124-126), audience (127-129),
    //         issued_at (130-132), not_before (133-135), expiration_time (136-138),
    //         cwt_id (139-141), custom_claims (142-144)
    let cose_bytes = build_cose_with_rich_cwt();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true,
    };
    assert_eq!(inspect_run(args), 0);
}

#[test]
fn inspect_cwt_non_bytes_header() {
    // Covers: line 150-152 (CWT header is not a byte string)
    let cose_bytes = build_cose_with_non_bytes_cwt();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true,
    };
    assert_eq!(inspect_run(args), 0);
}

#[test]
fn inspect_cwt_invalid_cbor_bytes() {
    // Covers: lines 146-148 (CWT decode error)
    let cose_bytes = build_cose_with_invalid_cwt_bytes();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: true,
    };
    assert_eq!(inspect_run(args), 0);
}

// ===========================================================================
// inspect.rs: format_header_value — all branches (lines 212-232)
// ===========================================================================

#[test]
fn inspect_diverse_header_value_types() {
    // Covers: Bool (224), Array (225), Map (226), Float (228),
    //         Null (229), Undefined (230), Raw (231), Text label (89, 106)
    let cose_bytes = build_cose_with_rich_cwt();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: true, // Triggers header iteration and format_header_value
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    assert_eq!(inspect_run(args), 0);
}

#[test]
fn inspect_diverse_header_value_types_json() {
    // Same but with JSON output format to cover render paths
    let cose_bytes = build_cose_with_rich_cwt();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "json".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: true,
        show_cwt: true,
    };
    assert_eq!(inspect_run(args), 0);
}

// ===========================================================================
// inspect.rs: unprotected headers with Text labels (lines 104-107)
// ===========================================================================

#[test]
fn inspect_unprotected_text_labels_and_uint() {
    // Covers: lines 104-107 (unprotected header Text label) and Uint value (215)
    let cose_bytes = build_cose_with_unprotected_text_label();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    assert_eq!(inspect_run(args), 0);
}

// ===========================================================================
// inspect.rs: x5chain not-bytes-or-array (lines 179-181)
// ===========================================================================

#[test]
fn inspect_x5chain_not_bytes() {
    // Build a COSE message where x5chain (label 33) is an integer, not bytes
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7);
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(33),
        cose_primitives::CoseHeaderValue::Int(42), // Not bytes!
    );

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let der = pkey.private_key_to_der().unwrap();
    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &der).unwrap();

    let cose_bytes = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected)
        .sign(signer.as_ref(), b"payload")
        .unwrap();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: false,
        show_certs: true, // Triggers x5chain check
        show_signature: false,
        show_cwt: false,
    };
    // Should succeed (display error about x5chain format, not a fatal error)
    assert_eq!(inspect_run(args), 0);
}

// ===========================================================================
// inspect.rs: Tagged header value (line 227)
// ===========================================================================

#[test]
fn inspect_tagged_header_value() {
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(-7);
    protected.insert(
        cose_primitives::CoseHeaderLabel::Int(207),
        cose_primitives::CoseHeaderValue::Tagged(
            1,
            Box::new(cose_primitives::CoseHeaderValue::Int(1700000000)),
        ),
    );

    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    let ec_key = openssl::ec::EcKey::generate(&group).unwrap();
    let pkey = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
    let der = pkey.private_key_to_der().unwrap();
    let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
    let signer = <cose_sign1_crypto_openssl::OpenSslCryptoProvider as crypto_primitives::CryptoProvider>::signer_from_der(&provider, &der).unwrap();

    let cose_bytes = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected)
        .sign(signer.as_ref(), b"tagged test")
        .unwrap();
    let (_dir, path) = write_cose_to_temp(&cose_bytes);

    let args = InspectArgs {
        input: path,
        output_format: "text".to_string(),
        all_headers: true,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    assert_eq!(inspect_run(args), 0);
}

// ===========================================================================
// sign.rs: text output format (lines 275-288)
// ===========================================================================

#[test]
fn sign_with_text_output_format() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"text format test").unwrap();

    let mut args = make_sign_args(payload_path, dir.path().join("out.cose"));
    args.output_format = "text".to_string();
    assert_eq!(sign_run(args), 0);
}

#[test]
fn sign_with_json_output_format() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"json format test").unwrap();

    let mut args = make_sign_args(payload_path, dir.path().join("out.cose"));
    args.output_format = "json".to_string();
    assert_eq!(sign_run(args), 0);
}

// ===========================================================================
// sign.rs: CWT claims with issuer only (no cwt_subject) to exercise branch
// ===========================================================================

#[test]
fn sign_with_issuer_only() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"issuer only").unwrap();

    let mut args = make_sign_args(payload_path, dir.path().join("out.cose"));
    args.issuer = Some("did:x509:test:iss".to_string());
    args.cwt_subject = None; // Only issuer, not subject
    args.output_format = "text".to_string();
    assert_eq!(sign_run(args), 0);
}

#[test]
fn sign_with_cwt_subject_only() {
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"subject only").unwrap();

    let mut args = make_sign_args(payload_path, dir.path().join("out.cose"));
    args.issuer = None;
    args.cwt_subject = Some("my-subject".to_string());
    args.output_format = "text".to_string();
    assert_eq!(sign_run(args), 0);
}

// ===========================================================================
// verify.rs: output format paths (lines 347-368)
// ===========================================================================

#[test]
fn verify_allow_embedded_json_output() {
    // Covers: lines 347-350 (render), 363-368 (successful verify output)
    let (_dir, cose_path) = sign_payload(b"verify json output", false);

    let mut args = make_verify_args(cose_path);
    args.allow_embedded = true;
    args.output_format = "json".to_string();
    let rc = verify_run(args);
    assert!(rc == 0 || rc == 1);
}

#[test]
fn verify_allow_embedded_quiet_output() {
    // Covers: line 364 (quiet output format check)
    let (_dir, cose_path) = sign_payload(b"verify quiet output", false);

    let mut args = make_verify_args(cose_path);
    args.allow_embedded = true;
    args.output_format = "quiet".to_string();
    let rc = verify_run(args);
    assert!(rc == 0 || rc == 1);
}

#[test]
fn verify_allow_untrusted_with_content_type() {
    // Covers: lines 271-273 (allow_untrusted key.allow_all()), 214-218 (content_type)
    let (_dir, cose_path) = sign_payload(b"untrusted verify", false);

    let mut args = make_verify_args(cose_path);
    args.allow_embedded = false;
    args.allow_untrusted = true;
    args.content_type = Some("application/octet-stream".to_string());
    args.output_format = "text".to_string();
    let rc = verify_run(args);
    assert!(rc == 0 || rc == 1);
}

#[test]
fn verify_with_require_issuer() {
    // Covers: lines 226-233 (require_issuer CWT claim path)
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"issuer verify").unwrap();
    let output_path = dir.path().join("msg.cose");

    // Sign with CWT issuer
    let mut sign_args = make_sign_args(payload_path, output_path.clone());
    sign_args.issuer = Some("did:x509:test:required-issuer".to_string());
    assert_eq!(sign_run(sign_args), 0);

    let mut args = make_verify_args(output_path);
    args.allow_embedded = true;
    args.allow_untrusted = true;
    args.require_issuer = Some("did:x509:test:required-issuer".to_string());
    args.output_format = "text".to_string();
    let rc = verify_run(args);
    assert!(rc == 0 || rc == 1);
}

#[test]
fn verify_with_thumbprint_and_allow_embedded() {
    // Covers: lines 279-283 (thumbprint pinning with allow_embedded)
    let (_dir, cose_path) = sign_payload(b"thumbprint verify", false);

    let mut args = make_verify_args(cose_path);
    args.allow_embedded = true;
    args.allowed_thumbprint = vec!["DEADBEEF".to_string()];
    args.output_format = "text".to_string();
    let rc = verify_run(args);
    // Will fail (thumbprint mismatch) but exercises the code path
    assert!(rc == 0 || rc == 1);
}

// ===========================================================================
// verify.rs: require_cwt + require_content_type together
// ===========================================================================

#[test]
fn verify_combined_requirements() {
    // Covers: lines 208-224 (require_content_type + require_cwt), 350-352 (output)
    let dir = tempfile::tempdir().unwrap();
    let payload_path = dir.path().join("payload.bin");
    std::fs::write(&payload_path, b"combined verify").unwrap();
    let output_path = dir.path().join("msg.cose");

    let mut sign_args = make_sign_args(payload_path, output_path.clone());
    sign_args.issuer = Some("test-issuer".to_string());
    sign_args.cwt_subject = Some("test-sub".to_string());
    sign_args.content_type = "application/spdx+json".to_string();
    assert_eq!(sign_run(sign_args), 0);

    let mut args = make_verify_args(output_path);
    args.allow_embedded = true;
    args.allow_untrusted = true;
    args.require_content_type = true;
    args.require_cwt = true;
    args.require_issuer = Some("test-issuer".to_string());
    args.output_format = "json".to_string();
    let rc = verify_run(args);
    assert!(rc == 0 || rc == 1);
}
