// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Final coverage-gap tests for cose_sign1_cli.
//!
//! Covers: inspect (format_header_value, format_timestamp, alg_name),
//! sign (CWT encoding, unknown provider, cert chain embedding),
//! providers/signing (PFX, PEM, ephemeral error paths),
//! providers/verification (construction), and
//! output formatting.

#![cfg(feature = "crypto-openssl")]

use std::fs;
use std::path::PathBuf;

use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use tempfile::TempDir;

use cose_sign1_cli::commands::{inspect, sign};
use cose_sign1_cli::providers::output::{OutputFormat, render};
use cose_sign1_cli::providers::signing::*;
use cose_sign1_cli::providers::{SigningProvider, SigningProviderArgs};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tmp() -> TempDir {
    TempDir::new().expect("temp dir")
}

fn write_ec_key(path: &std::path::Path) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ec = EcKey::generate(&group).unwrap();
    let pkey = PKey::from_ec_key(ec).unwrap();
    fs::write(path, pkey.private_key_to_der().unwrap()).unwrap();
}

fn sign_message(td: &TempDir, detached: bool, issuer: Option<&str>, cwt_sub: Option<&str>) -> PathBuf {
    let key = td.path().join("key.der");
    let payload = td.path().join("payload.bin");
    let output = td.path().join("msg.cose");
    write_ec_key(&key);
    fs::write(&payload, b"hello world").unwrap();
    let args = sign::SignArgs {
        input: payload,
        output: output.clone(),
        provider: "der".into(),
        key: Some(key),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".into(),
        key_size: None,
        content_type: "application/octet-stream".into(),
        format: "direct".into(),
        detached,
        issuer: issuer.map(String::from),
        cwt_subject: cwt_sub.map(String::from),
        output_format: "quiet".into(),
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
    };
    assert_eq!(sign::run(args), 0, "signing must succeed");
    output
}

// ---------------------------------------------------------------------------
// sign.rs — unknown provider error path
// ---------------------------------------------------------------------------

#[test]
fn sign_unknown_provider_returns_error() {
    let td = tmp();
    let payload = td.path().join("payload.bin");
    let output = td.path().join("out.cose");
    fs::write(&payload, b"data").unwrap();

    let args = sign::SignArgs {
        input: payload,
        output,
        provider: "does-not-exist".into(),
        key: None,
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".into(),
        key_size: None,
        content_type: "application/octet-stream".into(),
        format: "direct".into(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "quiet".into(),
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
    };
    assert_eq!(sign::run(args), 2);
}

// ---------------------------------------------------------------------------
// sign.rs — payload read error (nonexistent file)
// ---------------------------------------------------------------------------

#[test]
fn sign_missing_payload_file_returns_error() {
    let td = tmp();
    let key = td.path().join("key.der");
    write_ec_key(&key);
    let args = sign::SignArgs {
        input: td.path().join("nonexistent_payload.bin"),
        output: td.path().join("out.cose"),
        provider: "der".into(),
        key: Some(key),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".into(),
        key_size: None,
        content_type: "text/plain".into(),
        format: "direct".into(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "quiet".into(),
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
    };
    assert_eq!(sign::run(args), 2);
}

// ---------------------------------------------------------------------------
// sign.rs — CWT claims encoding: signing with issuer + subject
// ---------------------------------------------------------------------------

#[test]
fn sign_with_cwt_issuer_and_subject_succeeds() {
    let td = tmp();
    let cose = sign_message(&td, false, Some("did:x509:issuer"), Some("my-subject"));
    assert!(cose.exists());
    let bytes = fs::read(&cose).unwrap();
    assert!(bytes.len() > 10, "COSE message should have content");
}

// ---------------------------------------------------------------------------
// sign.rs — detached signature
// ---------------------------------------------------------------------------

#[test]
fn sign_detached_creates_null_payload_cose() {
    let td = tmp();
    let cose = sign_message(&td, true, None, None);
    assert!(cose.exists());
}

// ---------------------------------------------------------------------------
// sign.rs — output format variants (text, json)
// ---------------------------------------------------------------------------

#[test]
fn sign_text_output_format() {
    let td = tmp();
    let key = td.path().join("key.der");
    let payload = td.path().join("p.bin");
    let output = td.path().join("o.cose");
    write_ec_key(&key);
    fs::write(&payload, b"data").unwrap();
    let args = sign::SignArgs {
        input: payload,
        output,
        provider: "der".into(),
        key: Some(key),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".into(),
        key_size: None,
        content_type: "application/octet-stream".into(),
        format: "direct".into(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "text".into(),
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
    };
    assert_eq!(sign::run(args), 0);
}

#[test]
fn sign_json_output_format() {
    let td = tmp();
    let key = td.path().join("key.der");
    let payload = td.path().join("p.bin");
    let output = td.path().join("o.cose");
    write_ec_key(&key);
    fs::write(&payload, b"data").unwrap();
    let args = sign::SignArgs {
        input: payload,
        output,
        provider: "der".into(),
        key: Some(key),
        pfx: None,
        pfx_password: None,
        cert_file: None,
        key_file: None,
        subject: None,
        algorithm: "ecdsa".into(),
        key_size: None,
        content_type: "application/octet-stream".into(),
        format: "direct".into(),
        detached: false,
        issuer: None,
        cwt_subject: None,
        output_format: "json".into(),
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
    };
    assert_eq!(sign::run(args), 0);
}

// ---------------------------------------------------------------------------
// inspect.rs — format_header_value covered via real COSE messages with headers
// ---------------------------------------------------------------------------

#[test]
fn inspect_with_cwt_claims_present_covers_timestamp_format() {
    let td = tmp();
    let cose = sign_message(&td, false, Some("test-iss"), Some("test-sub"));
    let args = inspect::InspectArgs {
        input: cose,
        output_format: "text".into(),
        all_headers: true,
        show_certs: false,
        show_signature: true,
        show_cwt: true,
    };
    assert_eq!(inspect::run(args), 0);
}

#[test]
fn inspect_detached_shows_detached_label() {
    let td = tmp();
    let cose = sign_message(&td, true, None, None);
    let args = inspect::InspectArgs {
        input: cose,
        output_format: "text".into(),
        all_headers: true,
        show_certs: true,
        show_signature: true,
        show_cwt: false,
    };
    assert_eq!(inspect::run(args), 0);
}

#[test]
fn inspect_nonexistent_file_returns_error() {
    let args = inspect::InspectArgs {
        input: PathBuf::from("__nonexistent_file__.cose"),
        output_format: "text".into(),
        all_headers: false,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    assert_eq!(inspect::run(args), 2);
}

#[test]
fn inspect_json_output_with_all_sections() {
    let td = tmp();
    let cose = sign_message(&td, false, Some("iss"), Some("sub"));
    let args = inspect::InspectArgs {
        input: cose,
        output_format: "json".into(),
        all_headers: true,
        show_certs: true,
        show_signature: true,
        show_cwt: true,
    };
    assert_eq!(inspect::run(args), 0);
}

#[test]
fn inspect_quiet_produces_no_crash() {
    let td = tmp();
    let cose = sign_message(&td, false, None, None);
    let args = inspect::InspectArgs {
        input: cose,
        output_format: "quiet".into(),
        all_headers: true,
        show_certs: false,
        show_signature: false,
        show_cwt: false,
    };
    assert_eq!(inspect::run(args), 0);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — DER provider error: missing --key
// ---------------------------------------------------------------------------

#[test]
fn der_provider_missing_key_errors() {
    let provider = DerKeySigningProvider;
    let args = SigningProviderArgs::default();
    let result = provider.create_signer(&args);
    let msg = result.err().expect("should be error").to_string();
    assert!(msg.contains("--key"), "Expected --key error: {}", msg);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — DER provider error: nonexistent key file
// ---------------------------------------------------------------------------

#[test]
fn der_provider_nonexistent_key_errors() {
    let provider = DerKeySigningProvider;
    let args = SigningProviderArgs {
        key_path: Some(PathBuf::from("__no_such_key__.der")),
        ..Default::default()
    };
    let result = provider.create_signer(&args);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// providers/signing.rs — PFX provider: missing pfx path
// ---------------------------------------------------------------------------

#[test]
fn pfx_provider_missing_path_errors() {
    let provider = PfxSigningProvider;
    let args = SigningProviderArgs::default();
    let result = provider.create_signer(&args);
    let msg = result.err().expect("should be error").to_string();
    assert!(msg.contains("--pfx") || msg.contains("--key"), "Expected path error: {}", msg);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — PFX provider: invalid PFX file
// ---------------------------------------------------------------------------

#[test]
fn pfx_provider_invalid_pfx_errors() {
    let td = tmp();
    let pfx_path = td.path().join("bad.pfx");
    fs::write(&pfx_path, b"not-a-pfx-file").unwrap();

    let provider = PfxSigningProvider;
    let args = SigningProviderArgs {
        pfx_path: Some(pfx_path),
        pfx_password: Some("pass".into()),
        ..Default::default()
    };
    let result = provider.create_signer(&args);
    let msg = result.err().expect("should be error").to_string();
    assert!(msg.contains("Invalid PFX") || msg.contains("parse"), "Expected PFX error: {}", msg);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — PFX provider: --key fallback
// ---------------------------------------------------------------------------

#[test]
fn pfx_provider_uses_key_as_fallback_path() {
    let td = tmp();
    let pfx_path = td.path().join("bad.pfx");
    fs::write(&pfx_path, b"not-a-pfx-file").unwrap();

    let provider = PfxSigningProvider;
    let args = SigningProviderArgs {
        key_path: Some(pfx_path),
        ..Default::default()
    };
    let result = provider.create_signer(&args);
    // Will fail because the file is not a valid PFX, but should NOT fail on missing path
    let msg = result.err().expect("should be error").to_string();
    assert!(!msg.contains("--pfx or --key is required"), "Should have found key_path fallback: {}", msg);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — PEM provider: missing key-file
// ---------------------------------------------------------------------------

#[test]
fn pem_provider_missing_key_file_errors() {
    let provider = PemSigningProvider;
    let args = SigningProviderArgs::default();
    let result = provider.create_signer(&args);
    let msg = result.err().expect("should be error").to_string();
    assert!(msg.contains("--key-file"), "Expected --key-file error: {}", msg);
}

// ---------------------------------------------------------------------------
// providers/signing.rs — PEM provider: invalid PEM
// ---------------------------------------------------------------------------

#[test]
fn pem_provider_invalid_pem_errors() {
    let td = tmp();
    let pem_path = td.path().join("bad.pem");
    fs::write(&pem_path, b"NOT A PEM").unwrap();

    let provider = PemSigningProvider;
    let args = SigningProviderArgs {
        key_file: Some(pem_path),
        ..Default::default()
    };
    let result = provider.create_signer(&args);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// providers/signing.rs — available_providers + find_provider
// ---------------------------------------------------------------------------

#[test]
fn available_providers_includes_der_pfx_pem() {
    let providers = cose_sign1_cli::providers::signing::available_providers();
    let names: Vec<&str> = providers.iter().map(|p| p.name()).collect();
    assert!(names.contains(&"der"), "Should include der");
    assert!(names.contains(&"pfx"), "Should include pfx");
    assert!(names.contains(&"pem"), "Should include pem");
}

#[test]
fn find_provider_returns_some_for_der() {
    let provider = cose_sign1_cli::providers::signing::find_provider("der");
    assert!(provider.is_some());
}

#[test]
fn find_provider_returns_none_for_unknown() {
    let provider = cose_sign1_cli::providers::signing::find_provider("nonexistent");
    assert!(provider.is_none());
}

// ---------------------------------------------------------------------------
// providers/signing.rs — ephemeral provider (requires certificates feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "certificates")]
#[test]
fn ephemeral_provider_default_subject() {
    let provider = EphemeralSigningProvider;
    let args = SigningProviderArgs::default();
    let result = provider.create_signer_with_chain(&args);
    assert!(result.is_ok(), "Ephemeral provider should succeed: {:?}", result.err());
    let swc = result.unwrap();
    assert!(!swc.cert_chain.is_empty(), "Should produce a cert chain");
}

#[cfg(feature = "certificates")]
#[test]
fn ephemeral_provider_custom_subject() {
    let provider = EphemeralSigningProvider;
    let args = SigningProviderArgs {
        subject: Some("CN=MyTest".into()),
        ..Default::default()
    };
    let result = provider.create_signer_with_chain(&args);
    assert!(result.is_ok());
}

#[cfg(feature = "certificates")]
#[test]
fn ephemeral_provider_create_signer_delegates_to_with_chain() {
    let provider = EphemeralSigningProvider;
    let args = SigningProviderArgs::default();
    let result = provider.create_signer(&args);
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// providers/verification.rs — provider listing
// ---------------------------------------------------------------------------

#[test]
fn verification_providers_are_available() {
    let providers = cose_sign1_cli::providers::verification::available_providers();
    assert!(!providers.is_empty(), "At least one verification provider should exist");
    for p in &providers {
        assert!(!p.name().is_empty());
        assert!(!p.description().is_empty());
    }
}

// ---------------------------------------------------------------------------
// providers/output.rs — OutputFormat parsing + render
// ---------------------------------------------------------------------------

#[test]
fn output_format_parse_text() {
    let fmt: OutputFormat = "text".parse().unwrap();
    assert_eq!(fmt, OutputFormat::Text);
}

#[test]
fn output_format_parse_json() {
    let fmt: OutputFormat = "json".parse().unwrap();
    assert_eq!(fmt, OutputFormat::Json);
}

#[test]
fn output_format_parse_quiet() {
    let fmt: OutputFormat = "quiet".parse().unwrap();
    assert_eq!(fmt, OutputFormat::Quiet);
}

#[test]
fn output_format_parse_unknown_errors() {
    let result: Result<OutputFormat, _> = "xml".parse();
    assert!(result.is_err());
}

#[test]
fn output_format_case_insensitive() {
    let fmt: OutputFormat = "TEXT".parse().unwrap();
    assert_eq!(fmt, OutputFormat::Text);
    let fmt: OutputFormat = "Json".parse().unwrap();
    assert_eq!(fmt, OutputFormat::Json);
}

#[test]
fn render_text_format() {
    let mut section = std::collections::BTreeMap::new();
    section.insert("Key1".into(), "Value1".into());
    section.insert("Key2".into(), "Value2".into());
    let rendered = render(OutputFormat::Text, &[("Section".into(), section)]);
    assert!(rendered.contains("Section"));
    assert!(rendered.contains("Key1"));
    assert!(rendered.contains("Value1"));
}

#[test]
fn render_json_format() {
    let mut section = std::collections::BTreeMap::new();
    section.insert("k".into(), "v".into());
    let rendered = render(OutputFormat::Json, &[("S".into(), section)]);
    assert!(rendered.contains('{'));
    assert!(rendered.contains("\"k\""));
}

#[test]
fn render_quiet_is_empty() {
    let mut section = std::collections::BTreeMap::new();
    section.insert("k".into(), "v".into());
    let rendered = render(OutputFormat::Quiet, &[("S".into(), section)]);
    assert!(rendered.is_empty());
}

// ---------------------------------------------------------------------------
// providers/mod.rs — SignerWithChain default (trait default method)
// ---------------------------------------------------------------------------

#[test]
fn der_provider_create_signer_with_chain_returns_empty_chain() {
    let td = tmp();
    let key = td.path().join("key.der");
    write_ec_key(&key);

    let provider = DerKeySigningProvider;
    let args = SigningProviderArgs {
        key_path: Some(key),
        ..Default::default()
    };
    let result = provider.create_signer_with_chain(&args);
    assert!(result.is_ok());
    let swc = result.unwrap();
    assert!(swc.cert_chain.is_empty(), "DER provider should return empty chain");
}

// ---------------------------------------------------------------------------
// providers/mod.rs — SigningProviderArgs default
// ---------------------------------------------------------------------------

#[test]
fn signing_provider_args_default_fields() {
    let args = SigningProviderArgs::default();
    assert!(args.key_path.is_none());
    assert!(args.pfx_path.is_none());
    assert!(args.pfx_password.is_none());
    assert!(args.cert_file.is_none());
    assert!(args.key_file.is_none());
    assert!(args.subject.is_none());
    assert!(args.vault_url.is_none());
    assert!(!args.pqc);
    assert!(!args.minimal);
}
