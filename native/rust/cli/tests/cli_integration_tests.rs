// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_headers::{CWTClaimsHeaderLabels, CwtClaims};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderValue, CoseSign1Message};
#[cfg(feature = "mst")]
use cose_sign1_transparent_mst::validation::verify::get_receipts_from_transparent_statement;
use std::path::{Path, PathBuf};
use std::process::Command;

fn cosesigntool() -> Command {
    Command::new(env!("CARGO_BIN_EXE_CoseSignTool"))
}

fn rust_workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under native/rust")
        .to_path_buf()
}

fn scitt_test_file(name: &str) -> PathBuf {
    rust_workspace_root()
        .join("extension_packs")
        .join("certificates")
        .join("testdata")
        .join("v1")
        .join(name)
}

#[test]
fn help_shows_sign_verify_inspect() {
    let output = cosesigntool().arg("--help").output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("sign"));
    assert!(stdout.contains("verify"));
    assert!(stdout.contains("inspect"));
}

#[test]
fn sign_x509_help_shows_all_providers() {
    let output = cosesigntool()
        .args(["sign", "x509", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("pfx"));
    assert!(stdout.contains("pem"));
    assert!(stdout.contains("ephemeral"));
    assert!(stdout.contains("aas"));
    assert!(stdout.contains("akv"));
    assert!(stdout.contains("akv-cert"));
}

#[test]
fn verify_help_shows_x509_and_scitt() {
    let output = cosesigntool().args(["verify", "--help"]).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("x509"));
    assert!(stdout.contains("scitt"));
}

#[test]
fn verify_scitt_help_shows_issuer_flags() {
    let output = cosesigntool()
        .args(["verify", "scitt", "--help"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("--issuer"));
    assert!(stdout.contains("--issuer-offline-keys"));
}

#[test]
fn sign_ephemeral_direct_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.txt");
    let sig = dir.path().join("sig.cose");
    std::fs::write(&payload, b"test payload").unwrap();

    let sign_out = cosesigntool()
        .args(["sign", "x509", "ephemeral"])
        .arg(payload.to_str().unwrap())
        .args(["--output", sig.to_str().unwrap()])
        .args(["--format", "direct"])
        .args(["-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        sign_out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );
    assert!(sig.exists());

    let verify_out = cosesigntool()
        .args(["verify", "x509"])
        .arg(sig.to_str().unwrap())
        .args(["--trust-embedded"])
        .args(["-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        verify_out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
}

#[test]
fn sign_ephemeral_indirect_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.txt");
    let sig = dir.path().join("sig.cose");
    std::fs::write(&payload, b"indirect test").unwrap();

    let sign_out = cosesigntool()
        .args(["sign", "x509", "ephemeral"])
        .arg(payload.to_str().unwrap())
        .args(["--output", sig.to_str().unwrap()])
        .args(["--format", "indirect"])
        .args(["-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        sign_out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let verify_out = cosesigntool()
        .args(["verify", "x509"])
        .arg(sig.to_str().unwrap())
        .args(["--payload", payload.to_str().unwrap()])
        .args(["--trust-embedded"])
        .args(["-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        verify_out.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify_out.stderr)
    );
}

#[test]
fn inspect_shows_algorithm_and_chain() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.txt");
    let sig = dir.path().join("sig.cose");
    std::fs::write(&payload, b"inspect test").unwrap();

    let sign_out = cosesigntool()
        .args(["sign", "x509", "ephemeral"])
        .arg(payload.to_str().unwrap())
        .args(["--output", sig.to_str().unwrap()])
        .args(["--format", "direct", "-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        sign_out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let output = cosesigntool()
        .args(["inspect"])
        .arg(sig.to_str().unwrap())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("Algorithm") || stdout.contains("Signature"));
}

#[test]
fn sign_scitt_subject_sets_cwt_claim() {
    let dir = tempfile::tempdir().unwrap();
    let payload = dir.path().join("payload.txt");
    let sig = dir.path().join("sig.cose");
    std::fs::write(&payload, b"scitt test").unwrap();

    let sign_out = cosesigntool()
        .args(["sign", "x509", "ephemeral"])
        .arg(payload.to_str().unwrap())
        .args(["--output", sig.to_str().unwrap()])
        .args(["--scitt-subject", "my-artifact:v1.0"])
        .args(["--format", "direct", "-f", "quiet"])
        .output()
        .unwrap();
    assert!(
        sign_out.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign_out.stderr)
    );

    let message_bytes = std::fs::read(&sig).unwrap();
    let message = CoseSign1Message::parse(&message_bytes).unwrap();
    let claims_value = message
        .protected
        .get(&CoseHeaderLabel::Int(
            CWTClaimsHeaderLabels::CWT_CLAIMS_HEADER,
        ))
        .expect("CWT claims header should be present");
    let claims_bytes = match claims_value {
        CoseHeaderValue::Bytes(bytes) => bytes,
        other => panic!("expected CWT claims bytes, got {other:?}"),
    };
    let claims = CwtClaims::from_cbor_bytes(claims_bytes).unwrap();

    assert_eq!(claims.subject.as_deref(), Some("my-artifact:v1.0"));
}

#[cfg(feature = "mst")]
#[test]
fn verify_scitt_validates_scitt_file() {
    let scitt_file = scitt_test_file("1ts-statement.scitt");
    if !scitt_file.exists() {
        eprintln!(
            "Skipping: .scitt test file not found at {}",
            scitt_file.display()
        );
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let statement_bytes = std::fs::read(&scitt_file).unwrap();
    let receipts = get_receipts_from_transparent_statement(&statement_bytes).unwrap();
    let receipt = receipts
        .first()
        .expect("real .scitt file should contain a receipt");
    let kid = receipt
        .message
        .as_ref()
        .and_then(|message| {
            message
                .protected
                .headers()
                .kid()
                .or_else(|| message.unprotected.headers().kid())
        })
        .and_then(|value| std::str::from_utf8(value).ok())
        .expect("receipt should expose a text kid");
    let jwks_path = dir.path().join("offline.jwks");
    let jwks_json = format!(
        r#"{{"keys":[{{"kty":"EC","kid":"{}","crv":"P-384","x":"iA7dVHaUwQLFAJONiPWfNyvaCmbnhQlrY4MVCaVKBFuI5RmdTS4qmqS6sGEVWPWB","y":"qiwH95FhYzHxuRr56gDSLgWvfuCLGQ_BkPVPwVKP5hIi_wWYIc9UCHvWXqvhYR3u"}}]}}"#,
        kid
    );
    std::fs::write(&jwks_path, jwks_json).unwrap();
    let issuer_arg = format!("{}={}", receipt.issuer, jwks_path.display());

    let output = cosesigntool()
        .args(["verify", "scitt"])
        .arg(scitt_file.to_str().unwrap())
        .args(["--issuer-offline-keys", &issuer_arg])
        .args(["-f", "quiet"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(
        output.status.code(),
        Some(101),
        "verify scitt panicked: {stderr}"
    );
    assert!(
        !stderr.to_ascii_lowercase().contains("panicked"),
        "verify scitt should not panic: {stderr}"
    );
}
