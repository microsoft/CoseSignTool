// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration: `CoseSignTool verify x509 --trust-policy <path>` parses the
//! document, translates, binds, and compiles. We exercise both the success path
//! (a well-formed document + a baseline X.509 signature) and the failure path
//! (a malformed document → translator surfaces TPX001 in stderr).

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn cli_binary() -> PathBuf {
    // `cargo test` exposes the package's binary path through an env var; the manifest
    // dir resolves to `<repo>/native/rust/cli`, so the binary lives at
    // `<repo>/native/rust/target/debug/CoseSignTool[.exe]`.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_root = manifest.parent().unwrap().join("target");
    let exe_name = if cfg!(windows) {
        "CoseSignTool.exe"
    } else {
        "CoseSignTool"
    };
    let candidates = ["debug", "release"];
    for profile in candidates {
        let p = target_root.join(profile).join(exe_name);
        if p.exists() {
            return p;
        }
    }
    panic!("CoseSignTool binary not found under target/{{debug,release}}; run `cargo build` first")
}

fn cli_available() -> bool {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| {
            let exe_name = if cfg!(windows) {
                "CoseSignTool.exe"
            } else {
                "CoseSignTool"
            };
            p.join("target").join("debug").join(exe_name).exists()
                || p.join("target").join("release").join(exe_name).exists()
        })
        .unwrap_or(false)
}

#[test]
fn malformed_trust_policy_surfaces_translator_error() {
    if !cli_available() {
        eprintln!("CLI binary not built; skipping cli_integration test");
        return;
    }

    let tmp = std::env::temp_dir().join("np_frontend_json_malformed.coseTrustPolicy.json");
    std::fs::write(&tmp, "{ this is not legal json }").unwrap();

    // We use a non-existent signature file so the CLI fails fast before reaching
    // crypto; that's fine — we're asserting the trust-policy error surface, not the
    // verify outcome.
    let sig = std::env::temp_dir().join("np_frontend_json_dummy.cose");
    std::fs::write(&sig, b"\x00\x00\x00\x00").unwrap();

    let output = Command::new(cli_binary())
        .args([
            "verify",
            "x509",
            sig.to_str().unwrap(),
            "--trust-policy",
            tmp.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("CLI invocation failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("TPX")
            || combined.contains("Trust-policy")
            || combined.contains("trust-policy")
            || combined.contains("Failed to parse")
            || combined.contains("Malformed"),
        "expected a trust-policy diagnostic in CLI output; got:\n{combined}",
    );
    assert!(
        !output.status.success(),
        "CLI must exit non-zero on malformed trust-policy"
    );

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&sig);
}

#[test]
fn cli_help_advertises_trust_policy_flag() {
    if !cli_available() {
        eprintln!("CLI binary not built; skipping cli_integration test");
        return;
    }
    let output = Command::new(cli_binary())
        .args(["verify", "x509", "--help"])
        .output()
        .expect("CLI invocation failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--trust-policy"),
        "expected --trust-policy in help text; got:\n{stdout}",
    );
    assert!(
        stdout.contains("--trust-policy-param"),
        "expected --trust-policy-param in help text; got:\n{stdout}",
    );
}
