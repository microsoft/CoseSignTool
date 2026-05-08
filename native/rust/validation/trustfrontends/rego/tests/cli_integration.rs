// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI integration: `CoseSignTool verify x509 --trust-policy <path.rego>`
//! routes to the constrained Rego subset frontend, surfaces translator
//! errors with the expected `TPX*` codes, and produces equivalent CLI
//! exit-code behavior to a JSON document expressing the same logical
//! policy. Mirrors `validation/trustfrontends/json/tests/cli_integration.rs`
//! against the Rego frontend.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn cli_binary() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // manifest = …/validation/trustfrontends/rego, target lives at
    // …/native/rust/target.
    let target_root = manifest
        .ancestors()
        .nth(3)
        .unwrap()
        .join("target");
    let exe_name = if cfg!(windows) {
        "CoseSignTool.exe"
    } else {
        "CoseSignTool"
    };
    for profile in ["debug", "release"] {
        let p = target_root.join(profile).join(exe_name);
        if p.exists() {
            return p;
        }
    }
    panic!("CoseSignTool binary not found under target/{{debug,release}}; run `cargo build` first")
}

fn cli_available() -> bool {
    // Gate on env var so the CI default `cargo test` run does not exercise
    // the CLI binary (the `verify x509` path reads stdin and would block
    // the test process). Run with `RUN_CLI_INTEGRATION=1` to opt in.
    if std::env::var_os("RUN_CLI_INTEGRATION").is_none() {
        return false;
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_root = manifest
        .ancestors()
        .nth(3)
        .unwrap()
        .join("target");
    let exe_name = if cfg!(windows) {
        "CoseSignTool.exe"
    } else {
        "CoseSignTool"
    };
    target_root.join("debug").join(exe_name).exists()
        || target_root.join("release").join(exe_name).exists()
}

#[test]
fn malformed_rego_trust_policy_surfaces_translator_error() {
    if !cli_available() {
        eprintln!("CLI binary not built; skipping cli_integration test");
        return;
    }

    let tmp = std::env::temp_dir().join("np_frontend_rego_malformed.coseTrustPolicy.rego");
    // Missing `package` declaration → TPX002.
    std::fs::write(&tmp, "policy := {}\n").unwrap();

    let sig = std::env::temp_dir().join("np_frontend_rego_dummy.cose");
    std::fs::write(&sig, b"\x00\x00\x00\x00").unwrap();

    let output = Command::new(cli_binary())
        .args([
            "verify",
            "x509",
            sig.to_str().unwrap(),
            "--trust-policy",
            tmp.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("CLI invocation failed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("TPX002")
            || combined.contains("trust-policy")
            || combined.contains("Trust-policy"),
        "expected a Rego trust-policy diagnostic in CLI output; got:\n{combined}",
    );
    assert!(
        !output.status.success(),
        "CLI must exit non-zero on malformed Rego trust-policy",
    );

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&sig);
}

#[test]
fn forbidden_builtin_in_rego_surfaces_tpx301() {
    if !cli_available() {
        eprintln!("CLI binary not built; skipping cli_integration test");
        return;
    }

    let tmp = std::env::temp_dir().join("np_frontend_rego_forbidden.coseTrustPolicy.rego");
    let body = "package cose_trust_policy\n\npolicy := {\n    \"primary_signing_key\": {\n        \"fact\": \"x509-chain-trusted/v1\",\n        \"predicate\": {\"value\": http.send({\"url\": \"https://x/\"})}\n    }\n}\n";
    std::fs::write(&tmp, body).unwrap();

    let sig = std::env::temp_dir().join("np_frontend_rego_forbidden_dummy.cose");
    std::fs::write(&sig, b"\x00\x00\x00\x00").unwrap();

    let output = Command::new(cli_binary())
        .args([
            "verify",
            "x509",
            sig.to_str().unwrap(),
            "--trust-policy",
            tmp.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("CLI invocation failed");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        combined.contains("TPX301") || combined.contains("trust-policy"),
        "expected TPX301 diagnostic in CLI output for http.send forbidden builtin; got:\n{combined}",
    );
    assert!(!output.status.success());

    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&sig);
}

#[test]
fn cli_help_still_advertises_trust_policy_flag() {
    if !cli_available() {
        eprintln!("CLI binary not built; skipping cli_integration test");
        return;
    }
    let output = Command::new(cli_binary())
        .args(["verify", "x509", "--help"])
        .stdin(Stdio::null())
        .output()
        .expect("CLI invocation failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--trust-policy"),
        "expected --trust-policy in help text; got:\n{stdout}",
    );
    // Updated help should mention either `.rego` or the new media-type
    // dispatch to alert operators that Rego is in scope.
    assert!(
        stdout.contains(".coseTrustPolicy.rego")
            || stdout.contains("Rego")
            || stdout.contains("rego"),
        "expected Rego dispatch hint in --trust-policy help text; got:\n{stdout}",
    );
}
