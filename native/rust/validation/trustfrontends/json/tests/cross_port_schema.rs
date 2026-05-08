// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-port consistency lock (D7): the embedded schema bytes must match the .NET
//! schema at V2/schemas/cose-tp/v1.json after platform line-ending normalization.
//!
//! The test invokes `git show origin/users/jstatia/v2_clean_slate:V2/schemas/cose-tp/v1.json`
//! to fetch the .NET source; in CI the integration branch hosts both copies.
//!
//! This test is the cross-port consistency anchor — drift in either copy is a CI gate
//! failure.

use cose_sign1_trustfrontends_json::embedded_schema_bytes;
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
}

fn normalize_line_endings(bytes: &[u8]) -> Vec<u8> {
    // Drop CR characters so CRLF and LF compare equal.
    bytes.iter().copied().filter(|b| *b != b'\r').collect()
}

#[test]
fn embedded_schema_matches_local_disk_copy() {
    let on_disk_path = workspace_root().join("schemas").join("cose-tp").join("v1.json");
    let on_disk = std::fs::read(&on_disk_path)
        .expect("on-disk schema must be present (build-time include_bytes! anchor)");
    assert_eq!(
        normalize_line_endings(embedded_schema_bytes()),
        normalize_line_endings(&on_disk),
        "embedded schema and on-disk schema diverged — rebuild after `git checkout`"
    );
}

#[test]
fn embedded_schema_matches_dotnet_source() {
    // The .NET schema is committed at V2/schemas/cose-tp/v1.json on the
    // users/jstatia/v2_clean_slate branch. Either commit ref works as long as the file
    // is reachable; we try the integration ref first, fall back to a known commit.
    //
    // Skipping is acceptable when the test is run outside a git checkout (e.g. crates.io
    // packaging extraction); the on-disk match in `embedded_schema_matches_local_disk_copy`
    // covers in-workspace drift detection in that case.
    let candidates: &[&[&str]] = &[
        &["show", "origin/users/jstatia/v2_clean_slate:V2/schemas/cose-tp/v1.json"],
        &["show", "9d3f0789:V2/schemas/cose-tp/v1.json"],
    ];
    let mut last_err: Option<String> = None;
    for argv in candidates {
        let output = Command::new("git").args(*argv).output();
        match output {
            Ok(out) if out.status.success() => {
                assert_eq!(
                    normalize_line_endings(embedded_schema_bytes()),
                    normalize_line_endings(&out.stdout),
                    "embedded Rust schema and the .NET schema (V2/schemas/cose-tp/v1.json) diverged"
                );
                return;
            }
            Ok(out) => {
                last_err = Some(String::from_utf8_lossy(&out.stderr).into_owned());
            }
            Err(err) => {
                last_err = Some(err.to_string());
            }
        }
    }
    eprintln!(
        "skipping cross-port schema-equivalence test — git not available or schema ref not reachable: {:?}",
        last_err
    );
}
