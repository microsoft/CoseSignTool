// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fixture-path helpers shared across the harness functions.
//!
//! The fixture tree (under [`crate::ConformanceAdapter::fixture_root`]) is
//! organised by §6.5.10 property:
//!
//! ```text
//! fixtures/
//! ├── per_fact/<fact-id-encoded>.<ext>
//! ├── untranslatable/<scenario>.<ext>
//! ├── capability/missing_fact.<ext>
//! ├── schema/<scenario>.<ext>
//! ├── parametric/{host_baseline,host_alternate}.<ext>
//! ├── perf/representative_1kb.<ext>
//! └── cross/<base>/<base>.<ext>
//! ```
//!
//! `<ext>` is the [`crate::ConformanceAdapter::fixture_extension`] string.
//!
//! # Fact-id filename encoding
//!
//! Fact ids contain `/` (e.g. `x509-chain-trusted/v1`) and so cannot land in
//! a filesystem path verbatim. The harness encodes `/` as `--` — the literal
//! sequence is forbidden inside a valid fact id by the
//! `^[a-z][a-z0-9-]*/v[0-9]+$` regex (single dashes are legal but `--`
//! requires two adjacent hyphens, which the pack regex never emits because
//! the version separator is the slash). The encoding is therefore
//! collision-free and round-trippable.

use std::path::{Path, PathBuf};

/// Encode a fact id (e.g. `x509-chain-trusted/v1`) into its filesystem-safe
/// stem (`x509-chain-trusted--v1`).
pub fn encode_fact_id_for_filename(fact_id: &str) -> String {
    fact_id.replace('/', "--")
}

/// Reverse of [`encode_fact_id_for_filename`]: decode a filesystem stem back
/// into the canonical fact id.
pub fn decode_fact_id_from_filename(stem: &str) -> String {
    stem.replace("--", "/")
}

/// Build the path to a per-fact fixture for the given fact id and frontend
/// extension.
pub fn per_fact_path(root: &Path, fact_id: &str, extension: &str) -> PathBuf {
    fixture_path(
        root,
        "per_fact",
        &encode_fact_id_for_filename(fact_id),
        extension,
    )
}

/// Build the path to an `untranslatable/<scenario>` fixture.
pub fn untranslatable_path(root: &Path, scenario: &str, extension: &str) -> PathBuf {
    fixture_path(root, "untranslatable", scenario, extension)
}

/// Build the path to a `capability/<scenario>` fixture.
pub fn capability_path(root: &Path, scenario: &str, extension: &str) -> PathBuf {
    fixture_path(root, "capability", scenario, extension)
}

/// Build the path to a `schema/<scenario>` fixture.
pub fn schema_path(root: &Path, scenario: &str, extension: &str) -> PathBuf {
    fixture_path(root, "schema", scenario, extension)
}

/// Build the path to a `parametric/<scenario>` fixture.
pub fn parametric_path(root: &Path, scenario: &str, extension: &str) -> PathBuf {
    fixture_path(root, "parametric", scenario, extension)
}

/// Build the path to the perf-gate fixture.
pub fn perf_path(root: &Path, extension: &str) -> PathBuf {
    fixture_path(root, "perf", "representative_1kb", extension)
}

/// Build the path to a cross-frontend equivalence fixture.
///
/// `base` is the directory name under `fixtures/cross/`. The harness expects
/// each frontend to ship a sibling document with the matching extension
/// inside that directory — e.g. `cross/canonical_policy/canonical_policy.coseTrustPolicy.json`.
pub fn cross_path(root: &Path, base: &str, extension: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    path.push("cross");
    path.push(base);
    path.push(format!("{base}.{extension}"));
    path
}

/// Build the path to the cross-frontend canonical-IR golden file.
///
/// Phase 4 commits the golden alongside the JSON fixture so the cross-port
/// IR-equivalence test can assert byte-equality without invoking another
/// language runtime.
pub fn cross_golden_ir_path(root: &Path, base: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    path.push("cross");
    path.push(base);
    path.push("canonical_ir.expected.json");
    path
}

fn fixture_path(root: &Path, dir: &str, stem: &str, extension: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    path.push(dir);
    path.push(format!("{stem}.{extension}"));
    path
}

/// Read a fixture file's bytes; panic with a clear message on I/O failure.
pub fn read_fixture(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err| {
        panic!(
            "conformance fixture missing or unreadable: {} ({err})",
            path.display(),
        )
    })
}

/// Read a fixture file as UTF-8 text.
pub fn read_fixture_text(path: &Path) -> String {
    String::from_utf8(read_fixture(path)).unwrap_or_else(|err| {
        panic!("conformance fixture is not UTF-8: {err}",)
    })
}
