// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cross-port canonical-IR equivalence test (Phase 4 deliverable).
//!
//! Phase 2 already includes `cross_port_schema.rs` (in the JSON frontend
//! crate) which asserts the embedded `cose-tp/v1.json` schema is byte-equal
//! between the Rust and .NET copies. Phase 4 adds a stronger lock: parsing
//! the canonical cross-fixture with the Rust JSON frontend MUST produce
//! canonical-IR JSON that is byte-equal to the committed
//! `canonical_ir.expected.json` golden file (which itself was produced by
//! the .NET frontend on the same fixture).
//!
//! When (a) is preferred over (b) (running .NET at test time):
//!
//! - The golden file makes the cross-port lock visible in the diff — any IR
//!   shape change is one git-diff line.
//! - The Rust CI doesn't need .NET available.
//! - The .NET train owns the regeneration story when its frontend ships;
//!   when the Rust IR shape changes, the Rust train regenerates the golden
//!   and the .NET train confirms equality on its side.
//!
//! Regenerate the golden via the `regenerate_golden` ignored test below.

use cose_sign1_trust_policy_spec::{to_canonical_pretty, TrustPolicyTranslationContext};
use cose_sign1_trustfrontends_conformance::fixtures::{cross_golden_ir_path, cross_path};
use cose_sign1_trustfrontends_conformance::{ConformanceAdapter, JsonConformanceAdapter};

const CROSS_BASE: &str = "canonical_policy";

#[test]
fn rust_canonical_ir_matches_golden() {
    let adapter = JsonConformanceAdapter::default();
    let fixture_root = adapter.fixture_root();
    let fixture = cross_path(&fixture_root, CROSS_BASE, adapter.fixture_extension());
    let golden = cross_golden_ir_path(&fixture_root, CROSS_BASE);

    let frontend = adapter.create_frontend();
    let document = adapter.load_document(&fixture);
    let result = frontend.translate(document, &TrustPolicyTranslationContext::empty());
    let spec = result
        .spec
        .expect("cross-port fixture should translate without errors");
    let actual = to_canonical_pretty(&spec).expect("encode canonical IR");

    let expected = std::fs::read_to_string(&golden)
        .expect("golden cross-port IR file must be committed alongside the fixture");

    let actual_norm = normalize_line_endings(&actual);
    let expected_norm = normalize_line_endings(&expected);

    assert_eq!(
        actual_norm.trim_end(),
        expected_norm.trim_end(),
        "Rust canonical-IR output diverges from the committed cross-port \
         golden ({}). Either the Rust IR shape changed (regenerate the \
         golden via `cargo test -p cose_sign1_trustfrontends_conformance \
         regenerate_golden -- --ignored`) or the .NET copy needs to follow.",
        golden.display(),
    );
}

#[test]
#[ignore = "Run with --ignored to regenerate the cross-port golden file after an intentional IR change."]
fn regenerate_golden() {
    let adapter = JsonConformanceAdapter::default();
    let fixture_root = adapter.fixture_root();
    let fixture = cross_path(&fixture_root, CROSS_BASE, adapter.fixture_extension());
    let golden = cross_golden_ir_path(&fixture_root, CROSS_BASE);

    let frontend = adapter.create_frontend();
    let document = adapter.load_document(&fixture);
    let result = frontend.translate(document, &TrustPolicyTranslationContext::empty());
    let spec = result.spec.expect("translate");
    let canonical = to_canonical_pretty(&spec).expect("encode");

    std::fs::write(&golden, format!("{canonical}\n")).expect("write golden");
    eprintln!("regenerated cross-port golden at {}", golden.display());
}

fn normalize_line_endings(s: &str) -> String {
    s.replace("\r\n", "\n")
}
