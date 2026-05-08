// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Smoke tests that exercise the high-level [`run_conformance_all`] composite
//! and the helper-module surface. The per-property tests in
//! `json_conformance.rs` cover each property in isolation; this file ensures
//! the all-in-one entry point remains green and that loader-error paths panic
//! with diagnostic messages rather than silently mis-routing.

use cose_sign1_trustfrontends_conformance::fixtures::{read_fixture, read_fixture_text};
use cose_sign1_trustfrontends_conformance::{measure_p99, run_conformance_all, JsonConformanceAdapter};
use std::path::PathBuf;

#[test]
fn run_all_passes_with_default_json_adapter() {
    run_conformance_all(&JsonConformanceAdapter::default());
}

#[test]
fn measure_p99_returns_well_formed_measurement() {
    let m = measure_p99(|| {
        let _ = std::hint::black_box(1u64.wrapping_add(2));
    });
    assert_eq!(m.warmup_count, cose_sign1_trustfrontends_conformance::PERF_WARMUP_COUNT);
    assert_eq!(m.sample_count, cose_sign1_trustfrontends_conformance::PERF_SAMPLE_COUNT);
    assert!(m.min <= m.mean);
    assert!(m.mean <= m.max);
    // p99 over the sample set must lie between min and max inclusive.
    assert!(m.p99 >= m.min);
    assert!(m.p99 <= m.max);
}

#[test]
#[should_panic(expected = "conformance fixture missing or unreadable")]
fn read_fixture_panics_with_clear_message_when_missing() {
    let bogus: PathBuf = PathBuf::from("definitely-not-a-fixture-path/nonexistent.json");
    let _ = read_fixture(&bogus);
}

#[test]
#[should_panic(expected = "conformance fixture missing or unreadable")]
fn read_fixture_text_panics_when_missing() {
    let bogus: PathBuf = PathBuf::from("definitely-not-a-fixture-path/nonexistent.json");
    let _ = read_fixture_text(&bogus);
}
