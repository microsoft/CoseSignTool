// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coverage for the fixture-path helpers in [`cose_sign1_trustfrontends_conformance::fixtures`].
//!
//! The harness functions consume these helpers indirectly; these tests exercise
//! the encode/decode + path-composition surface directly so the round-trip is
//! verified independently of any I/O.

use cose_sign1_trustfrontends_conformance::fixtures::{
    capability_path, cross_golden_ir_path, cross_path, decode_fact_id_from_filename,
    encode_fact_id_for_filename, parametric_path, per_fact_path, perf_path, schema_path,
    untranslatable_path,
};
use cose_sign1_trustfrontends_conformance::{ConformanceAdapter, JsonConformanceAdapter};
use std::path::Path;

#[test]
fn fact_id_filename_round_trip_for_canonical_ids() {
    let canonical = JsonConformanceAdapter::canonical_fact_ids();
    for id in &canonical {
        let encoded = encode_fact_id_for_filename(id);
        assert!(
            !encoded.contains('/'),
            "encoded fact id '{encoded}' must not contain '/'",
        );
        assert!(
            encoded.contains("--"),
            "encoded fact id '{encoded}' must contain the '--' separator",
        );
        let decoded = decode_fact_id_from_filename(&encoded);
        assert_eq!(decoded, *id, "encode→decode must round-trip");
    }
}

#[test]
fn per_fact_path_uses_encoded_stem() {
    let root = Path::new("/tmp/fixtures");
    let path = per_fact_path(root, "x509-chain-trusted/v1", "coseTrustPolicy.json");
    let s = path.to_string_lossy();
    assert!(s.contains("per_fact"));
    assert!(s.contains("x509-chain-trusted--v1.coseTrustPolicy.json"));
    assert!(!s.contains("/v1.coseTrustPolicy.json"));
}

#[test]
fn other_helpers_compose_expected_segments() {
    let root = Path::new("/tmp/fixtures");
    assert!(
        untranslatable_path(root, "free_text_search", "coseTrustPolicy.json")
            .to_string_lossy()
            .contains("untranslatable")
    );
    assert!(
        capability_path(root, "missing_fact", "coseTrustPolicy.json")
            .to_string_lossy()
            .contains("capability")
    );
    assert!(
        schema_path(root, "shape_violation", "coseTrustPolicy.json")
            .to_string_lossy()
            .contains("schema")
    );
    assert!(
        parametric_path(root, "host_baseline", "coseTrustPolicy.json")
            .to_string_lossy()
            .contains("parametric")
    );
    assert!(
        perf_path(root, "coseTrustPolicy.json")
            .to_string_lossy()
            .contains("representative_1kb"),
    );

    let cross = cross_path(root, "canonical_policy", "coseTrustPolicy.json");
    let cross_str = cross.to_string_lossy();
    assert!(cross_str.contains("cross"));
    assert!(cross_str.contains("canonical_policy.coseTrustPolicy.json"));

    let golden = cross_golden_ir_path(root, "canonical_policy");
    assert!(golden
        .to_string_lossy()
        .ends_with("canonical_ir.expected.json"));
}

#[test]
fn json_adapter_advertises_canonical_baseline() {
    let adapter = JsonConformanceAdapter::default();
    let ids = adapter.registered_fact_ids();
    assert_eq!(
        ids.len(),
        16,
        "JsonConformanceAdapter::default must advertise the 16-fact canonical baseline",
    );
    assert!(ids.contains("x509-chain-trusted/v1"));
    assert!(ids.contains("mst-receipt-present/v1"));
    assert!(ids.contains("content-type/v1"));
}

#[test]
fn json_adapter_with_custom_fact_ids_overrides_baseline() {
    let mut custom = std::collections::BTreeSet::new();
    custom.insert("x509-chain-trusted/v1".to_string());
    let adapter = JsonConformanceAdapter::with_fact_ids(custom.clone());
    assert_eq!(adapter.registered_fact_ids(), custom);
}

#[test]
fn json_adapter_extension_and_fixture_root_resolve() {
    let adapter = JsonConformanceAdapter::default();
    assert_eq!(adapter.fixture_extension(), "coseTrustPolicy.json");
    let root = adapter.fixture_root();
    assert!(root.exists(), "fixture root must exist on disk: {}", root.display());
    assert!(root.is_dir(), "fixture root must be a directory");
}
