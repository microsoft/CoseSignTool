// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Criterion harness for §6.5.10 #4 (bounded runtime).
//!
//! Opt-in via the `criterion-perf` feature:
//!
//! ```text
//! cargo bench -p cose_sign1_trustfrontends_conformance --features criterion-perf
//! ```
//!
//! Default `cargo test` does NOT compile this file — the `required-features`
//! gate in Cargo.toml gates the entire bench target on `criterion-perf`.
//!
//! The Criterion harness gives richer reporting + regression history than the
//! built-in `measure_p99` helper. Both run the same fixture, so a Criterion
//! regression and a built-in test failure point at the same root cause.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use cose_sign1_trust_policy_spec::TrustPolicyTranslationContext;
use cose_sign1_trustfrontends_conformance::{ConformanceAdapter, JsonConformanceAdapter};
use cose_sign1_trustfrontends_conformance::fixtures::perf_path;

fn bench_translate_p99(c: &mut Criterion) {
    let adapter = JsonConformanceAdapter::default();
    let path = perf_path(&adapter.fixture_root(), adapter.fixture_extension());
    let frontend = adapter.create_frontend();
    let ctx = TrustPolicyTranslationContext::empty();

    c.bench_function("translate_1kb_representative", |b| {
        b.iter(|| {
            let document = adapter.load_document(&path);
            let result = frontend.translate(black_box(document), black_box(&ctx));
            black_box(result);
        });
    });
}

criterion_group!(benches, bench_translate_p99);
criterion_main!(benches);
