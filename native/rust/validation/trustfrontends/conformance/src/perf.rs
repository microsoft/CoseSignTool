// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Statistical p99 measurement for §6.5.10 #4 (bounded runtime).
//!
//! The perf gate has two implementations:
//!
//! - **Built-in** (`#[test]`-style, always on): hand-rolled
//!   [`std::time::Instant`] sampling, nearest-rank p99, asserts ≤ 10 ms.
//!   See [`measure_p99`].
//! - **Criterion bench** (opt-in via the `criterion-perf` feature): richer
//!   reporting, regression history, HTML output. See `benches/translate_p99.rs`.
//!
//! Both consume the same fixture
//! (`fixtures/perf/representative_1kb.coseTrustPolicy.json`) and apply the
//! same warm-up + sample-count knobs ([`PERF_WARMUP_COUNT`],
//! [`PERF_SAMPLE_COUNT`]).
//!
//! # Why a built-in measurement instead of "criterion always"?
//!
//! Criterion is a dev-dependency-only crate (per `allowed-dependencies.toml`'s
//! `[dev]` tier). Pulling it into `[dependencies]` so default `cargo test`
//! could exercise the perf gate would (a) bloat the dependency graph for
//! every consumer of the conformance crate, and (b) violate the per-crate
//! allowlist invariant. The `criterion-perf` feature gates the dependency
//! cleanly. The built-in measurement keeps the gate always-on with zero
//! external surface.

use std::time::{Duration, Instant};

/// Number of warm-up iterations executed before any sample is recorded.
///
/// The first translate pays for the lazily-compiled embedded JSON-Schema
/// validator (the `OnceLock` initialiser). We discard it and a few more
/// runs so the steady-state sample is not skewed by one-time setup costs.
pub const PERF_WARMUP_COUNT: usize = 16;

/// Number of timed samples taken per measurement.
///
/// 256 keeps the run cheap (< 1 s on any halfway-modern CPU) while still
/// giving the nearest-rank p99 enough resolution. Each measurement is one
/// translate of a ≤ 1 KiB document.
pub const PERF_SAMPLE_COUNT: usize = 256;

/// Tightened p99 target for §6.5.10 #4.
///
/// Phase 2's smoke test asserts ≤ 50 ms (loose, single-shot). Phase 4
/// tightens to ≤ 10 ms p99 over [`PERF_SAMPLE_COUNT`] samples. Frontends
/// that miss this gate are NOT ship-eligible — anti-deferral rule from the
/// dispatch contract.
pub const PERF_TARGET_P99_MILLIS: u64 = 10;

/// Snapshot of one [`measure_p99`] call.
///
/// Surfaced so callers can attach the figures to assertion messages or log
/// them for trend analysis on slow CI agents.
#[derive(Clone, Debug)]
pub struct PerfMeasurement {
    /// Number of warm-up iterations executed (always [`PERF_WARMUP_COUNT`]).
    pub warmup_count: usize,
    /// Number of timed samples (always [`PERF_SAMPLE_COUNT`]).
    pub sample_count: usize,
    /// p99 of the timed samples computed via the nearest-rank method.
    pub p99: Duration,
    /// Mean of the timed samples — diagnostic only, not gated.
    pub mean: Duration,
    /// Maximum sample observed — diagnostic only, not gated.
    pub max: Duration,
    /// Minimum sample observed — diagnostic only, not gated.
    pub min: Duration,
}

/// Run `f` `[PERF_WARMUP_COUNT] + [PERF_SAMPLE_COUNT]` times, discarding
/// warm-up runs, and return the resulting [`PerfMeasurement`].
///
/// `f` SHOULD be the smallest closure that captures the work being
/// measured (typically `frontend.translate(doc.clone(), &ctx)`); the harness
/// is intentionally allocation-tolerant — a few microseconds of `clone()` is
/// inside the noise floor for the 10 ms target.
pub fn measure_p99<F>(mut f: F) -> PerfMeasurement
where
    F: FnMut(),
{
    for _ in 0..PERF_WARMUP_COUNT {
        f();
    }

    let mut samples: Vec<Duration> = Vec::with_capacity(PERF_SAMPLE_COUNT);
    for _ in 0..PERF_SAMPLE_COUNT {
        let start = Instant::now();
        f();
        samples.push(start.elapsed());
    }

    samples.sort();
    let p99 = nearest_rank_percentile(&samples, 99);
    let mean = samples.iter().copied().sum::<Duration>() / samples.len() as u32;
    let max = samples.last().copied().unwrap_or_default();
    let min = samples.first().copied().unwrap_or_default();

    PerfMeasurement {
        warmup_count: PERF_WARMUP_COUNT,
        sample_count: PERF_SAMPLE_COUNT,
        p99,
        mean,
        max,
        min,
    }
}

/// Nearest-rank percentile over an already-sorted slice of [`Duration`]s.
///
/// Uses [`usize::div_ceil`] so the rank computation is `ceil(pct/100 * n)` for
/// any 0 ≤ pct ≤ 100 — the canonical nearest-rank formula. The conformance
/// harness only calls this with `pct = 99`, but the helper is generic and
/// unit-tested across the percentile range.
///
/// Exposed for direct unit testing (the no-tests-in-src gate forbids in-line
/// `#[cfg(test)]` modules under `src/`; integration tests in `tests/` cover
/// this helper end-to-end).
///
/// Returns [`Duration::ZERO`] for an empty input.
pub fn nearest_rank_percentile(sorted: &[Duration], pct: u32) -> Duration {
    debug_assert!(pct <= 100);
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let n = sorted.len();
    let rank = (pct as usize * n).div_ceil(100);
    let idx = rank.saturating_sub(1).min(n - 1);
    sorted[idx]
}
