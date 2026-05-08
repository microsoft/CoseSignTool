// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit-level coverage for the percentile helper exposed in [`crate::perf`].
//!
//! The §6.5.10 #4 property test exercises [`crate::measure_p99`] end-to-end;
//! these tests target the smaller helper directly so the percentile maths is
//! verified independently of any frontend.

use cose_sign1_trustfrontends_conformance::nearest_rank_percentile;
use std::time::Duration;

fn millis(values: &[u64]) -> Vec<Duration> {
    values.iter().copied().map(Duration::from_millis).collect()
}

#[test]
fn percentile_on_empty_slice_returns_zero() {
    assert_eq!(nearest_rank_percentile(&[], 99), Duration::ZERO);
    assert_eq!(nearest_rank_percentile(&[], 0), Duration::ZERO);
}

#[test]
fn percentile_on_single_sample_returns_that_sample() {
    let samples = millis(&[42]);
    assert_eq!(
        nearest_rank_percentile(&samples, 0),
        Duration::from_millis(42)
    );
    assert_eq!(
        nearest_rank_percentile(&samples, 50),
        Duration::from_millis(42)
    );
    assert_eq!(
        nearest_rank_percentile(&samples, 100),
        Duration::from_millis(42)
    );
}

#[test]
fn percentile_99_of_100_samples_is_99th_index() {
    // 1..=100 ms; nearest-rank p99 over 100 samples = ceil(99/100 * 100) = 99 → index 98 = 99 ms
    let samples: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
    assert_eq!(
        nearest_rank_percentile(&samples, 99),
        Duration::from_millis(99),
    );
}

#[test]
fn percentile_50_of_10_samples_is_median() {
    let samples = millis(&[10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
    // ceil(50/100 * 10) = 5 → index 4 = 50 ms
    assert_eq!(
        nearest_rank_percentile(&samples, 50),
        Duration::from_millis(50),
    );
}

#[test]
fn percentile_caps_at_last_index() {
    let samples = millis(&[1, 2, 3]);
    assert_eq!(
        nearest_rank_percentile(&samples, 100),
        Duration::from_millis(3),
    );
}
