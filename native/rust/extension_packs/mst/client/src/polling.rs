// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Polling strategy types for MST transparency client operations.
//!
//! When a COSE_Sign1 message is submitted to MST via `create_entry`, the service
//! returns a long-running operation that must be polled until completion. These types
//! let callers tune the polling behavior to balance latency against cost.

use std::time::Duration;

/// Strategy controlling the delay between polling attempts.
#[derive(Debug, Clone)]
pub enum DelayStrategy {
    /// Fixed interval between polls.
    Fixed(Duration),
    /// Exponential back-off: starts at `initial`, multiplies by `factor` each retry,
    /// capped at `max`.
    Exponential {
        initial: Duration,
        factor: f64,
        max: Duration,
    },
}

impl DelayStrategy {
    /// Creates a fixed-delay strategy.
    pub fn fixed(interval: Duration) -> Self {
        DelayStrategy::Fixed(interval)
    }

    /// Creates an exponential back-off strategy.
    ///
    /// # Arguments
    ///
    /// * `initial` - The delay before the first retry.
    /// * `factor` - Multiplicative factor applied each retry (e.g. 2.0 for doubling).
    /// * `max` - Maximum delay cap.
    pub fn exponential(initial: Duration, factor: f64, max: Duration) -> Self {
        DelayStrategy::Exponential {
            initial,
            factor,
            max,
        }
    }

    /// Computes the delay for the given retry attempt (0-indexed).
    pub fn delay_for_retry(&self, retry: u32) -> Duration {
        match self {
            DelayStrategy::Fixed(d) => *d,
            DelayStrategy::Exponential {
                initial,
                factor,
                max,
            } => {
                let millis = initial.as_millis() as f64 * factor.powi(retry as i32);
                let capped = millis.min(max.as_millis() as f64);
                Duration::from_millis(capped as u64)
            }
        }
    }
}

/// Configuration options for controlling how the MST client polls for completed
/// receipt registrations.
///
/// If neither `polling_interval` nor `delay_strategy` is set, the client's default
/// fixed-interval polling is used. If both are set, `delay_strategy` takes precedence.
#[derive(Debug, Clone, Default)]
pub struct MstPollingOptions {
    /// Fixed interval between polling attempts. Set to `None` to use the default.
    pub polling_interval: Option<Duration>,
    /// Custom delay strategy. Takes precedence over `polling_interval` if both are set.
    pub delay_strategy: Option<DelayStrategy>,
    /// Maximum number of polling attempts. `None` means use the client default (30).
    pub max_retries: Option<u32>,
}

impl MstPollingOptions {
    /// Computes the delay for the given retry attempt, applying the configured strategy.
    ///
    /// Priority: `delay_strategy` > `polling_interval` > `fallback`.
    pub fn delay_for_retry(&self, retry: u32, fallback: Duration) -> Duration {
        if let Some(ref strategy) = self.delay_strategy {
            strategy.delay_for_retry(retry)
        } else if let Some(interval) = self.polling_interval {
            interval
        } else {
            fallback
        }
    }

    /// Returns the effective max retries, falling back to the provided default.
    pub fn effective_max_retries(&self, default: u32) -> u32 {
        self.max_retries.unwrap_or(default)
    }
}
