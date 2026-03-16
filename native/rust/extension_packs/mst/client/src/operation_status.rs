// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Status monitor for Code Transparency long-running operations.
//!
//! Implements `azure_core::http::poller::StatusMonitor` so the operation
//! can be tracked via `Poller<OperationStatus>`.

use azure_core::http::{
    poller::{PollerStatus, StatusMonitor},
    JsonFormat,
};
use serde::{Deserialize, Serialize};

/// Status of a Code Transparency long-running operation.
///
/// This type implements [`StatusMonitor`] so it can be used with
/// [`Poller<OperationStatus>`](azure_core::http::poller::Poller).
///
/// The MST service returns CBOR-encoded operation status with `Status` and
/// `EntryId` text fields. This struct is populated from manual CBOR parsing
/// in the `Poller` callback (not from JSON deserialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStatus {
    /// The operation ID.
    #[serde(default)]
    pub operation_id: String,
    /// The operation status string (`"Running"`, `"Succeeded"`, `"Failed"`).
    #[serde(default, rename = "status")]
    pub operation_status: String,
    /// The entry ID (populated when status is `"Succeeded"`).
    #[serde(default)]
    pub entry_id: Option<String>,
}

impl StatusMonitor for OperationStatus {
    type Output = OperationStatus;
    type Format = JsonFormat;

    fn status(&self) -> PollerStatus {
        match self.operation_status.as_str() {
            "Succeeded" => PollerStatus::Succeeded,
            "Failed" => PollerStatus::Failed,
            "Canceled" | "Cancelled" => PollerStatus::Canceled,
            _ => PollerStatus::InProgress,
        }
    }
}
