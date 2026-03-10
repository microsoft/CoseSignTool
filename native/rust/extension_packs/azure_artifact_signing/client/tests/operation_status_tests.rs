// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::OperationStatus;
use azure_core::http::poller::PollerStatus;

#[test]
fn test_operation_status_to_poller_status_inprogress() {
    let status = OperationStatus::InProgress;
    assert_eq!(status.to_poller_status(), PollerStatus::InProgress);
}

#[test]
fn test_operation_status_to_poller_status_running() {
    let status = OperationStatus::Running;
    assert_eq!(status.to_poller_status(), PollerStatus::InProgress);
}

#[test]
fn test_operation_status_to_poller_status_succeeded() {
    let status = OperationStatus::Succeeded;
    assert_eq!(status.to_poller_status(), PollerStatus::Succeeded);
}

#[test]
fn test_operation_status_to_poller_status_failed() {
    let status = OperationStatus::Failed;
    assert_eq!(status.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn test_operation_status_to_poller_status_timedout() {
    let status = OperationStatus::TimedOut;
    assert_eq!(status.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn test_operation_status_to_poller_status_notfound() {
    let status = OperationStatus::NotFound;
    assert_eq!(status.to_poller_status(), PollerStatus::Failed);
}

#[test]
fn test_all_operation_status_variants_covered() {
    // Test all variants to ensure complete mapping
    let test_cases = vec![
        (OperationStatus::InProgress, PollerStatus::InProgress),
        (OperationStatus::Running, PollerStatus::InProgress),
        (OperationStatus::Succeeded, PollerStatus::Succeeded),
        (OperationStatus::Failed, PollerStatus::Failed),
        (OperationStatus::TimedOut, PollerStatus::Failed),
        (OperationStatus::NotFound, PollerStatus::Failed),
    ];

    for (operation_status, expected_poller_status) in test_cases {
        assert_eq!(operation_status.to_poller_status(), expected_poller_status);
    }
}