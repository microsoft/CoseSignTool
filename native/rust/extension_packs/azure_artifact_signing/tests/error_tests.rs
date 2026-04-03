// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_azure_artifact_signing::error::AasError;

#[test]
fn test_ats_error_certificate_fetch_failed_display() {
    let error = AasError::CertificateFetchFailed("network timeout".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "AAS certificate fetch failed: network timeout");
}

#[test]
fn test_ats_error_signing_failed_display() {
    let error = AasError::SigningFailed("HSM unavailable".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "AAS signing failed: HSM unavailable");
}

#[test]
fn test_ats_error_invalid_configuration_display() {
    let error = AasError::InvalidConfiguration("missing endpoint".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "AAS invalid configuration: missing endpoint");
}

#[test]
fn test_ats_error_did_x509_error_display() {
    let error = AasError::DidX509Error("malformed certificate".to_string());
    let display = format!("{}", error);
    assert_eq!(display, "AAS DID:x509 error: malformed certificate");
}

#[test]
fn test_ats_error_debug() {
    let error = AasError::SigningFailed("test message".to_string());
    let debug_str = format!("{:?}", error);
    assert!(debug_str.contains("SigningFailed"));
    assert!(debug_str.contains("test message"));
}

#[test]
fn test_ats_error_is_std_error() {
    let error = AasError::InvalidConfiguration("test".to_string());

    // Test that it implements std::error::Error
    let error_trait: &dyn std::error::Error = &error;
    assert!(error_trait
        .to_string()
        .contains("AAS invalid configuration"));
}
