// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_certificates::error::CertificateError;

#[test]
fn test_certificate_error_display() {
    let err = CertificateError::NotFound;
    assert_eq!(err.to_string(), "Certificate not found");

    let err = CertificateError::InvalidCertificate("invalid DER".to_string());
    assert_eq!(err.to_string(), "Invalid certificate: invalid DER");

    let err = CertificateError::ChainBuildFailed("no root found".to_string());
    assert_eq!(err.to_string(), "Chain building failed: no root found");

    let err = CertificateError::NoPrivateKey;
    assert_eq!(err.to_string(), "Private key not available");

    let err = CertificateError::SigningError("key mismatch".to_string());
    assert_eq!(err.to_string(), "Signing error: key mismatch");
}
