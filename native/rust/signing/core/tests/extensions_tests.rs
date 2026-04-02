// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signature format and extensions.

use cose_sign1_primitives::CoseHeaderLabel;
use cose_sign1_signing::{CoseHeaderLocation, IndirectSignatureHeaderLabels, SignatureFormat};

#[test]
fn test_signature_format_variants() {
    assert_eq!(format!("{:?}", SignatureFormat::Direct), "Direct");
    assert_eq!(
        format!("{:?}", SignatureFormat::IndirectHashLegacy),
        "IndirectHashLegacy"
    );
    assert_eq!(
        format!("{:?}", SignatureFormat::IndirectCoseHashV),
        "IndirectCoseHashV"
    );
    assert_eq!(
        format!("{:?}", SignatureFormat::IndirectCoseHashEnvelope),
        "IndirectCoseHashEnvelope"
    );
}

#[test]
fn test_signature_format_equality() {
    assert_eq!(SignatureFormat::Direct, SignatureFormat::Direct);
    assert_ne!(SignatureFormat::Direct, SignatureFormat::IndirectHashLegacy);
}

#[test]
fn test_signature_format_copy() {
    let format = SignatureFormat::IndirectCoseHashV;
    let copied = format;
    assert_eq!(format, copied);
}

#[test]
fn test_indirect_signature_header_labels() {
    let payload_hash_alg = IndirectSignatureHeaderLabels::payload_hash_alg();
    let preimage_content_type = IndirectSignatureHeaderLabels::preimage_content_type();
    let payload_location = IndirectSignatureHeaderLabels::payload_location();

    // Verify the correct integer values
    match payload_hash_alg {
        CoseHeaderLabel::Int(258) => {}
        _ => panic!("Expected PayloadHashAlg to be Int(258)"),
    }

    match preimage_content_type {
        CoseHeaderLabel::Int(259) => {}
        _ => panic!("Expected PreimageContentType to be Int(259)"),
    }

    match payload_location {
        CoseHeaderLabel::Int(260) => {}
        _ => panic!("Expected PayloadLocation to be Int(260)"),
    }
}

#[test]
fn test_cose_header_location_variants() {
    assert_eq!(format!("{:?}", CoseHeaderLocation::Protected), "Protected");
    assert_eq!(
        format!("{:?}", CoseHeaderLocation::Unprotected),
        "Unprotected"
    );
    assert_eq!(format!("{:?}", CoseHeaderLocation::Any), "Any");
}

#[test]
fn test_cose_header_location_equality() {
    assert_eq!(CoseHeaderLocation::Protected, CoseHeaderLocation::Protected);
    assert_ne!(
        CoseHeaderLocation::Protected,
        CoseHeaderLocation::Unprotected
    );
}

#[test]
fn test_cose_header_location_copy() {
    let location = CoseHeaderLocation::Any;
    let copied = location;
    assert_eq!(location, copied);
}
