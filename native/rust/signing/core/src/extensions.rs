// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signature format detection and indirect signature header labels.
//!
//! Maps V2 CoseSign1.Abstractions/Extensions/

use cose_sign1_primitives::CoseHeaderLabel;

/// Signature format type.
///
/// Maps V2 `SignatureFormat` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Standard direct signature.
    Direct,
    /// Legacy indirect with +hash-sha256 content-type.
    IndirectHashLegacy,
    /// Indirect with +cose-hash-v content-type.
    IndirectCoseHashV,
    /// Indirect using COSE Hash Envelope (RFC 9054) with headers 258/259/260.
    IndirectCoseHashEnvelope,
}

/// COSE header labels for indirect signatures (RFC 9054).
///
/// Maps V2 `IndirectSignatureHeaderLabels`.
pub struct IndirectSignatureHeaderLabels;

impl IndirectSignatureHeaderLabels {
    /// PayloadHashAlg (258) - hash algorithm for payload.
    pub fn payload_hash_alg() -> CoseHeaderLabel {
        CoseHeaderLabel::from(258)
    }

    /// PreimageContentType (259) - original content type before hashing.
    pub fn preimage_content_type() -> CoseHeaderLabel {
        CoseHeaderLabel::from(259)
    }

    /// PayloadLocation (260) - where the original payload can be retrieved.
    pub fn payload_location() -> CoseHeaderLabel {
        CoseHeaderLabel::from(260)
    }
}

/// Header location search flags.
///
/// Maps V2 `CoseHeaderLocation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoseHeaderLocation {
    /// Search only protected headers.
    Protected,
    /// Search only unprotected headers.
    Unprotected,
    /// Search both protected and unprotected headers.
    Any,
}
