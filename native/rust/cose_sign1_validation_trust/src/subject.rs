// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ids::{sha256_domain_separated, sha256_of_bytes, sha256_of_concat, SubjectId};

/// A stable identifier for the entity being evaluated by a trust policy.
///
/// Subjects are intentionally deterministic: the same bytes yield the same ID, which enables
/// caching, auditing, and reproducible decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustSubject {
    /// Stable, deterministic subject identifier.
    pub id: SubjectId,
    /// A short kind string used for diagnostics and grouping (e.g. "Message").
    pub kind: &'static str,
}

impl TrustSubject {
    /// Message subject derived from the full encoded COSE_Sign1 bytes.
    pub fn message(encoded_cose_sign1: &[u8]) -> Self {
        // V2 parity: MessageId = SHA-256 of the full encoded COSE_Sign1 bytes.
        Self {
            id: sha256_of_bytes(encoded_cose_sign1),
            kind: "Message",
        }
    }

    /// Primary signing key subject derived from a message subject.
    pub fn primary_signing_key(message: &TrustSubject) -> Self {
        // V2 parity: SHA256("PrimarySigningKey" || messageId)
        Self {
            id: sha256_of_concat(&[b"PrimarySigningKey", message.id.0.as_slice()]),
            kind: "PrimarySigningKey",
        }
    }

    /// Counter-signature subject derived from raw counter-signature bytes.
    pub fn counter_signature(message: &TrustSubject, raw_counter_signature_bytes: &[u8]) -> Self {
        // V2 parity: CounterSignatureId = SHA-256 of raw counter-signature bytes.
        // Note: V2 also records parentId=messageId; Rust stores only stable id+kind.
        let _ = message;
        Self {
            id: sha256_of_bytes(raw_counter_signature_bytes),
            kind: "CounterSignature",
        }
    }

    /// Counter-signature signing key subject derived from a counter-signature subject.
    pub fn counter_signature_signing_key(counter_signature: &TrustSubject) -> Self {
        // V2 parity: SHA256("CounterSignatureSigningKey" || counterSignatureId)
        Self {
            id: sha256_of_concat(&[
                b"CounterSignatureSigningKey",
                counter_signature.id.0.as_slice(),
            ]),
            kind: "CounterSignatureSigningKey",
        }
    }

    /// Root subject useful for non-message evaluations (tests, tooling, or pack-local policies).
    pub fn root(kind: &'static str, seed: &[u8]) -> Self {
        let id = sha256_domain_separated(
            b"CoseSign1.Validation/TrustSubject/root",
            &[kind.as_bytes(), seed],
        );
        Self { id, kind }
    }

    /// Subject derived from another subject using a domain-separated hash.
    ///
    /// Use this to create stable identifiers for pack-specific derived entities.
    pub fn derived(parent: &TrustSubject, kind: &'static str, discriminator: &[u8]) -> Self {
        let id = sha256_domain_separated(
            b"CoseSign1.Validation/TrustSubject/derived",
            &[parent.id.0.as_slice(), kind.as_bytes(), discriminator],
        );
        Self { id, kind }
    }
}
