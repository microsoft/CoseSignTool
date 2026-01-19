// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::ids::{sha256_domain_separated, sha256_of_bytes, sha256_of_concat, SubjectId};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustSubject {
    pub id: SubjectId,
    pub kind: &'static str,
}

impl TrustSubject {
    pub fn message(encoded_cose_sign1: &[u8]) -> Self {
        // V2 parity: MessageId = SHA-256 of the full encoded COSE_Sign1 bytes.
        Self {
            id: sha256_of_bytes(encoded_cose_sign1),
            kind: "Message",
        }
    }

    pub fn primary_signing_key(message: &TrustSubject) -> Self {
        // V2 parity: SHA256("PrimarySigningKey" || messageId)
        Self {
            id: sha256_of_concat(&[b"PrimarySigningKey", message.id.0.as_slice()]),
            kind: "PrimarySigningKey",
        }
    }

    pub fn counter_signature(message: &TrustSubject, raw_counter_signature_bytes: &[u8]) -> Self {
        // V2 parity: CounterSignatureId = SHA-256 of raw counter-signature bytes.
        // Note: V2 also records parentId=messageId; Rust stores only stable id+kind.
        let _ = message;
        Self {
            id: sha256_of_bytes(raw_counter_signature_bytes),
            kind: "CounterSignature",
        }
    }

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

    pub fn root(kind: &'static str, seed: &[u8]) -> Self {
        let id = sha256_domain_separated(
            b"CoseSign1.Validation/TrustSubject/root",
            &[kind.as_bytes(), seed],
        );
        Self { id, kind }
    }

    pub fn derived(parent: &TrustSubject, kind: &'static str, discriminator: &[u8]) -> Self {
        let id = sha256_domain_separated(
            b"CoseSign1.Validation/TrustSubject/derived",
            &[parent.id.0.as_slice(), kind.as_bytes(), discriminator],
        );
        Self { id, kind }
    }
}
