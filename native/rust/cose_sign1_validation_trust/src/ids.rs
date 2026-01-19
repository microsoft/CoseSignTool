// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubjectId(pub [u8; 32]);

impl SubjectId {
    /// Render the subject id as a lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Compute a SHA-256 over a domain separator and length-prefixed parts.
///
/// This helper is used to create stable, collision-resistant derived subject ids when multiple
/// variable-length components are involved.
pub fn sha256_domain_separated(domain: &[u8], parts: &[&[u8]]) -> SubjectId {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0u8]);
    for part in parts {
        // length-prefix to avoid ambiguity
        let len = (part.len() as u64).to_be_bytes();
        hasher.update(len);
        hasher.update(*part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SubjectId(out)
}

/// Compute `SHA-256(bytes)`.
pub fn sha256_of_bytes(bytes: &[u8]) -> SubjectId {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SubjectId(out)
}

/// Compute `SHA-256(concat(parts...))`.
///
/// Prefer [`sha256_domain_separated`] when concatenation ambiguity could matter.
pub fn sha256_of_concat(parts: &[&[u8]]) -> SubjectId {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(*part);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    SubjectId(out)
}
