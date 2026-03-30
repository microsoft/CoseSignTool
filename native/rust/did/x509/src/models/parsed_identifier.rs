// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::DidX509Policy;

/// A parsed DID:x509 identifier with all its components
#[derive(Debug, Clone, PartialEq)]
pub struct DidX509ParsedIdentifier {
    /// The hash algorithm used for the CA fingerprint (e.g., "sha256")
    pub hash_algorithm: String,

    /// The decoded CA fingerprint bytes
    pub ca_fingerprint: Vec<u8>,

    /// The CA fingerprint as hex string
    pub ca_fingerprint_hex: String,

    /// The list of policy constraints
    pub policies: Vec<DidX509Policy>,
}

impl DidX509ParsedIdentifier {
    /// Create a new parsed identifier
    pub fn new(
        hash_algorithm: String,
        ca_fingerprint: Vec<u8>,
        ca_fingerprint_hex: String,
        policies: Vec<DidX509Policy>,
    ) -> Self {
        Self {
            hash_algorithm,
            ca_fingerprint,
            ca_fingerprint_hex,
            policies,
        }
    }

    /// Check if a specific policy type exists
    pub fn has_eku_policy(&self) -> bool {
        self.policies
            .iter()
            .any(|p| matches!(p, DidX509Policy::Eku(_)))
    }

    /// Check if a subject policy exists
    pub fn has_subject_policy(&self) -> bool {
        self.policies
            .iter()
            .any(|p| matches!(p, DidX509Policy::Subject(_)))
    }

    /// Check if a SAN policy exists
    pub fn has_san_policy(&self) -> bool {
        self.policies
            .iter()
            .any(|p| matches!(p, DidX509Policy::San(_, _)))
    }

    /// Check if a Fulcio issuer policy exists
    pub fn has_fulcio_issuer_policy(&self) -> bool {
        self.policies
            .iter()
            .any(|p| matches!(p, DidX509Policy::FulcioIssuer(_)))
    }

    /// Get the EKU policy if it exists
    pub fn get_eku_policy(&self) -> Option<&Vec<String>> {
        self.policies.iter().find_map(|p| {
            if let DidX509Policy::Eku(oids) = p {
                Some(oids)
            } else {
                None
            }
        })
    }

    /// Get the subject policy if it exists
    pub fn get_subject_policy(&self) -> Option<&Vec<(String, String)>> {
        self.policies.iter().find_map(|p| {
            if let DidX509Policy::Subject(attrs) = p {
                Some(attrs)
            } else {
                None
            }
        })
    }
}
