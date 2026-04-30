// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic key and service metadata.

use std::collections::HashMap;

/// Cryptographic key types supported for signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptographicKeyType {
    /// RSA key.
    Rsa,
    /// Elliptic Curve Digital Signature Algorithm (ECDSA).
    Ecdsa,
    /// Edwards-curve Digital Signature Algorithm (EdDSA).
    EdDsa,
    /// Post-quantum ML-DSA (FIPS 204).
    MlDsa,
    /// Other or unknown key type.
    Other,
}

/// Metadata about a signing key.
///
/// Maps V2 `SigningKeyMetadata` class.
#[derive(Debug, Clone)]
pub struct SigningKeyMetadata {
    /// Key identifier.
    pub key_id: Option<Vec<u8>>,
    /// COSE algorithm identifier.
    pub algorithm: i64,
    /// Key type.
    pub key_type: CryptographicKeyType,
    /// Whether the key is remote (e.g., in Azure Key Vault).
    pub is_remote: bool,
    /// Additional metadata as key-value pairs.
    pub additional_metadata: HashMap<String, String>,
}

impl SigningKeyMetadata {
    /// Creates new metadata.
    pub fn new(
        key_id: Option<Vec<u8>>,
        algorithm: i64,
        key_type: CryptographicKeyType,
        is_remote: bool,
    ) -> Self {
        Self {
            key_id,
            algorithm,
            key_type,
            is_remote,
            additional_metadata: HashMap::new(),
        }
    }
}

/// Metadata about a signing service.
///
/// Maps V2 `SigningServiceMetadata` class.
#[derive(Debug, Clone)]
pub struct SigningServiceMetadata {
    /// Service name.
    pub service_name: String,
    /// Service description.
    pub service_description: String,
    /// Additional metadata as key-value pairs.
    pub additional_metadata: HashMap<String, String>,
}

impl SigningServiceMetadata {
    /// Creates new service metadata.
    pub fn new(service_name: String, service_description: String) -> Self {
        Self {
            service_name,
            service_description,
            additional_metadata: HashMap::new(),
        }
    }
}

/// Describes a transparency service endpoint compatible with a signing service.
#[derive(Debug, Clone)]
pub struct TransparencyEndpointInfo {
    /// Transparency service type identifier (e.g., "mst", "rekor", "sigstore").
    pub service_type: String,
    /// Endpoint URL for the transparency service.
    pub endpoint: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether auto-submission is recommended for this signing profile.
    pub auto_submit: bool,
}
