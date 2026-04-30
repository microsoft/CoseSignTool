// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin capability traits — mirroring V2 .NET plugin interfaces.
//!
//! These traits define what a plugin can provide. A single plugin binary
//! may implement multiple capabilities (e.g., both signing and verification).

use serde::{Deserialize, Serialize};

/// Metadata about a plugin, reported during capability discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    /// Unique plugin identifier (e.g., "yubikey", "aws-kms").
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Plugin version.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Capabilities this plugin provides.
    pub capabilities: Vec<PluginCapability>,
}

/// What a plugin can do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginCapability {
    /// Can create signing services (sign payloads).
    Signing,
    /// Can provide verification trust packs.
    Verification,
    /// Can add transparency receipts.
    Transparency,
}

/// Configuration passed to a plugin when creating a service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    /// Key-value configuration from CLI arguments.
    pub options: std::collections::HashMap<String, String>,
}

/// A signing request sent to a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignRequest {
    /// Request ID for multiplexing.
    pub id: u64,
    /// Hash of the payload to sign (Sig_structure digest).
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    /// COSE algorithm identifier (e.g., -7 for ES256, -37 for PS256).
    pub algorithm: i64,
}

/// A signing response from a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignResponse {
    /// Matching request ID.
    pub id: u64,
    /// The signature bytes.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
}

/// Certificate chain response from a plugin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChainResponse {
    /// Matching request ID.
    pub id: u64,
    /// DER-encoded certificates, leaf first.
    pub certificates: Vec<Base64Bytes>,
}

/// Wrapper for base64-encoded byte arrays in JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base64Bytes(#[serde(with = "base64_bytes")] pub Vec<u8>);

/// Custom serde module for base64 encoding/decoding of byte arrays.
mod base64_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        use base64::Engine;
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}
