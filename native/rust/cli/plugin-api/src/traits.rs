// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin capability types — mirroring V2 .NET plugin interfaces.
//!
//! These types define what a plugin can provide. A single plugin binary
//! may implement multiple capabilities (e.g., both signing and verification).
//!
//! All byte arrays are CBOR byte strings (major type 2) on the wire —
//! no base64 encoding overhead.

/// Metadata about a plugin, reported during capability discovery.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginCapability {
    /// Can create signing services (sign payloads).
    Signing,
    /// Can provide verification trust packs.
    Verification,
    /// Can add transparency receipts.
    Transparency,
}

impl PluginCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::Verification => "verification",
            Self::Transparency => "transparency",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "signing" => Some(Self::Signing),
            "verification" => Some(Self::Verification),
            "transparency" => Some(Self::Transparency),
            _ => None,
        }
    }
}

/// Configuration passed to a plugin when creating a service.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    /// Key-value configuration from CLI arguments.
    pub options: std::collections::HashMap<String, String>,
}

/// A signing request sent to a plugin.
#[derive(Debug, Clone)]
pub struct SignRequest {
    /// Service ID from create_service.
    pub service_id: String,
    /// Data to sign (Sig_structure digest). CBOR byte string on the wire.
    pub data: Vec<u8>,
    /// COSE algorithm identifier (e.g., -7 for ES256, -37 for PS256).
    pub algorithm: i64,
}

/// A signing response from a plugin.
#[derive(Debug, Clone)]
pub struct SignResponse {
    /// The signature bytes. CBOR byte string on the wire.
    pub signature: Vec<u8>,
}

/// Certificate chain response from a plugin.
#[derive(Debug, Clone)]
pub struct CertificateChainResponse {
    /// DER-encoded certificates, leaf first. Each is a CBOR byte string.
    pub certificates: Vec<Vec<u8>>,
}

/// Algorithm response from a plugin.
#[derive(Debug, Clone)]
pub struct AlgorithmResponse {
    /// COSE algorithm identifier.
    pub algorithm: i64,
}
