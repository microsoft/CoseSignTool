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

/// Trait that plugin implementations must implement.
///
/// First-party plugins implement this directly in the plugin-loader.
/// Third-party plugins implement this in their own binary.
pub trait PluginProvider: Send {
    /// Plugin metadata.
    fn info(&self) -> PluginInfo;

    /// Create a signing service, returning a service identifier.
    fn create_service(&mut self, config: PluginConfig) -> Result<String, String>;

    /// Get the certificate chain for a service.
    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String>;

    /// Get the signing algorithm for a service.
    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String>;

    /// Sign data, returning signature bytes.
    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String>;
}

impl<T> PluginProvider for Box<T>
where
    T: PluginProvider + ?Sized,
{
    fn info(&self) -> PluginInfo {
        self.as_ref().info()
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        self.as_mut().create_service(config)
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        self.as_mut().get_cert_chain(service_id)
    }

    fn get_algorithm(&mut self, service_id: &str) -> Result<i64, String> {
        self.as_mut().get_algorithm(service_id)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        self.as_mut().sign(service_id, data, algorithm)
    }
}
