// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin capability types — mirroring V2 .NET plugin interfaces.
//!
//! These types define what a plugin can provide. A single plugin binary
//! may implement multiple capabilities (e.g., both signing and verification).
//!
//! All byte arrays are CBOR byte strings (major type 2) on the wire —
//! no base64 encoding overhead.

use std::collections::HashMap;

/// Definition of a CLI option exposed by a plugin command.
#[derive(Debug, Clone)]
pub struct PluginOptionDef {
    /// Long option name without dashes (e.g., "aas-endpoint").
    pub name: String,
    /// Value placeholder (e.g., "aas-endpoint", "URL").
    pub value_name: String,
    /// Help description text.
    pub description: String,
    /// Whether this option is required.
    pub required: bool,
    /// Default value if any.
    pub default_value: Option<String>,
    /// Short alias (single char, e.g., 'o' for -o).
    pub short: Option<char>,
    /// Whether this option is a boolean flag with no value.
    pub is_flag: bool,
}

/// Definition of a CLI subcommand exposed by a plugin.
#[derive(Debug, Clone)]
pub struct PluginCommandDef {
    /// Subcommand name (e.g., "aas", "pfx", "akv-cert").
    pub name: String,
    /// Short description for help output.
    pub description: String,
    /// Options accepted by this subcommand.
    pub options: Vec<PluginOptionDef>,
    /// Capability provided by this command.
    pub capability: PluginCapability,
}

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
    /// CLI commands exposed by this plugin.
    pub commands: Vec<PluginCommandDef>,
    /// Transparency-specific CLI options this plugin contributes to sign commands.
    /// These are added to all sign x509 subcommands when the plugin is loaded.
    /// Convention: options should be prefixed with --scitt-<plugin-id>-.
    pub transparency_options: Vec<PluginOptionDef>,
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

/// An end-to-end signing request sent to a plugin.
#[derive(Debug, Clone)]
pub struct SignPayloadRequest {
    /// Service ID from create_service.
    pub service_id: String,
    /// Raw payload bytes to sign.
    pub payload: Vec<u8>,
    /// Content type to apply to the signature.
    pub content_type: String,
    /// Signature format name (`direct` or `indirect`).
    pub format: String,
    /// Additional signing options.
    pub options: PluginConfig,
}

/// An end-to-end signing response from a plugin.
#[derive(Debug, Clone)]
pub struct SignPayloadResponse {
    /// The complete COSE_Sign1 bytes.
    pub cose_bytes: Vec<u8>,
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

/// Result of a verification operation.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Overall pass/fail.
    pub is_valid: bool,
    /// Per-stage results.
    pub stages: Vec<VerificationStageResult>,
    /// Metadata (provider name, trust mode, etc.).
    pub metadata: HashMap<String, String>,
}

/// Result of one verification stage.
#[derive(Debug, Clone)]
pub struct VerificationStageResult {
    /// Stage name (e.g., "key_resolution", "trust", "signature", "post_signature").
    pub stage: String,
    /// Pass/fail/not_applicable.
    pub kind: VerificationStageKind,
    /// Failure details (empty if passed).
    pub failures: Vec<VerificationFailure>,
    /// Stage metadata.
    pub metadata: HashMap<String, String>,
}

/// Outcome kind for a verification stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationStageKind {
    /// Stage completed successfully.
    Success,
    /// Stage failed.
    Failure,
    /// Stage does not apply to this provider/message.
    NotApplicable,
}

/// Failure detail produced during verification.
#[derive(Debug, Clone)]
pub struct VerificationFailure {
    /// Human-readable failure message.
    pub message: String,
    /// Optional stable error code.
    pub error_code: Option<String>,
}

/// Verification options passed from host to plugin.
#[derive(Debug, Clone, Default)]
pub struct VerificationOptions {
    /// Trust embedded x5chain as trusted (no OS trust store).
    pub trust_embedded_chain: bool,
    /// Allow specific thumbprints (SHA-256 hex).
    pub allowed_thumbprints: Vec<String>,
    /// Skip post-signature policy validation (signature-only mode).
    pub signature_only: bool,
}

/// Describes what trust policies a verification plugin supports.
#[derive(Debug, Clone)]
pub struct TrustPolicyInfo {
    /// Name of this trust provider (e.g., "x509", "akv-kid", "mst-receipt").
    pub name: String,
    /// What this provider validates.
    pub description: String,
    /// Supported trust modes.
    pub supported_modes: Vec<String>,
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

    /// Sign a payload end-to-end, returning the complete COSE_Sign1 bytes.
    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        let _ = service_id;
        let _ = payload;
        let _ = content_type;
        let _ = format;
        let _ = options;
        Err("sign_payload not implemented".into())
    }

    /// Verify a COSE_Sign1 message. Returns `None` if this plugin does not support verification.
    fn verify(
        &mut self,
        cose_bytes: &[u8],
        detached_payload: Option<&[u8]>,
        options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, String> {
        let _ = cose_bytes;
        let _ = detached_payload;
        let _ = options;
        Ok(None)
    }

    /// Describe supported trust policies. Returns `None` if this plugin does not support verification.
    fn trust_policy_info(&self) -> Option<TrustPolicyInfo> {
        None
    }
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

    fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: &PluginConfig,
    ) -> Result<Vec<u8>, String> {
        self.as_mut()
            .sign_payload(service_id, payload, content_type, format, options)
    }

    fn verify(
        &mut self,
        cose_bytes: &[u8],
        detached_payload: Option<&[u8]>,
        options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, String> {
        self.as_mut().verify(cose_bytes, detached_payload, options)
    }

    fn trust_policy_info(&self) -> Option<TrustPolicyInfo> {
        self.as_ref().trust_policy_info()
    }
}
