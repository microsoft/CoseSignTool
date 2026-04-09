// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate options with fluent builder.

use crate::certificate::Certificate;
use crate::key_algorithm::KeyAlgorithm;
use std::time::Duration;

/// Hash algorithm for certificate signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    /// SHA-256 hash algorithm.
    #[default]
    Sha256,
    /// SHA-384 hash algorithm.
    Sha384,
    /// SHA-512 hash algorithm.
    Sha512,
}

/// RSA signature padding mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningPadding {
    /// PKCS#1 v1.5 padding (default, most compatible).
    #[default]
    Pkcs1v15,
    /// Probabilistic Signature Scheme (PSS) padding (RFC 4055).
    Pss,
}

/// A custom X.509v3 extension to add to the certificate.
#[derive(Debug, Clone)]
pub struct CustomExtension {
    /// OID string (e.g., "2.5.29.17" or "1.2.3.4.5.6").
    pub oid: String,
    /// Whether this extension is marked critical.
    pub critical: bool,
    /// DER-encoded extension value (the OCTET STRING payload).
    pub value: Vec<u8>,
}

impl CustomExtension {
    /// Creates a new custom extension.
    pub fn new(oid: impl Into<String>, critical: bool, value: Vec<u8>) -> Self {
        Self {
            oid: oid.into(),
            critical,
            value,
        }
    }
}

/// Key usage flags for X.509 certificates.
#[derive(Debug, Clone, Copy)]
pub struct KeyUsageFlags {
    /// Bitfield of key usage flags.
    pub flags: u16,
}

impl KeyUsageFlags {
    /// Digital signature key usage.
    pub const DIGITAL_SIGNATURE: Self = Self { flags: 0x80 };
    /// Key encipherment key usage.
    pub const KEY_ENCIPHERMENT: Self = Self { flags: 0x20 };
    /// Certificate signing key usage.
    pub const KEY_CERT_SIGN: Self = Self { flags: 0x04 };
}

impl Default for KeyUsageFlags {
    fn default() -> Self {
        Self::DIGITAL_SIGNATURE
    }
}

/// Configuration options for certificate creation.
pub struct CertificateOptions {
    /// Subject name (Distinguished Name) for the certificate.
    pub subject_name: String,
    /// Cryptographic algorithm for key generation.
    pub key_algorithm: KeyAlgorithm,
    /// Key size in bits (if None, uses algorithm defaults).
    pub key_size: Option<u32>,
    /// Hash algorithm for certificate signing.
    pub hash_algorithm: HashAlgorithm,
    /// RSA signature padding mode (only applies to RSA keys).
    pub signing_padding: SigningPadding,
    /// Certificate validity duration from creation time.
    pub validity: Duration,
    /// Not-before offset from current time (negative for clock skew tolerance).
    pub not_before_offset: Duration,
    /// Whether this certificate is a Certificate Authority.
    pub is_ca: bool,
    /// CA path length constraint (only applicable when is_ca is true).
    pub path_length_constraint: u32,
    /// Key usage flags for the certificate.
    pub key_usage: KeyUsageFlags,
    /// Enhanced Key Usage (EKU) OIDs.
    pub enhanced_key_usages: Vec<String>,
    /// Subject Alternative Names.
    pub subject_alternative_names: Vec<String>,
    /// Issuer certificate for chain signing (if None, creates self-signed).
    pub issuer: Option<Box<Certificate>>,
    /// Custom X.509v3 extensions.
    pub custom_extensions: Vec<CustomExtension>,
}

impl Default for CertificateOptions {
    fn default() -> Self {
        Self {
            subject_name: "CN=Ephemeral Certificate".to_string(),
            key_algorithm: KeyAlgorithm::default(),
            key_size: None,
            hash_algorithm: HashAlgorithm::default(),
            signing_padding: SigningPadding::default(),
            validity: Duration::from_secs(3600), // 1 hour
            not_before_offset: Duration::from_secs(5 * 60), // 5 minutes
            is_ca: false,
            path_length_constraint: 0,
            key_usage: KeyUsageFlags::default(),
            enhanced_key_usages: vec!["1.3.6.1.5.5.7.3.3".to_string()], // Code signing
            subject_alternative_names: Vec::new(),
            issuer: None,
            custom_extensions: Vec::new(),
        }
    }
}

impl CertificateOptions {
    /// Creates a new options builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the subject name.
    pub fn with_subject_name(mut self, name: impl Into<String>) -> Self {
        self.subject_name = name.into();
        self
    }

    /// Sets the key algorithm.
    pub fn with_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// Sets the key size.
    pub fn with_key_size(mut self, size: u32) -> Self {
        self.key_size = Some(size);
        self
    }

    /// Sets the hash algorithm.
    pub fn with_hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.hash_algorithm = algorithm;
        self
    }

    /// Sets the RSA signing padding mode.
    pub fn with_signing_padding(mut self, padding: SigningPadding) -> Self {
        self.signing_padding = padding;
        self
    }

    /// Sets the validity duration.
    pub fn with_validity(mut self, duration: Duration) -> Self {
        self.validity = duration;
        self
    }

    /// Sets the not-before offset.
    pub fn with_not_before_offset(mut self, offset: Duration) -> Self {
        self.not_before_offset = offset;
        self
    }

    /// Configures this certificate as a CA.
    pub fn as_ca(mut self, path_length: u32) -> Self {
        self.is_ca = true;
        self.path_length_constraint = path_length;
        self
    }

    /// Sets the key usage flags.
    pub fn with_key_usage(mut self, usage: KeyUsageFlags) -> Self {
        self.key_usage = usage;
        self
    }

    /// Sets the enhanced key usages.
    pub fn with_enhanced_key_usages(mut self, usages: Vec<String>) -> Self {
        self.enhanced_key_usages = usages;
        self
    }

    /// Adds a subject alternative name.
    pub fn add_subject_alternative_name(mut self, name: impl Into<String>) -> Self {
        self.subject_alternative_names.push(name.into());
        self
    }

    /// Signs this certificate with the given issuer.
    pub fn signed_by(mut self, issuer: Certificate) -> Self {
        self.issuer = Some(Box::new(issuer));
        self
    }

    /// Adds a custom X.509v3 extension.
    pub fn add_custom_extension(mut self, extension: CustomExtension) -> Self {
        self.custom_extensions.push(extension);
        self
    }

    /// Adds a custom extension from OID, criticality, and DER value.
    pub fn add_custom_extension_der(
        mut self,
        oid: impl Into<String>,
        critical: bool,
        value: Vec<u8>,
    ) -> Self {
        self.custom_extensions.push(CustomExtension::new(oid, critical, value));
        self
    }
}
