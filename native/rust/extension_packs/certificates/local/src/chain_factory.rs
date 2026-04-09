// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Certificate chain factory implementation.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use crate::factory::EphemeralCertificateFactory;
use crate::key_algorithm::KeyAlgorithm;
use crate::options::{CertificateOptions, KeyUsageFlags};
use crate::traits::CertificateFactory;
use std::time::Duration;

/// Configuration options for certificate chain creation.
///
/// Maps V2 C# `CertificateChainOptions`.
pub struct CertificateChainOptions {
    /// Subject name for the root CA certificate.
    /// Default: "CN=Ephemeral Root CA"
    pub root_name: String,

    /// Subject name for the intermediate CA certificate.
    /// If None, no intermediate CA is created (2-tier chain).
    /// Default: Some("CN=Ephemeral Intermediate CA")
    pub intermediate_name: Option<String>,

    /// Subject name for the leaf (end-entity) certificate.
    /// Default: "CN=Ephemeral Leaf Certificate"
    pub leaf_name: String,

    /// Cryptographic algorithm for all certificates in the chain (default).
    /// Overridden per-tier by root_key_algorithm, intermediate_key_algorithm,
    /// leaf_key_algorithm when set.
    /// Default: ECDSA
    pub key_algorithm: KeyAlgorithm,

    /// Override algorithm for root CA. If None, uses key_algorithm.
    pub root_key_algorithm: Option<KeyAlgorithm>,

    /// Override algorithm for intermediate CA. If None, uses key_algorithm.
    pub intermediate_key_algorithm: Option<KeyAlgorithm>,

    /// Override algorithm for leaf certificate. If None, uses key_algorithm.
    pub leaf_key_algorithm: Option<KeyAlgorithm>,

    /// Key size for all certificates in the chain.
    /// If None, uses algorithm defaults. Per-tier overrides below take precedence.
    pub key_size: Option<u32>,

    /// Override key size for root CA.
    pub root_key_size: Option<u32>,

    /// Override key size for intermediate CA.
    pub intermediate_key_size: Option<u32>,

    /// Override key size for leaf certificate.
    pub leaf_key_size: Option<u32>,

    /// Validity duration for the root CA.
    /// Default: 10 years
    pub root_validity: Duration,

    /// Validity duration for the intermediate CA.
    /// Default: 5 years
    pub intermediate_validity: Duration,

    /// Validity duration for the leaf certificate.
    /// Default: 1 year
    pub leaf_validity: Duration,

    /// Whether only the leaf certificate should have a private key.
    /// Root and intermediate will only contain public keys.
    /// Default: false
    pub leaf_only_private_key: bool,

    /// Whether to return certificates in leaf-first order.
    /// If false, returns root-first order.
    /// Default: false (root first)
    pub leaf_first: bool,

    /// Enhanced Key Usage OIDs for the leaf certificate.
    /// If None, uses default code signing EKU.
    pub leaf_enhanced_key_usages: Option<Vec<String>>,
}

impl Default for CertificateChainOptions {
    fn default() -> Self {
        Self {
            root_name: "CN=Ephemeral Root CA".into(),
            intermediate_name: Some("CN=Ephemeral Intermediate CA".into()),
            leaf_name: "CN=Ephemeral Leaf Certificate".into(),
            key_algorithm: KeyAlgorithm::Ecdsa,
            root_key_algorithm: None,
            intermediate_key_algorithm: None,
            leaf_key_algorithm: None,
            key_size: None,
            root_key_size: None,
            intermediate_key_size: None,
            leaf_key_size: None,
            root_validity: Duration::from_secs(3650 * 24 * 60 * 60), // 10 years
            intermediate_validity: Duration::from_secs(1825 * 24 * 60 * 60), // 5 years
            leaf_validity: Duration::from_secs(365 * 24 * 60 * 60),  // 1 year
            leaf_only_private_key: false,
            leaf_first: false,
            leaf_enhanced_key_usages: None,
        }
    }
}

impl CertificateChainOptions {
    /// Creates a new options builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the root CA name.
    pub fn with_root_name(mut self, name: impl Into<String>) -> Self {
        self.root_name = name.into();
        self
    }

    /// Sets the intermediate CA name. Use None for 2-tier chain.
    pub fn with_intermediate_name(mut self, name: Option<impl Into<String>>) -> Self {
        self.intermediate_name = name.map(|n| n.into());
        self
    }

    /// Sets the leaf certificate name.
    pub fn with_leaf_name(mut self, name: impl Into<String>) -> Self {
        self.leaf_name = name.into();
        self
    }

    /// Sets the default key algorithm for all certificates.
    pub fn with_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.key_algorithm = algorithm;
        self
    }

    /// Sets the key algorithm for the root CA only (hybrid chain support).
    pub fn with_root_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.root_key_algorithm = Some(algorithm);
        self
    }

    /// Sets the key algorithm for the intermediate CA only (hybrid chain support).
    pub fn with_intermediate_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.intermediate_key_algorithm = Some(algorithm);
        self
    }

    /// Sets the key algorithm for the leaf certificate only (hybrid chain support).
    pub fn with_leaf_key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.leaf_key_algorithm = Some(algorithm);
        self
    }

    /// Sets the default key size for all certificates.
    pub fn with_key_size(mut self, size: u32) -> Self {
        self.key_size = Some(size);
        self
    }

    /// Sets the key size for the root CA only.
    pub fn with_root_key_size(mut self, size: u32) -> Self {
        self.root_key_size = Some(size);
        self
    }

    /// Sets the key size for the intermediate CA only.
    pub fn with_intermediate_key_size(mut self, size: u32) -> Self {
        self.intermediate_key_size = Some(size);
        self
    }

    /// Sets the key size for the leaf certificate only.
    pub fn with_leaf_key_size(mut self, size: u32) -> Self {
        self.leaf_key_size = Some(size);
        self
    }

    /// Sets the root CA validity duration.
    pub fn with_root_validity(mut self, duration: Duration) -> Self {
        self.root_validity = duration;
        self
    }

    /// Sets the intermediate CA validity duration.
    pub fn with_intermediate_validity(mut self, duration: Duration) -> Self {
        self.intermediate_validity = duration;
        self
    }

    /// Sets the leaf certificate validity duration.
    pub fn with_leaf_validity(mut self, duration: Duration) -> Self {
        self.leaf_validity = duration;
        self
    }

    /// Sets whether only the leaf should have a private key.
    pub fn with_leaf_only_private_key(mut self, value: bool) -> Self {
        self.leaf_only_private_key = value;
        self
    }

    /// Sets whether to return certificates in leaf-first order.
    pub fn with_leaf_first(mut self, value: bool) -> Self {
        self.leaf_first = value;
        self
    }

    /// Sets the leaf certificate's enhanced key usages.
    pub fn with_leaf_enhanced_key_usages(mut self, usages: Vec<String>) -> Self {
        self.leaf_enhanced_key_usages = Some(usages);
        self
    }

    /// Resolves the effective algorithm for a tier.
    fn resolve_algorithm(&self, tier_override: Option<KeyAlgorithm>) -> KeyAlgorithm {
        tier_override.unwrap_or(self.key_algorithm)
    }

    /// Resolves the effective key size for a tier.
    fn resolve_key_size(&self, tier_override: Option<u32>, algorithm: KeyAlgorithm) -> u32 {
        tier_override
            .or(self.key_size)
            .unwrap_or_else(|| algorithm.default_key_size())
    }
}

/// Factory for creating certificate chains (root → intermediate → leaf).
///
/// Creates hierarchical certificate chains suitable for testing certificate
/// validation, chain building, and production-like signing scenarios.
///
/// Maps V2 C# `CertificateChainFactory`.
pub struct CertificateChainFactory {
    /// Underlying certificate factory for individual certificate creation.
    certificate_factory: EphemeralCertificateFactory,
}

impl CertificateChainFactory {
    /// Creates a new certificate chain factory with the specified certificate factory.
    pub fn new(certificate_factory: EphemeralCertificateFactory) -> Self {
        Self {
            certificate_factory,
        }
    }

    /// Creates a certificate chain with default options.
    pub fn create_chain(&self) -> Result<Vec<Certificate>, CertLocalError> {
        self.create_chain_with_options(CertificateChainOptions::default())
    }

    /// Creates a certificate chain with the specified options.
    ///
    /// Supports hybrid chains where each tier can use a different key algorithm.
    /// For example: ECDSA root → ECDSA intermediate → EdDSA leaf.
    pub fn create_chain_with_options(
        &self,
        options: CertificateChainOptions,
    ) -> Result<Vec<Certificate>, CertLocalError> {
        let root_algo = options.resolve_algorithm(options.root_key_algorithm);
        let root_size = options.resolve_key_size(options.root_key_size, root_algo);

        // Create root CA
        let root = self.certificate_factory.create_certificate(
            CertificateOptions::new()
                .with_subject_name(&options.root_name)
                .with_key_algorithm(root_algo)
                .with_key_size(root_size)
                .with_validity(options.root_validity)
                .as_ca(if options.intermediate_name.is_some() {
                    1
                } else {
                    0
                })
                .with_key_usage(KeyUsageFlags {
                    flags: KeyUsageFlags::KEY_CERT_SIGN.flags
                        | KeyUsageFlags::DIGITAL_SIGNATURE.flags,
                }),
        )?;

        // Determine the issuer for the leaf
        let (leaf_issuer, intermediate) =
            if let Some(intermediate_name) = &options.intermediate_name {
                let inter_algo = options.resolve_algorithm(options.intermediate_key_algorithm);
                let inter_size = options.resolve_key_size(options.intermediate_key_size, inter_algo);

                // Create intermediate CA
                let intermediate = self.certificate_factory.create_certificate(
                    CertificateOptions::new()
                        .with_subject_name(intermediate_name)
                        .with_key_algorithm(inter_algo)
                        .with_key_size(inter_size)
                        .with_validity(options.intermediate_validity)
                        .as_ca(0)
                        .with_key_usage(KeyUsageFlags {
                            flags: KeyUsageFlags::KEY_CERT_SIGN.flags
                                | KeyUsageFlags::DIGITAL_SIGNATURE.flags,
                        })
                        .signed_by(root.clone()),
                )?;
                (intermediate.clone(), Some(intermediate))
            } else {
                (root.clone(), None)
            };

        // Create leaf certificate
        let leaf_algo = options.resolve_algorithm(options.leaf_key_algorithm);
        let leaf_size = options.resolve_key_size(options.leaf_key_size, leaf_algo);

        let mut leaf_opts = CertificateOptions::new()
            .with_subject_name(&options.leaf_name)
            .with_key_algorithm(leaf_algo)
            .with_key_size(leaf_size)
            .with_validity(options.leaf_validity)
            .with_key_usage(KeyUsageFlags::DIGITAL_SIGNATURE)
            .signed_by(leaf_issuer);

        if let Some(ekus) = options.leaf_enhanced_key_usages {
            leaf_opts = leaf_opts.with_enhanced_key_usages(ekus);
        }

        let leaf = self.certificate_factory.create_certificate(leaf_opts)?;

        // Optionally strip private keys from root and intermediate
        let mut result = Vec::new();
        let root_cert = if options.leaf_only_private_key {
            Certificate::new(root.cert_der)
        } else {
            root
        };

        let intermediate_cert = intermediate.map(|i| {
            if options.leaf_only_private_key {
                Certificate::new(i.cert_der)
            } else {
                i
            }
        });

        // Build result collection in configured order
        if options.leaf_first {
            result.push(leaf);
            if let Some(i) = intermediate_cert {
                result.push(i);
            }
            result.push(root_cert);
        } else {
            result.push(root_cert);
            if let Some(i) = intermediate_cert {
                result.push(i);
            }
            result.push(leaf);
        }

        Ok(result)
    }
}
