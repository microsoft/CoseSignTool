// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ephemeral certificate factory for creating self-signed and issuer-signed certificates.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::options::CertificateOptions;
use crate::traits::{CertificateFactory, GeneratedKey, PrivateKeyProvider};
use rcgen::{CertificateParams, DnType, IsCa, KeyPair};
use std::collections::HashMap;
use std::sync::Mutex;

/// Factory for creating ephemeral (in-memory) X.509 certificates.
///
/// Creates self-signed or issuer-signed certificates suitable for testing,
/// development, and scenarios where temporary certificates are acceptable.
///
/// Maps V2 C# `EphemeralCertificateFactory`.
pub struct EphemeralCertificateFactory {
    /// The key provider used for generating keys.
    key_provider: Box<dyn PrivateKeyProvider>,
    /// Generated keys indexed by certificate serial number (hex).
    generated_keys: Mutex<HashMap<String, GeneratedKey>>,
}

impl EphemeralCertificateFactory {
    /// Creates a new ephemeral certificate factory with the specified key provider.
    pub fn new(key_provider: Box<dyn PrivateKeyProvider>) -> Self {
        Self {
            key_provider,
            generated_keys: Mutex::new(HashMap::new()),
        }
    }

    /// Retrieves a previously generated key by certificate serial number (hex).
    pub fn get_generated_key(&self, serial_hex: &str) -> Option<GeneratedKey> {
        self.generated_keys
            .lock()
            .ok()
            .and_then(|keys| keys.get(serial_hex).cloned())
    }

    /// Releases a generated key by certificate serial number (hex).
    /// Returns true if the key was found and released.
    pub fn release_key(&self, serial_hex: &str) -> bool {
        self.generated_keys
            .lock()
            .ok()
            .map(|mut keys| keys.remove(serial_hex).is_some())
            .unwrap_or(false)
    }
}

impl CertificateFactory for EphemeralCertificateFactory {
    fn key_provider(&self) -> &dyn PrivateKeyProvider {
        self.key_provider.as_ref()
    }

    fn create_certificate(&self, options: CertificateOptions) -> Result<Certificate, CertLocalError> {
        // Check if the algorithm is supported
        match options.key_algorithm {
            KeyAlgorithm::Ecdsa => {} // Supported
            KeyAlgorithm::Rsa => {
                return Err(CertLocalError::UnsupportedAlgorithm(
                    "RSA key generation is not supported with ring backend".to_string(),
                ));
            }
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => {
                return Err(CertLocalError::UnsupportedAlgorithm(
                    "ML-DSA is not yet implemented".to_string(),
                ));
            }
        }

        // Generate a key pair (ECDSA P-256)
        let key_pair = KeyPair::generate()
            .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
        let private_key_der = key_pair.serialize_der();
        let public_key_der = key_pair.public_key_der().to_vec();

        // Build certificate parameters
        let mut params = CertificateParams::default();

        // Parse subject name - simple CN= extraction
        let subject = &options.subject_name;
        if let Some(cn_value) = subject.strip_prefix("CN=") {
            params.distinguished_name.push(DnType::CommonName, cn_value);
        } else {
            params.distinguished_name.push(DnType::CommonName, subject);
        }

        // Set validity
        let now = time::OffsetDateTime::now_utc();
        let not_before = now - time::Duration::seconds(options.not_before_offset.as_secs() as i64);
        let not_after = now + time::Duration::seconds(options.validity.as_secs() as i64);
        params.not_before = not_before;
        params.not_after = not_after;

        // Set CA status
        if options.is_ca {
            params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(
                options.path_length_constraint as u8,
            ));
        } else {
            params.is_ca = IsCa::NoCa;
        }

        // Generate the certificate
        let cert = if let Some(issuer) = &options.issuer {
            // Signed by issuer - we need the issuer's key pair
            if let Some(issuer_key_der) = &issuer.private_key_der {
                let issuer_key = KeyPair::try_from(issuer_key_der.as_slice())
                    .map_err(|e| CertLocalError::CertificateCreationFailed(
                        format!("failed to load issuer key: {}", e)
                    ))?;
                
                // Create issuer certificate params for signing
                let mut issuer_params = CertificateParams::default();
                let issuer_subject = issuer.subject()
                    .unwrap_or_else(|_| "CN=Unknown Issuer".to_string());
                if let Some(cn_value) = issuer_subject.strip_prefix("CN=") {
                    issuer_params.distinguished_name.push(DnType::CommonName, cn_value);
                } else {
                    issuer_params.distinguished_name.push(DnType::CommonName, &issuer_subject);
                }
                issuer_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
                
                let issuer_cert = issuer_params.self_signed(&issuer_key)
                    .map_err(|e| CertLocalError::CertificateCreationFailed(
                        format!("failed to create issuer cert for signing: {}", e)
                    ))?;

                params.signed_by(&key_pair, &issuer_cert, &issuer_key)
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?
            } else {
                return Err(CertLocalError::CertificateCreationFailed(
                    "issuer certificate must have a private key".to_string(),
                ));
            }
        } else {
            // Self-signed
            params.self_signed(&key_pair)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?
        };

        let cert_der = cert.der().to_vec();

        // Store the generated key by serial number
        let serial_hex = {
            use x509_parser::prelude::*;
            let (_, parsed) = X509Certificate::from_der(&cert_der)
                .map_err(|e| CertLocalError::CertificateCreationFailed(format!("failed to parse cert: {}", e)))?;
            parsed.serial
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
        };

        let generated_key = GeneratedKey {
            private_key_der: private_key_der.clone(),
            public_key_der,
            algorithm: options.key_algorithm,
            key_size: options.key_size.unwrap_or_else(|| options.key_algorithm.default_key_size()),
        };

        if let Ok(mut keys) = self.generated_keys.lock() {
            keys.insert(serial_hex, generated_key);
        }

        Ok(Certificate::with_private_key(cert_der, private_key_der))
    }
}
