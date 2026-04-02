// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ephemeral certificate factory for creating self-signed and issuer-signed certificates.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::options::CertificateOptions;
use crate::traits::{CertificateFactory, GeneratedKey, PrivateKeyProvider};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
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

type EcKeyResult = Result<(PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>), CertLocalError>;

/// Helper: generate an ECDSA P-256 key pair, returning (PKey, private_key_der, public_key_der).
fn generate_ec_p256_key() -> EcKeyResult {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let ec_key =
        EcKey::generate(&group).map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let private_key_der = pkey
        .private_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let public_key_der = pkey
        .public_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    Ok((pkey, private_key_der, public_key_der))
}

/// Helper: generate an ML-DSA key pair, returning (PKey, private_key_der, public_key_der).
#[cfg(feature = "pqc")]
fn generate_mldsa_key(
    key_size: &Option<u32>,
) -> Result<(PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>), CertLocalError> {
    use cose_sign1_crypto_openssl::{generate_mldsa_key_der, MlDsaVariant};

    let variant = match key_size.unwrap_or(65) {
        44 => MlDsaVariant::MlDsa44,
        87 => MlDsaVariant::MlDsa87,
        _ => MlDsaVariant::MlDsa65,
    };

    let (private_der, public_der) =
        generate_mldsa_key_der(variant).map_err(CertLocalError::KeyGenerationFailed)?;

    let pkey = PKey::private_key_from_der(&private_der)
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;

    Ok((pkey, private_der, public_der))
}

/// Signs an X509 builder with the appropriate method for the given algorithm.
///
/// Traditional algorithms (ECDSA, RSA) use `builder.sign()` with a digest.
/// Pure signature algorithms (ML-DSA) use `sign_x509_prehash` with a null digest.
fn sign_x509_builder(
    builder: &mut X509Builder,
    pkey: &PKey<openssl::pkey::Private>,
    algorithm: KeyAlgorithm,
) -> Result<(), CertLocalError> {
    match algorithm {
        KeyAlgorithm::Ecdsa | KeyAlgorithm::Rsa => builder
            .sign(pkey, MessageDigest::sha256())
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string())),
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa => {
            // ML-DSA is a pure signature scheme — no external digest.
            // We must build the cert first, then sign it via the crypto_openssl API
            // that calls X509_sign with NULL md.
            //
            // However, X509Builder::build() consumes the builder. So we use a
            // workaround: sign with a dummy digest first (OpenSSL will overwrite
            // the signature when we re-sign), then re-sign after build().
            //
            // Actually, X509Builder requires sign() before build() for the cert to
            // be well-formed. For pure-sig algorithms, we call sign_x509_prehash
            // on the already-built X509. The builder is consumed by build() below,
            // so we set a flag here and handle the signing after build().
            //
            // Since we can't skip builder.sign() (it would produce an unsigned cert),
            // and builder.build() consumes the builder, we'll just return Ok here
            // and do the actual signing in the caller after build().
            Ok(())
        }
    }
}

/// Re-signs an already-built X509 certificate for pure signature algorithms (ML-DSA).
#[cfg(feature = "pqc")]
fn resign_x509_prehash(
    x509: &openssl::x509::X509,
    pkey: &PKey<openssl::pkey::Private>,
) -> Result<(), CertLocalError> {
    cose_sign1_crypto_openssl::sign_x509_prehash(x509, pkey)
        .map_err(|e| CertLocalError::CertificateCreationFailed(e))
}

impl CertificateFactory for EphemeralCertificateFactory {
    fn key_provider(&self) -> &dyn PrivateKeyProvider {
        self.key_provider.as_ref()
    }

    fn create_certificate(
        &self,
        options: CertificateOptions,
    ) -> Result<Certificate, CertLocalError> {
        // Generate key pair based on algorithm
        let (pkey, private_key_der, public_key_der) = match options.key_algorithm {
            KeyAlgorithm::Ecdsa => generate_ec_p256_key()?,
            KeyAlgorithm::Rsa => {
                return Err(CertLocalError::UnsupportedAlgorithm(
                    "RSA key generation is not yet implemented".into(),
                ));
            }
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => generate_mldsa_key(&options.key_size)?,
        };

        // Build the X.509 certificate
        let mut builder = X509Builder::new()
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Set version to V3
        builder
            .set_version(2) // 0-indexed: 2 == v3
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Random serial number
        let mut serial =
            BigNum::new().map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        serial
            .rand(128, MsbOption::MAYBE_ZERO, false)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        let serial_asn1 = serial
            .to_asn1_integer()
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        builder
            .set_serial_number(&serial_asn1)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Build subject name
        let mut name_builder = X509NameBuilder::new()
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        let subject = &options.subject_name;
        let cn_value = subject.strip_prefix("CN=").unwrap_or(subject);
        name_builder
            .append_entry_by_text("CN", cn_value)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        let subject_name = name_builder.build();
        builder
            .set_subject_name(&subject_name)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Set validity
        let not_before_secs = -(options.not_before_offset.as_secs() as i64);
        let not_after_secs = options.validity.as_secs() as i64;
        let not_before =
            Asn1Time::from_unix(time::OffsetDateTime::now_utc().unix_timestamp() + not_before_secs)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        let not_after =
            Asn1Time::from_unix(time::OffsetDateTime::now_utc().unix_timestamp() + not_after_secs)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        builder
            .set_not_before(&not_before)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        builder
            .set_not_after(&not_after)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Set public key
        builder
            .set_pubkey(&pkey)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Basic constraints
        if options.is_ca {
            let mut bc = BasicConstraints::new();
            bc.critical().ca();
            if options.path_length_constraint < u32::MAX {
                bc.pathlen(options.path_length_constraint);
            }
            builder
                .append_extension(
                    bc.build()
                        .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?,
                )
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

            let ku = KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
            builder
                .append_extension(ku)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        }

        // Set issuer name and sign
        if let Some(issuer) = &options.issuer {
            if let Some(issuer_key_der) = &issuer.private_key_der {
                // Load issuer private key
                let issuer_pkey = PKey::private_key_from_der(issuer_key_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to load issuer key: {}",
                        e
                    ))
                })?;

                // Parse issuer cert to get its subject as our issuer name
                let issuer_x509 = X509::from_der(&issuer.cert_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to parse issuer cert: {}",
                        e
                    ))
                })?;
                builder
                    .set_issuer_name(issuer_x509.subject_name())
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

                sign_x509_builder(&mut builder, &issuer_pkey, options.key_algorithm)?;
            } else {
                return Err(CertLocalError::CertificateCreationFailed(
                    "issuer certificate must have a private key".into(),
                ));
            }
        } else {
            // Self-signed: issuer == subject
            builder
                .set_issuer_name(&subject_name)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
            sign_x509_builder(&mut builder, &pkey, options.key_algorithm)?;
        }

        let x509 = builder.build();

        // For pure-sig algorithms, sign the built certificate via crypto_openssl
        #[cfg(feature = "pqc")]
        if matches!(options.key_algorithm, KeyAlgorithm::MlDsa) {
            let sign_key = if options.issuer.is_some() {
                // Issuer-signed: re-load the issuer key for signing
                let issuer_key_der = options
                    .issuer
                    .as_ref()
                    .unwrap()
                    .private_key_der
                    .as_ref()
                    .unwrap();
                PKey::private_key_from_der(issuer_key_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to reload issuer key for ML-DSA signing: {}",
                        e
                    ))
                })?
            } else {
                // Self-signed
                PKey::private_key_from_der(&private_key_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to reload key for ML-DSA signing: {}",
                        e
                    ))
                })?
            };
            resign_x509_prehash(&x509, &sign_key)?;
        }

        let cert_der = x509
            .to_der()
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Store the generated key by serial number
        let serial_hex = {
            use x509_parser::prelude::*;
            let (_, parsed) = X509Certificate::from_der(&cert_der).map_err(|e| {
                CertLocalError::CertificateCreationFailed(format!("failed to parse cert: {}", e))
            })?;
            parsed
                .serial
                .to_bytes_be()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>()
        };

        let generated_key = GeneratedKey {
            private_key_der: private_key_der.clone(),
            public_key_der,
            algorithm: options.key_algorithm,
            key_size: options
                .key_size
                .unwrap_or_else(|| options.key_algorithm.default_key_size()),
        };

        if let Ok(mut keys) = self.generated_keys.lock() {
            keys.insert(serial_hex, generated_key);
        }

        Ok(Certificate::with_private_key(cert_der, private_key_der))
    }
}
