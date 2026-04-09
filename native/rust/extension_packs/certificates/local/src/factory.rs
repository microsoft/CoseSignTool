// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Ephemeral certificate factory for creating self-signed and issuer-signed certificates.

use crate::certificate::Certificate;
use crate::error::CertLocalError;
use crate::key_algorithm::KeyAlgorithm;
use crate::options::{CertificateOptions, HashAlgorithm, SigningPadding};
use crate::traits::{CertificateFactory, GeneratedKey, PrivateKeyProvider};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
    SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509Builder, X509Extension, X509NameBuilder, X509};
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

/// Helper: generate an ECDSA key pair for the given curve size.
///
/// Maps key_size to NIST curves:
/// - 256 (default) → P-256 (prime256v1)
/// - 384 → P-384 (secp384r1)
/// - 521 → P-521 (secp521r1)
///
/// Returns (PKey, private_key_der, public_key_der).
fn generate_ec_key(key_size: Option<u32>) -> EcKeyResult {
    let nid = match key_size.unwrap_or(256) {
        384 => Nid::SECP384R1,
        521 => Nid::SECP521R1,
        _ => Nid::X9_62_PRIME256V1,
    };
    let group = EcGroup::from_curve_name(nid)
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

/// Helper: generate an RSA key pair.
///
/// Maps key_size to RSA modulus bits:
/// - 2048 (default) → RSA-2048
/// - 3072 → RSA-3072
/// - 4096 → RSA-4096
///
/// Returns (PKey, private_key_der, public_key_der).
fn generate_rsa_key(
    key_size: Option<u32>,
) -> Result<(PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>), CertLocalError> {
    let bits = key_size.unwrap_or(2048);
    let rsa = Rsa::generate(bits)
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let pkey = PKey::from_rsa(rsa)
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let private_key_der = pkey
        .private_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let public_key_der = pkey
        .public_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    Ok((pkey, private_key_der, public_key_der))
}

/// Helper: generate an EdDSA key pair (Ed25519 or Ed448).
///
/// Maps key_size: 448 → Ed448, anything else → Ed25519 (default).
///
/// Returns (PKey, private_key_der, public_key_der).
fn generate_eddsa_key(
    key_size: Option<u32>,
) -> Result<(PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>), CertLocalError> {
    let pkey = match key_size.unwrap_or(255) {
        448 => PKey::generate_ed448(),
        _ => PKey::generate_ed25519(),
    }
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

/// Helper: generate an IETF composite key pair (ML-DSA + ECDSA).
///
/// Uses OpenSSL 3.5+ composite key provider. The algorithm name encodes
/// both components:
/// - 44 → MLDSA44-ECDSA-P256-SHA256
/// - 65 → MLDSA65-ECDSA-P384-SHA384
/// - 87 → MLDSA87-ECDSA-P384-SHA384
///
/// Returns (PKey, private_key_der, public_key_der).
#[cfg(feature = "composite")]
fn generate_composite_key(
    key_size: Option<u32>,
) -> Result<(PKey<openssl::pkey::Private>, Vec<u8>, Vec<u8>), CertLocalError> {
    use foreign_types::ForeignType;

    // Null-terminated C strings for OpenSSL API
    let alg_name: &[u8] = match key_size.unwrap_or(65) {
        44 => b"MLDSA44-ECDSA-P256-SHA256\0",
        87 => b"MLDSA87-ECDSA-P384-SHA384\0",
        _ => b"MLDSA65-ECDSA-P384-SHA384\0",
    };

    let pkey = unsafe {
        let ctx = openssl_sys::EVP_PKEY_CTX_new_from_name(
            std::ptr::null_mut(),
            alg_name.as_ptr() as *const std::os::raw::c_char,
            std::ptr::null(),
        );
        if ctx.is_null() {
            return Err(CertLocalError::KeyGenerationFailed(format!(
                "EVP_PKEY_CTX_new_from_name({}) failed — OpenSSL 3.5+ with composite provider required",
                String::from_utf8_lossy(&alg_name[..alg_name.len() - 1])
            )));
        }

        let rc = openssl_sys::EVP_PKEY_keygen_init(ctx);
        if rc != 1 {
            openssl_sys::EVP_PKEY_CTX_free(ctx);
            return Err(CertLocalError::KeyGenerationFailed(
                "EVP_PKEY_keygen_init failed for composite key".into(),
            ));
        }

        let mut pkey_raw: *mut openssl_sys::EVP_PKEY = std::ptr::null_mut();
        let rc = openssl_sys::EVP_PKEY_keygen(ctx, &mut pkey_raw);
        openssl_sys::EVP_PKEY_CTX_free(ctx);

        if rc != 1 || pkey_raw.is_null() {
            return Err(CertLocalError::KeyGenerationFailed(
                "EVP_PKEY_keygen failed for composite key".into(),
            ));
        }

        PKey::from_ptr(pkey_raw)
    };

    let private_key_der = pkey
        .private_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    let public_key_der = pkey
        .public_key_to_der()
        .map_err(|e| CertLocalError::KeyGenerationFailed(e.to_string()))?;
    Ok((pkey, private_key_der, public_key_der))
}

/// Resolves the MessageDigest from options.
fn resolve_digest(hash: HashAlgorithm) -> MessageDigest {
    match hash {
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
        HashAlgorithm::Sha384 => MessageDigest::sha384(),
        HashAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}

/// Signs an X509 builder with the appropriate method for the given algorithm.
///
/// Traditional algorithms (ECDSA, RSA with PKCS#1 v1.5) use `builder.sign()` with a digest.
/// RSA-PSS uses `X509_sign_ctx` with a PSS-configured signing context.
/// Pure signature algorithms (EdDSA, ML-DSA) use `sign_x509_null_digest`.
fn sign_x509_builder(
    builder: &mut X509Builder,
    pkey: &PKey<openssl::pkey::Private>,
    algorithm: KeyAlgorithm,
    hash: HashAlgorithm,
    padding: SigningPadding,
) -> Result<(), CertLocalError> {
    match algorithm {
        KeyAlgorithm::Ecdsa => builder
            .sign(pkey, resolve_digest(hash))
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string())),
        KeyAlgorithm::Rsa => match padding {
            SigningPadding::Pkcs1v15 => builder
                .sign(pkey, resolve_digest(hash))
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string())),
            SigningPadding::Pss => {
                // RSA-PSS requires X509_sign_ctx with a PSS-configured EVP_MD_CTX.
                // We sign with a dummy first so builder.build() succeeds, then
                // re-sign with PSS after building.
                builder
                    .sign(pkey, resolve_digest(hash))
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))
            }
        },
        KeyAlgorithm::EdDsa => {
            // EdDSA is a pure signature scheme — no external digest.
            // We return Ok here; actual signing happens after builder.build().
            Ok(())
        }
        #[cfg(feature = "pqc")]
        KeyAlgorithm::MlDsa => {
            // ML-DSA is a pure signature scheme — no external digest.
            // We return Ok here; actual signing happens after builder.build().
            Ok(())
        }
        #[cfg(feature = "composite")]
        KeyAlgorithm::Composite => {
            // Composite is a pure signature scheme — no external digest.
            // We return Ok here; actual signing happens after builder.build().
            Ok(())
        }
    }
}

/// Signs an already-built X509 certificate using null-digest (for pure signature algorithms).
///
/// EdDSA (Ed25519/Ed448) and ML-DSA don't use an external hash function.
/// OpenSSL handles these by passing NULL as the message digest to X509_sign.
///
/// # Safety
///
/// Uses openssl-sys FFI to call X509_sign with a null digest pointer.
fn sign_x509_null_digest(
    x509: &X509,
    pkey: &PKey<openssl::pkey::Private>,
) -> Result<(), CertLocalError> {
    use foreign_types::ForeignTypeRef;

    extern "C" {
        fn X509_sign(
            x: *mut openssl_sys::X509,
            pkey: *mut openssl_sys::EVP_PKEY,
            md: *const openssl_sys::EVP_MD,
        ) -> std::os::raw::c_int;
    }

    let rc = unsafe {
        X509_sign(
            x509.as_ptr() as *mut openssl_sys::X509,
            pkey.as_ptr() as *mut openssl_sys::EVP_PKEY,
            std::ptr::null(),
        )
    };
    if rc <= 0 {
        return Err(CertLocalError::CertificateCreationFailed(
            "X509_sign with null digest failed (pure signature algorithm)".into(),
        ));
    }
    Ok(())
}

/// Re-signs an already-built X509 certificate with RSA-PSS padding.
///
/// Uses EVP_DigestSignInit + EVP_PKEY_CTX_set_rsa_padding + X509_sign_ctx.
///
/// # Safety
///
/// Uses openssl-sys FFI to call EVP_DigestSignInit and X509_sign_ctx.
fn sign_x509_rsa_pss(
    x509: &X509,
    pkey: &PKey<openssl::pkey::Private>,
    hash: HashAlgorithm,
) -> Result<(), CertLocalError> {
    use foreign_types::ForeignTypeRef;

    extern "C" {
        fn X509_sign_ctx(
            x: *mut openssl_sys::X509,
            ctx: *mut openssl_sys::EVP_MD_CTX,
        ) -> std::os::raw::c_int;
    }

    let md = match hash {
        HashAlgorithm::Sha256 => unsafe { openssl_sys::EVP_sha256() },
        HashAlgorithm::Sha384 => unsafe { openssl_sys::EVP_sha384() },
        HashAlgorithm::Sha512 => unsafe { openssl_sys::EVP_sha512() },
    };

    unsafe {
        let ctx = openssl_sys::EVP_MD_CTX_new();
        if ctx.is_null() {
            return Err(CertLocalError::CertificateCreationFailed(
                "EVP_MD_CTX_new failed".into(),
            ));
        }

        let mut pkey_ctx: *mut openssl_sys::EVP_PKEY_CTX = std::ptr::null_mut();
        let rc = openssl_sys::EVP_DigestSignInit(
            ctx,
            &mut pkey_ctx,
            md,
            std::ptr::null_mut(),
            pkey.as_ptr() as *mut _,
        );
        if rc != 1 {
            openssl_sys::EVP_MD_CTX_free(ctx);
            return Err(CertLocalError::CertificateCreationFailed(
                "EVP_DigestSignInit failed for RSA-PSS".into(),
            ));
        }

        // RSA_PKCS1_PSS_PADDING = 6
        let rc = openssl_sys::EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, 6);
        if rc != 1 {
            openssl_sys::EVP_MD_CTX_free(ctx);
            return Err(CertLocalError::CertificateCreationFailed(
                "EVP_PKEY_CTX_set_rsa_padding(PSS) failed".into(),
            ));
        }

        // RSA_PSS_SALTLEN_AUTO = -2
        let rc = openssl_sys::EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -2);
        if rc != 1 {
            openssl_sys::EVP_MD_CTX_free(ctx);
            return Err(CertLocalError::CertificateCreationFailed(
                "EVP_PKEY_CTX_set_rsa_pss_saltlen failed".into(),
            ));
        }

        let rc = X509_sign_ctx(x509.as_ptr() as *mut openssl_sys::X509, ctx);
        openssl_sys::EVP_MD_CTX_free(ctx);

        if rc <= 0 {
            return Err(CertLocalError::CertificateCreationFailed(
                "X509_sign_ctx failed for RSA-PSS".into(),
            ));
        }
    }
    Ok(())
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
            KeyAlgorithm::Ecdsa => generate_ec_key(options.key_size)?,
            KeyAlgorithm::Rsa => generate_rsa_key(options.key_size)?,
            KeyAlgorithm::EdDsa => generate_eddsa_key(options.key_size)?,
            #[cfg(feature = "pqc")]
            KeyAlgorithm::MlDsa => generate_mldsa_key(&options.key_size)?,
            #[cfg(feature = "composite")]
            KeyAlgorithm::Composite => generate_composite_key(options.key_size)?,
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

        // Basic constraints and key usage
        if options.is_ca {
            // CA certificate: BasicConstraints CA:TRUE + keyCertSign + cRLSign
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
        } else {
            // End-entity (leaf) certificate: BasicConstraints CA:FALSE + digitalSignature
            let bc = BasicConstraints::new()
                .critical()
                .build()
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
            builder
                .append_extension(bc)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

            let ku = KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
            builder
                .append_extension(ku)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        }

        // Extended Key Usage (EKU)
        if !options.enhanced_key_usages.is_empty() {
            let mut eku = ExtendedKeyUsage::new();
            for oid in &options.enhanced_key_usages {
                match oid.as_str() {
                    "1.3.6.1.5.5.7.3.1" => { eku.server_auth(); }
                    "1.3.6.1.5.5.7.3.2" => { eku.client_auth(); }
                    "1.3.6.1.5.5.7.3.3" => { eku.code_signing(); }
                    "1.3.6.1.5.5.7.3.4" => { eku.email_protection(); }
                    "1.3.6.1.5.5.7.3.8" => { eku.time_stamping(); }
                    other => { eku.other(other); }
                }
            }
            builder
                .append_extension(
                    eku.build()
                        .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?,
                )
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        }

        // Subject Alternative Names (SANs)
        if !options.subject_alternative_names.is_empty() {
            let mut san = SubjectAlternativeName::new();
            for name in &options.subject_alternative_names {
                if let Some(email) = name.strip_prefix("email:") {
                    san.email(email);
                } else if let Some(uri) = name.strip_prefix("URI:") {
                    san.uri(uri);
                } else if let Some(ip) = name.strip_prefix("IP:") {
                    san.ip(ip);
                } else {
                    san.dns(name);
                }
            }
            builder
                .append_extension(
                    san.build(&builder.x509v3_context(None, None))
                        .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?,
                )
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        }

        // Subject Key Identifier (SKI) — hash of the subject's public key
        let ski = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        builder
            .append_extension(ski)
            .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

        // Custom X.509v3 extensions
        for ext in &options.custom_extensions {
            let oid = openssl::asn1::Asn1Object::from_str(&ext.oid)
                .map_err(|e| CertLocalError::CertificateCreationFailed(format!(
                    "invalid OID {}: {}", ext.oid, e
                )))?;
            let octet_string = openssl::asn1::Asn1OctetString::new_from_bytes(&ext.value)
                .map_err(|e| CertLocalError::CertificateCreationFailed(format!(
                    "failed to create octet string for extension {}: {}", ext.oid, e
                )))?;
            let extension = X509Extension::new_from_der(&oid, ext.critical, &octet_string)
                .map_err(|e| CertLocalError::CertificateCreationFailed(format!(
                    "failed to create custom extension {}: {}", ext.oid, e
                )))?;
            builder
                .append_extension(extension)
                .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
        }

        // Set issuer name and sign
        let (signing_key, issuer_x509) = if let Some(issuer) = &options.issuer {
            if let Some(issuer_key_der) = &issuer.private_key_der {
                let issuer_pkey = PKey::private_key_from_der(issuer_key_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to load issuer key: {}", e
                    ))
                })?;
                let issuer_cert = X509::from_der(&issuer.cert_der).map_err(|e| {
                    CertLocalError::CertificateCreationFailed(format!(
                        "failed to parse issuer cert: {}", e
                    ))
                })?;
                builder
                    .set_issuer_name(issuer_cert.subject_name())
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

                // Authority Key Identifier (AKI) — links to the issuer's key
                let aki = AuthorityKeyIdentifier::new()
                    .keyid(false)
                    .build(&builder.x509v3_context(Some(&issuer_cert), None))
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;
                builder
                    .append_extension(aki)
                    .map_err(|e| CertLocalError::CertificateCreationFailed(e.to_string()))?;

                sign_x509_builder(
                    &mut builder,
                    &issuer_pkey,
                    options.key_algorithm,
                    options.hash_algorithm,
                    options.signing_padding,
                )?;
                (issuer_pkey, Some(issuer_cert))
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
            sign_x509_builder(
                &mut builder,
                &pkey,
                options.key_algorithm,
                options.hash_algorithm,
                options.signing_padding,
            )?;
            (pkey.clone(), None)
        };

        let x509 = builder.build();

        // Post-build re-signing for pure signature algorithms and RSA-PSS
        if options.key_algorithm.is_pure_signature() {
            match options.key_algorithm {
                KeyAlgorithm::EdDsa => {
                    sign_x509_null_digest(&x509, &signing_key)?;
                }
                #[cfg(feature = "pqc")]
                KeyAlgorithm::MlDsa => {
                    resign_x509_prehash(&x509, &signing_key)?;
                }
                #[cfg(feature = "composite")]
                KeyAlgorithm::Composite => {
                    // Composite uses null digest like EdDSA/ML-DSA
                    sign_x509_null_digest(&x509, &signing_key)?;
                }
                _ => {}
            }
        } else if matches!(options.key_algorithm, KeyAlgorithm::Rsa)
            && matches!(options.signing_padding, SigningPadding::Pss)
        {
            sign_x509_rsa_pss(&x509, &signing_key, options.hash_algorithm)?;
        }

        let _ = issuer_x509; // consumed above for AKI context

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
