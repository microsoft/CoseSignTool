// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::TrustFactProducer;
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::{CoseHeaderLocation, CoseSign1Message};
use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::validation::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use crate::validation::fluent_ext::{X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt};
use crate::validation::pack::X509CertificateTrustPack;

/// Resolves COSE keys from X.509 certificate chains embedded in COSE messages.
pub struct X509CertificateCoseKeyResolver {
    _phantom: PhantomData<()>,
}

impl X509CertificateCoseKeyResolver {
    pub fn new() -> Self {
        Self { _phantom: PhantomData }
    }
}

impl Default for X509CertificateCoseKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CoseKeyResolver for X509CertificateCoseKeyResolver {
    /// Resolve the COSE key from an `x5chain` embedded in the COSE headers.
    ///
    /// This extracts the leaf certificate and creates a verification key using OpenSslCryptoProvider.
    fn resolve(
        &self,
        message: &CoseSign1Message,
        options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        let chain = match parse_x5chain_from_message(message, options.certificate_header_location) {
            Ok(v) => v,
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("X5CHAIN_NOT_FOUND".to_string()),
                    Some(e),
                )
            }
        };

        let Some(leaf) = chain.first() else {
            return CoseKeyResolutionResult::failure(
                Some("X5CHAIN_EMPTY".to_string()),
                Some("x5chain was present but empty".to_string()),
            );
        };

        let resolved_key = match extract_leaf_public_key_material(leaf.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("X509_PARSE_FAILED".to_string()),
                    Some(e),
                )
            }
        };

        // Extract public key from certificate using OpenSSL
        let public_pkey = match openssl::x509::X509::from_der(&resolved_key.spki_der) {
            Ok(cert) => match cert.public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    return CoseKeyResolutionResult::failure(
                        Some("PUBLIC_KEY_EXTRACTION_FAILED".to_string()),
                        Some(format!("Failed to extract public key: {}", e)),
                    );
                }
            },
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("CERT_PARSE_FAILED".to_string()),
                    Some(format!("Failed to parse certificate: {}", e)),
                );
            }
        };

        // Convert to DER format for the crypto provider
        let public_key_der = match public_pkey.public_key_to_der() {
            Ok(der) => der,
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("PUBLIC_KEY_DER_FAILED".to_string()),
                    Some(format!("Failed to convert public key to DER: {}", e)),
                );
            }
        };

        // Create verifier using OpenSslCryptoProvider.
        // For RSA keys, use the message's algorithm (PS256, RS256, etc.) since
        // the key type alone can't distinguish PSS from PKCS#1 v1.5.
        let msg_alg = message.alg().unwrap_or(0);
        let verifier = match cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
            &public_key_der, msg_alg,
        ) {
            Ok(v) => v,
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("VERIFIER_CREATION_FAILED".to_string()),
                    Some(format!("Failed to create verifier: {}", e)),
                );
            }
        };

        let verifier: Box<dyn crypto_primitives::CryptoVerifier> = Box::new(verifier);

        let mut out = CoseKeyResolutionResult::success(Arc::from(verifier));
        out.diagnostics.push("x509_verifier_resolved_via_openssl_crypto_provider".to_string());
        out
    }
}

struct LeafPublicKeyMaterial {
    /// Full certificate DER bytes (for OpenSSL)
    spki_der: Vec<u8>,
}

/// Parse the leaf certificate and return its DER bytes.
fn extract_leaf_public_key_material(cert_der: &[u8]) -> Result<LeafPublicKeyMaterial, String> {
    // Validate that the certificate can be parsed
    let (_rem, _cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("x509_parse_failed: {e}"))?;

    // Pass the full certificate DER to be parsed by OpenSSL later
    Ok(LeafPublicKeyMaterial {
        spki_der: cert_der.to_vec(),
    })
}

fn parse_x5chain_from_message(
    message: &CoseSign1Message,
    loc: CoseHeaderLocation,
) -> Result<Vec<Vec<u8>>, String> {
    const X5CHAIN_LABEL: CoseHeaderLabel = CoseHeaderLabel::Int(33);

    /// Try to extract x5chain certificates from a header value.
    fn extract_certs(value: &CoseHeaderValue) -> Result<Vec<Vec<u8>>, String> {
        match value {
            // Single certificate as byte string
            CoseHeaderValue::Bytes(cert) => Ok(vec![cert.clone()]),
            // Array of certificates
            CoseHeaderValue::Array(arr) => {
                let mut certs = Vec::new();
                for item in arr {
                    match item {
                        CoseHeaderValue::Bytes(cert) => certs.push(cert.clone()),
                        _ => return Err("x5chain array item is not a byte string".to_string()),
                    }
                }
                Ok(certs)
            }
            _ => Err("x5chain value is not a byte string or array".to_string()),
        }
    }

    /// Try to read x5chain from a header map.
    fn try_read_x5chain(headers: &CoseHeaderMap) -> Result<Option<Vec<Vec<u8>>>, String> {
        match headers.get(&X5CHAIN_LABEL) {
            Some(value) => Ok(Some(extract_certs(value)?)),
            None => Ok(None),
        }
    }

    match loc {
        CoseHeaderLocation::Protected => try_read_x5chain(message.protected.headers())?
            .ok_or_else(|| "x5chain not found in protected header".to_string()),
        CoseHeaderLocation::Any => {
            if let Some(v) = try_read_x5chain(message.protected.headers())? {
                return Ok(v);
            }
            if let Some(v) = try_read_x5chain(&message.unprotected)? {
                return Ok(v);
            }
            Err("x5chain not found in protected or unprotected header".to_string())
        }
    }
}

/// Return the current Unix timestamp in seconds.
///
/// If the system clock is before the Unix epoch, returns 0.
fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl CoseSign1TrustPack for X509CertificateTrustPack {
    /// Short display name for this trust pack.
    fn name(&self) -> &'static str {
        "X509CertificateTrustPack"
    }

    /// Return a `TrustFactProducer` instance for this pack.
    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(self.clone())
    }

    /// Provide COSE key resolvers contributed by this pack.
    fn cose_key_resolvers(&self) -> Vec<Arc<dyn CoseKeyResolver>> {
        vec![Arc::new(X509CertificateCoseKeyResolver::new())]
    }

    /// Return the default trust plan for certificate-based validation.
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        let now = now_unix_seconds();

        // Secure-by-default certificate policy:
        // - chain must be trusted (until OS trust is implemented, this defaults to false unless
        //   configured to trust embedded chains)
        // - signing certificate must be currently time-valid
        let bundled = TrustPlanBuilder::new(vec![Arc::new(self.clone())])
            .for_primary_signing_key(|key| {
                key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now))
            })
            .compile()
            .expect("default trust plan should be satisfiable by the certificates trust pack");

        Some(bundled.plan().clone())
    }
}
