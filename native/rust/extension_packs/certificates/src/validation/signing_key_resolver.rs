// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! X.509 certificate COSE key resolver — extracts verification keys from
//! `x5chain` headers embedded in COSE Sign1 messages and builds the
//! default certificate trust plan.

use cose_sign1_primitives::headers::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue};
use cose_sign1_primitives::ArcSlice;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::facts::TrustFactProducer;
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::{CoseHeaderLocation, CoseSign1Message};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::validation::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use crate::validation::fluent_ext::{
    X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt,
};
use crate::validation::pack::X509CertificateTrustPack;

/// Resolves COSE keys from X.509 certificate chains embedded in COSE messages.
#[derive(Default)]
pub struct X509CertificateCoseKeyResolver {
    _phantom: PhantomData<()>,
}

impl X509CertificateCoseKeyResolver {
    /// Creates a new resolver instance.
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
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
                return CoseKeyResolutionResult::failure(Some("X5CHAIN_NOT_FOUND".into()), Some(e))
            }
        };

        let Some(leaf) = chain.first() else {
            return CoseKeyResolutionResult::failure(
                Some("X5CHAIN_EMPTY".into()),
                Some("x5chain was present but empty".into()),
            );
        };

        let resolved_key = match extract_leaf_public_key_material(leaf) {
            Ok(v) => v,
            Err(e) => {
                return CoseKeyResolutionResult::failure(Some("X509_PARSE_FAILED".into()), Some(e))
            }
        };

        // Extract public key from certificate using OpenSSL
        let public_pkey = match openssl::x509::X509::from_der(resolved_key.cert_arc.as_bytes()) {
            Ok(cert) => match cert.public_key() {
                Ok(pk) => pk,
                Err(e) => {
                    return CoseKeyResolutionResult::failure(
                        Some("PUBLIC_KEY_EXTRACTION_FAILED".into()),
                        Some(format!("Failed to extract public key: {}", e)),
                    );
                }
            },
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("CERT_PARSE_FAILED".into()),
                    Some(format!("Failed to parse certificate: {}", e)),
                );
            }
        };

        // Convert to DER format for the crypto provider
        let public_key_der = match public_pkey.public_key_to_der() {
            Ok(der) => der,
            Err(e) => {
                return CoseKeyResolutionResult::failure(
                    Some("PUBLIC_KEY_DER_FAILED".into()),
                    Some(format!("Failed to convert public key to DER: {}", e)),
                );
            }
        };

        // Create verifier using the message's algorithm when available.
        // This matters for RSA keys where the key type alone can't distinguish
        // RS* (PKCS#1 v1.5) from PS* (PSS). If the message has no algorithm,
        // fall back to auto-detection from the key type.
        let msg_alg = message.alg();
        let verifier = if let Some(alg) = msg_alg {
            // Use the message's algorithm directly
            match cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
                &public_key_der,
                alg,
            ) {
                Ok(v) => v,
                Err(e) => {
                    return CoseKeyResolutionResult::failure(
                        Some("VERIFIER_CREATION_FAILED".into()),
                        Some(format!("Failed to create verifier: {}", e)),
                    );
                }
            }
        } else {
            // No algorithm in message — use auto-detection from key type
            use crypto_primitives::CryptoProvider;
            let provider = cose_sign1_crypto_openssl::OpenSslCryptoProvider;
            match provider.verifier_from_der(&public_key_der) {
                Ok(v) => {
                    // verifier_from_der returns Box<dyn CryptoVerifier>, we need EvpVerifier
                    // Re-create with the auto-detected algorithm
                    let detected_alg = v.algorithm();
                    match cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
                        &public_key_der,
                        detected_alg,
                    ) {
                        Ok(ev) => ev,
                        Err(e) => {
                            return CoseKeyResolutionResult::failure(
                                Some("VERIFIER_CREATION_FAILED".into()),
                                Some(format!("Failed to create verifier: {}", e)),
                            );
                        }
                    }
                }
                Err(e) => {
                    return CoseKeyResolutionResult::failure(
                        Some("VERIFIER_CREATION_FAILED".into()),
                        Some(format!("Failed to create verifier: {}", e)),
                    );
                }
            }
        };

        let verifier: Box<dyn crypto_primitives::CryptoVerifier> = Box::new(verifier);

        let mut out = CoseKeyResolutionResult::success(Arc::from(verifier));
        out.diagnostics
            .push("x509_verifier_resolved_via_openssl_crypto_provider".into());
        out
    }
}

struct LeafPublicKeyMaterial {
    /// Certificate DER bytes (zero-copy ArcSlice from message buffer).
    cert_arc: ArcSlice,
}

/// Parse the leaf certificate and return its DER bytes as a zero-copy ArcSlice.
fn extract_leaf_public_key_material(cert: &ArcSlice) -> Result<LeafPublicKeyMaterial, String> {
    // Validate that the certificate can be parsed
    let (_rem, _cert) = x509_parser::parse_x509_certificate(cert.as_bytes())
        .map_err(|e| format!("x509_parse_failed: {e}"))?;

    // Return the ArcSlice directly — zero allocation
    Ok(LeafPublicKeyMaterial {
        cert_arc: cert.clone(),
    })
}

fn parse_x5chain_from_message(
    message: &CoseSign1Message,
    loc: CoseHeaderLocation,
) -> Result<Vec<ArcSlice>, String> {
    const X5CHAIN_LABEL: CoseHeaderLabel = CoseHeaderLabel::Int(33);

    /// Try to extract x5chain certificates as zero-copy ArcSlices.
    fn extract_certs(value: &CoseHeaderValue) -> Result<Vec<ArcSlice>, String> {
        match value {
            CoseHeaderValue::Bytes(cert) => Ok(vec![cert.clone()]),
            CoseHeaderValue::Array(arr) => {
                let mut certs = Vec::new();
                for item in arr {
                    match item {
                        CoseHeaderValue::Bytes(cert) => certs.push(cert.clone()),
                        _ => return Err("x5chain array item is not a byte string".into()),
                    }
                }
                Ok(certs)
            }
            _ => Err("x5chain value is not a byte string or array".into()),
        }
    }

    fn try_read_x5chain(headers: &CoseHeaderMap) -> Result<Option<Vec<ArcSlice>>, String> {
        match headers.get(&X5CHAIN_LABEL) {
            Some(value) => Ok(Some(extract_certs(value)?)),
            None => Ok(None),
        }
    }

    match loc {
        CoseHeaderLocation::Protected => try_read_x5chain(message.protected.headers())?
            .ok_or_else(|| "x5chain not found in protected header".into()),
        CoseHeaderLocation::Any => {
            if let Some(v) = try_read_x5chain(message.protected.headers())? {
                return Ok(v);
            }
            if let Some(v) = try_read_x5chain(message.unprotected.headers())? {
                return Ok(v);
            }
            Err("x5chain not found in protected or unprotected header".into())
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
        let bundled = match TrustPlanBuilder::new(vec![Arc::new(self.clone())])
            .for_primary_signing_key(|key| {
                key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now))
            })
            .compile()
        {
            Ok(b) => b,
            Err(_) => return None,
        };

        Some(bundled.plan().clone())
    }
}
