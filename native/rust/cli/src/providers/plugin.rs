// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin-backed signing service adapters.

use crate::plugin_host::{PluginProcess, PluginRegistry};
use anyhow::{anyhow, Context, Result};
use cose_sign1_certificates::signing::CertificateHeaderContributor;
use cose_sign1_signing::{
    CoseSigner, HeaderContributor, HeaderContributorContext, SigningContext, SigningError,
    SigningService, SigningServiceMetadata,
};
use cosesigntool_plugin_api::traits::PluginConfig;
use crypto_primitives::{CryptoError, CryptoSigner, CryptoVerifier};
use openssl::x509::X509;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub struct PluginSigningService {
    process: Arc<Mutex<PluginProcess>>,
    service_id: String,
    algorithm: i64,
    certificate_chain: Vec<Vec<u8>>,
    metadata: SigningServiceMetadata,
}

impl PluginSigningService {
    fn new(
        process: Arc<Mutex<PluginProcess>>,
        service_id: String,
        algorithm: i64,
        certificate_chain: Vec<Vec<u8>>,
        service_name: String,
        service_description: String,
    ) -> Self {
        Self {
            process,
            service_id,
            algorithm,
            certificate_chain,
            metadata: SigningServiceMetadata::new(service_name, service_description),
        }
    }
}

pub fn create_plugin_service(
    registry: &PluginRegistry,
    command_name: &str,
    options: &HashMap<String, String>,
) -> Result<PluginSigningService> {
    let (plugin_id, _) = registry
        .find_signing_command(command_name)
        .ok_or_else(|| anyhow!("No signing plugin command named '{command_name}' is available"))?;
    let process = registry
        .get(plugin_id.as_str())
        .ok_or_else(|| anyhow!("Signing plugin '{plugin_id}' is no longer available"))?;

    let (service_name, service_description, service_id, algorithm, certificate_chain) = {
        let mut process_guard = process
            .lock()
            .map_err(|_| anyhow!("Signing plugin '{plugin_id}' is unavailable"))?;
        let service_id = process_guard
            .create_service(&PluginConfig {
                options: options.clone(),
            })
            .with_context(|| format!("Failed to create signing service for '{command_name}'"))?;
        let algorithm = process_guard
            .get_algorithm(service_id.as_str())
            .with_context(|| format!("Failed to get signing algorithm for '{command_name}'"))?;
        let certificate_chain = process_guard
            .get_cert_chain(service_id.as_str())
            .with_context(|| format!("Failed to get certificate chain for '{command_name}'"))?;
        if certificate_chain.is_empty() {
            return Err(anyhow!(
                "Signing plugin '{plugin_id}' did not return an X.509 certificate chain"
            ));
        }

        (
            process_guard.info.name.clone(),
            process_guard.info.description.clone(),
            service_id,
            algorithm,
            certificate_chain,
        )
    };

    Ok(PluginSigningService::new(
        process,
        service_id,
        algorithm,
        certificate_chain,
        service_name,
        service_description,
    ))
}

impl SigningService for PluginSigningService {
    fn get_cose_signer(&self, context: &SigningContext<'_>) -> Result<CoseSigner, SigningError> {
        let signer: Arc<dyn CryptoSigner> = Arc::new(PluginCryptoSigner {
            process: self.process.clone(),
            service_id: self.service_id.clone(),
            algorithm: self.algorithm,
        });
        let contributor_context = HeaderContributorContext::new(context, signer.as_ref());

        let mut protected_headers = cose_sign1_primitives::CoseHeaderMap::new();
        let mut unprotected_headers = cose_sign1_primitives::CoseHeaderMap::new();
        protected_headers.set_alg(self.algorithm);

        let certificate = self.certificate_chain.first().ok_or_else(|| SigningError::SigningFailed {
            detail: "plugin certificate chain is empty".into(),
        })?;
        let chain_refs: Vec<&[u8]> = self
            .certificate_chain
            .iter()
            .map(|certificate_der| certificate_der.as_slice())
            .collect();
        let certificate_contributor = CertificateHeaderContributor::new(certificate, &chain_refs)
            .map_err(|error| SigningError::SigningFailed {
                detail: error.to_string().into(),
            })?;
        certificate_contributor
            .contribute_protected_headers(&mut protected_headers, &contributor_context);

        for contributor in &context.additional_header_contributors {
            contributor.contribute_protected_headers(&mut protected_headers, &contributor_context);
            contributor.contribute_unprotected_headers(&mut unprotected_headers, &contributor_context);
        }

        Ok(CoseSigner::new(
            Box::new(ArcPluginSignerWrapper { signer }),
            protected_headers,
            unprotected_headers,
        ))
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn service_metadata(&self) -> &SigningServiceMetadata {
        &self.metadata
    }

    fn verify_signature(
        &self,
        message_bytes: &[u8],
        _context: &SigningContext<'_>,
    ) -> Result<bool, SigningError> {
        let message = cose_sign1_primitives::CoseSign1Message::parse(message_bytes).map_err(|error| {
            SigningError::VerificationFailed {
                detail: format!("failed to parse COSE_Sign1: {error}").into(),
            }
        })?;
        let certificate_der = self.certificate_chain.first().ok_or_else(|| {
            SigningError::VerificationFailed {
                detail: "plugin certificate chain is empty".into(),
            }
        })?;
        let x509 = X509::from_der(certificate_der).map_err(|error| SigningError::VerificationFailed {
            detail: format!("failed to parse certificate: {error}").into(),
        })?;
        let public_key_der = x509
            .public_key()
            .map_err(|error| SigningError::VerificationFailed {
                detail: format!("failed to extract public key: {error}").into(),
            })?
            .public_key_to_der()
            .map_err(|error| SigningError::VerificationFailed {
                detail: format!("failed to encode public key: {error}").into(),
            })?;
        let verifier = cose_sign1_crypto_openssl::evp_verifier::EvpVerifier::from_der(
            public_key_der.as_slice(),
            self.algorithm,
        )
        .map_err(|error| SigningError::VerificationFailed {
            detail: format!("verifier creation: {error}").into(),
        })?;
        let payload = message.payload().unwrap_or_default();
        let sig_structure = message.sig_structure_bytes(payload, None).map_err(|error| {
            SigningError::VerificationFailed {
                detail: format!("sig_structure: {error}").into(),
            }
        })?;

        verifier
            .verify(sig_structure.as_slice(), message.signature())
            .map_err(|error| SigningError::VerificationFailed {
                detail: format!("verify: {error}").into(),
            })
    }
}

struct PluginCryptoSigner {
    process: Arc<Mutex<PluginProcess>>,
    service_id: String,
    algorithm: i64,
}

impl CryptoSigner for PluginCryptoSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut process = self.process.lock().map_err(|_| {
            CryptoError::SigningFailed("plugin signer is unavailable".into())
        })?;
        process
            .sign(self.service_id.as_str(), data, self.algorithm)
            .map_err(|error| CryptoError::SigningFailed(error.to_string()))
    }

    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn key_type(&self) -> &str {
        "remote"
    }
}

struct ArcPluginSignerWrapper {
    signer: Arc<dyn CryptoSigner>,
}

impl CryptoSigner for ArcPluginSignerWrapper {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.signer.sign(data)
    }

    fn algorithm(&self) -> i64 {
        self.signer.algorithm()
    }

    fn key_id(&self) -> Option<&[u8]> {
        self.signer.key_id()
    }

    fn key_type(&self) -> &str {
        self.signer.key_type()
    }
}