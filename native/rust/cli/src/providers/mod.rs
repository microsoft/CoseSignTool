// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Provider abstractions for the CLI.
//!
//! Maps V2 C# `ISigningCommandProvider` + `IVerificationProvider`.
//! Instead of runtime plugin loading, Rust uses compile-time feature flags.

pub mod crypto;
pub mod signing;
pub mod verification;
pub mod output;

use std::sync::Arc;

/// A signing provider creates a `CryptoSigner` from CLI arguments.
pub trait SigningProvider {
    /// Short name for `--provider` dispatch (e.g., "der", "pfx", "akv").
    fn name(&self) -> &str;
    /// Description for help text.
    #[allow(dead_code)]
    fn description(&self) -> &str;
    /// Create a CryptoSigner from the provider-specific arguments.
    fn create_signer(&self, args: &SigningProviderArgs) -> Result<Box<dyn crypto_primitives::CryptoSigner>, anyhow::Error>;
    /// Create a CryptoSigner along with an optional certificate chain (DER-encoded certs).
    /// Providers that generate or load certificates should return the chain here
    /// so the sign command can embed x5chain in the COSE protected header.
    fn create_signer_with_chain(&self, args: &SigningProviderArgs) -> Result<SignerWithChain, anyhow::Error> {
        let signer = self.create_signer(args)?;
        Ok(SignerWithChain { signer, cert_chain: Vec::new() })
    }
}

/// A signer plus optional certificate chain for embedding in COSE headers.
pub struct SignerWithChain {
    pub signer: Box<dyn crypto_primitives::CryptoSigner>,
    /// DER-encoded certificate chain (signing cert first, then intermediates).
    pub cert_chain: Vec<Vec<u8>>,
}

/// Arguments passed to signing providers.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct SigningProviderArgs {
    // DER provider
    pub key_path: Option<std::path::PathBuf>,
    // PFX provider
    pub pfx_path: Option<std::path::PathBuf>,
    pub pfx_password: Option<String>,
    // PEM provider
    pub cert_file: Option<std::path::PathBuf>,
    pub key_file: Option<std::path::PathBuf>,
    // Cert store provider
    pub thumbprint: Option<String>,
    pub store_location: Option<String>,  // CurrentUser or LocalMachine
    pub store_name: Option<String>,      // My, Root, etc.
    // Ephemeral provider
    pub subject: Option<String>,
    pub algorithm: Option<String>,       // RSA, ECDSA, MLDSA
    pub key_size: Option<u32>,
    pub validity_days: Option<u32>,
    pub minimal: bool,
    pub pqc: bool,
    // AKV provider
    pub vault_url: Option<String>,
    /// AKV certificate name
    pub cert_name: Option<String>,
    /// AKV certificate version (optional)
    pub cert_version: Option<String>,
    /// AKV key name
    pub key_name: Option<String>,
    /// AKV key version (optional)
    pub key_version: Option<String>,
    // ATS provider
    pub ats_endpoint: Option<String>,
    pub ats_account: Option<String>,
    pub ats_profile: Option<String>,
}

/// A verification provider contributes trust packs and policy to the validator.
#[allow(dead_code)]
pub trait VerificationProvider {
    /// Short name (e.g., "certificates", "mst", "akv").
    fn name(&self) -> &str;
    /// Description for help text.
    fn description(&self) -> &str;
    /// Create a trust pack for this provider.
    fn create_trust_pack(
        &self,
        args: &VerificationProviderArgs,
    ) -> Result<Arc<dyn cose_sign1_validation::fluent::CoseSign1TrustPack>, anyhow::Error>;
}

/// Arguments passed to verification providers.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct VerificationProviderArgs {
    /// Allow embedded cert chains as trusted (testing only)
    pub allow_embedded: bool,
    /// Trusted root certificate paths
    pub trust_roots: Vec<std::path::PathBuf>,
    /// Allowed thumbprints for identity pinning
    pub allowed_thumbprints: Vec<String>,
    /// Whether MST receipt verification is required
    pub require_mst_receipt: bool,
    /// AKV allowed KID patterns
    pub akv_kid_patterns: Vec<String>,
    /// MST offline JWKS JSON content
    pub mst_offline_jwks: Option<String>,
    /// MST allowed ledger instances
    pub mst_ledger_instances: Vec<String>,
}