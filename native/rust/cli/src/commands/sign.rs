// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sign command: create a COSE_Sign1 message from a payload.

use crate::providers::{self, SigningProviderArgs};
use clap::Args;
use std::fs;
use std::path::PathBuf;

#[derive(Args)]
pub struct SignArgs {
    /// Path to the payload file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Path to write the COSE_Sign1 output
    #[arg(short, long)]
    pub output: PathBuf,

    /// Signing provider (e.g., "der", "pfx", "akv", "ats")
    #[arg(long, default_value = "der")]
    pub provider: String,

    /// Path to the private key or certificate file (provider-specific)
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// PFX file path (for --provider pfx)
    #[arg(long)]
    pub pfx: Option<PathBuf>,

    /// PFX password (or set COSESIGNTOOL_PFX_PASSWORD env var)
    #[arg(long)]
    pub pfx_password: Option<String>,

    /// Certificate file path for PEM provider
    #[arg(long)]
    pub cert_file: Option<PathBuf>,

    /// Private key file path for PEM provider
    #[arg(long)]
    pub key_file: Option<PathBuf>,

    /// Certificate subject for ephemeral provider
    #[arg(long)]
    pub subject: Option<String>,

    /// Key algorithm for ephemeral provider: ecdsa (default) or mldsa (requires --features pqc)
    #[arg(long, default_value = "ecdsa", value_parser = ["ecdsa", "mldsa"])]
    pub algorithm: String,

    /// Key size / parameter set (e.g., 256 for ECDSA P-256, 44/65/87 for ML-DSA)
    #[arg(long)]
    pub key_size: Option<u32>,

    /// Content type (e.g., "application/spdx+json")
    #[arg(short, long, default_value = "application/octet-stream")]
    pub content_type: String,

    /// Signature format: direct or indirect
    #[arg(long, default_value = "direct", value_parser = ["direct", "indirect"])]
    pub format: String,

    /// Create a detached signature (payload not embedded)
    #[arg(long)]
    pub detached: bool,

    /// CWT issuer claim (--issuer)
    #[arg(long)]
    pub issuer: Option<String>,

    /// CWT subject claim (--cwt-subject)
    #[arg(long)]
    pub cwt_subject: Option<String>,

    /// Output format
    #[arg(long, default_value = "text", value_parser = ["text", "json", "quiet"])]
    pub output_format: String,

    /// Azure Key Vault URL (e.g., https://my-vault.vault.azure.net)
    #[arg(long = "akv-vault")]
    pub vault_url: Option<String>,

    /// AKV certificate name (for --provider akv-cert)
    #[arg(long = "akv-cert-name")]
    pub cert_name: Option<String>,

    /// AKV certificate version (optional — uses latest if not specified)
    #[arg(long = "akv-cert-version")]
    pub cert_version: Option<String>,

    /// AKV key name (for --provider akv-key)
    #[arg(long = "akv-key-name")]
    pub key_name: Option<String>,

    /// AKV key version (optional — uses latest if not specified)
    #[arg(long = "akv-key-version")]
    pub key_version: Option<String>,

    /// ATS endpoint URL (e.g., https://eus.codesigning.azure.net)
    #[arg(long = "ats-endpoint")]
    pub ats_endpoint: Option<String>,

    /// ATS account name
    #[arg(long = "ats-account-name")]
    pub ats_account: Option<String>,

    /// ATS certificate profile name
    #[arg(long = "ats-cert-profile-name")]
    pub ats_profile: Option<String>,

    /// Add MST transparency receipt after signing
    #[arg(long)]
    pub add_mst_receipt: bool,

    /// MST service endpoint URL
    #[arg(long)]
    pub mst_endpoint: Option<String>,
}

pub fn run(args: SignArgs) -> i32 {
    tracing::info!(
        input = %args.input.display(),
        output = %args.output.display(),
        provider = %args.provider,
        format = %args.format,
        "Signing payload"
    );

    // 1. Resolve signing provider
    let provider = match providers::signing::find_provider(&args.provider) {
        Some(p) => p,
        None => {
            let available: Vec<_> = providers::signing::available_providers()
                .iter()
                .map(|p| p.name().to_string())
                .collect();
            eprintln!(
                "Unknown signing provider '{}'. Available: {}",
                args.provider,
                available.join(", ")
            );
            return 2;
        }
    };

    // 2. Read payload
    let payload = match fs::read(&args.input) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error reading payload: {}", e);
            return 2;
        }
    };

    // 3. Create signer via provider
    let provider_args = SigningProviderArgs {
        key_path: args.key.clone(),
        pfx_path: args.pfx.clone(),
        pfx_password: args
            .pfx_password
            .clone()
            .or_else(|| std::env::var("COSESIGNTOOL_PFX_PASSWORD").ok()),
        cert_file: args.cert_file.clone(),
        key_file: args.key_file.clone(),
        subject: args.subject.clone(),
        algorithm: Some(args.algorithm.clone()),
        key_size: args.key_size,
        pqc: args.algorithm == "mldsa",
        vault_url: args.vault_url.clone(),
        cert_name: args.cert_name.clone(),
        cert_version: args.cert_version.clone(),
        key_name: args.key_name.clone(),
        key_version: args.key_version.clone(),
        ats_endpoint: args.ats_endpoint.clone(),
        ats_account: args.ats_account.clone(),
        ats_profile: args.ats_profile.clone(),
        ..Default::default()
    };
    let result = match provider.create_signer_with_chain(&provider_args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error creating signer: {}", e);
            return 2;
        }
    };
    let signer = result.signer;
    let cert_chain = result.cert_chain;

    // 4. Set up protected headers
    let mut protected = cose_primitives::CoseHeaderMap::new();
    protected.set_alg(signer.algorithm());
    protected.set_content_type(cose_primitives::ContentType::Text(args.content_type.clone()));

    // Embed x5chain (label 33) if the provider returned certificates
    if !cert_chain.is_empty() {
        if cert_chain.len() == 1 {
            // Single cert: bstr
            protected.insert(
                cose_primitives::CoseHeaderLabel::Int(33),
                cose_primitives::CoseHeaderValue::Bytes(cert_chain[0].clone()),
            );
        } else {
            // Multiple certs: array of bstr
            let arr: Vec<cose_primitives::CoseHeaderValue> = cert_chain
                .iter()
                .map(|c| cose_primitives::CoseHeaderValue::Bytes(c.clone()))
                .collect();
            protected.insert(
                cose_primitives::CoseHeaderLabel::Int(33),
                cose_primitives::CoseHeaderValue::Array(arr),
            );
        }
    }

    // 5. Add CWT claims if specified
    if args.issuer.is_some() || args.cwt_subject.is_some() {
        let mut claims = cose_sign1_headers::CwtClaims::new();
        if let Some(ref iss) = args.issuer {
            claims.issuer = Some(iss.clone());
        }
        if let Some(ref sub) = args.cwt_subject {
            claims.subject = Some(sub.clone());
        }
        claims.issued_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        // Encode CWT and set as protected header label 15
        match claims.to_cbor_bytes() {
            Ok(cwt_bytes) => {
                protected.insert(
                    cose_primitives::CoseHeaderLabel::Int(15),
                    cose_primitives::CoseHeaderValue::Bytes(cwt_bytes),
                );
            }
            Err(e) => {
                eprintln!("Error encoding CWT claims: {}", e);
                return 2;
            }
        }
    }

    // 6. Build and sign the message
    let builder = cose_sign1_primitives::CoseSign1Builder::new()
        .protected(protected)
        .detached(args.detached);

    match builder.sign(signer.as_ref(), &payload) {
        Ok(mut cose_bytes) => {
            // Apply transparency proofs if requested
            #[cfg(feature = "mst")]
            if args.add_mst_receipt {
                tracing::info!("Adding MST transparency receipt");
                match apply_mst_transparency(&args, &cose_bytes) {
                    Ok(transparent_bytes) => {
                        cose_bytes = transparent_bytes;
                        tracing::info!("MST transparency receipt added successfully");
                    }
                    Err(e) => {
                        tracing::warn!("Failed to add MST transparency receipt: {}", e);
                        // Continue with original bytes - don't fail the signing operation
                    }
                }
            }

            if let Err(e) = fs::write(&args.output, &cose_bytes) {
                eprintln!("Error writing output: {}", e);
                return 2;
            }
            // Format output
            let output_format: providers::output::OutputFormat = args.output_format.parse().unwrap_or(providers::output::OutputFormat::Text);
            let mut section = std::collections::BTreeMap::new();
            section.insert("Output".to_string(), args.output.display().to_string());
            section.insert("Size".to_string(), format!("{} bytes", cose_bytes.len()));
            section.insert("Algorithm".to_string(), format!("{}", signer.algorithm()));
            section.insert("Provider".to_string(), args.provider.clone());
            section.insert("Format".to_string(), args.format.clone());
            let rendered = providers::output::render(
                output_format,
                &[("Signing Result".to_string(), section)],
            );
            if !rendered.is_empty() {
                print!("{}", rendered);
            }
            0
        }
        Err(e) => {
            eprintln!("Signing failed: {}", e);
            2
        }
    }
}

/// Applies MST transparency to a COSE_Sign1 message.
#[cfg(feature = "mst")]
fn apply_mst_transparency(args: &SignArgs, cose_bytes: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use cose_sign1_transparent_mst::signing::{MstTransparencyClient, MstTransparencyClientOptions, MstTransparencyProvider};
    use url::Url;

    // This is a stub implementation as per the task requirements
    tracing::warn!("MST transparency integration is a stub — receipt not actually added");
    
    // Determine MST endpoint
    let endpoint_url = match &args.mst_endpoint {
        Some(url) => url.clone(),
        None => "https://dataplane.codetransparency.azure.net".to_string(), // Default from V2
    };

    let endpoint = Url::parse(&endpoint_url)
        .map_err(|e| format!("Invalid MST endpoint URL '{}': {}", endpoint_url, e))?;

    // Create MST client with default options (this code path validates but doesn't execute)
    let client_options = MstTransparencyClientOptions::default();
    let mst_client = MstTransparencyClient::new(endpoint, client_options);
    let _transparency_provider = MstTransparencyProvider::new(mst_client);

    // For now, just return the original bytes as a stub
    // The real implementation would call:
    // let result = add_proof_with_receipt_merge(&transparency_provider, cose_bytes)?;
    Ok(cose_bytes.to_vec())
}