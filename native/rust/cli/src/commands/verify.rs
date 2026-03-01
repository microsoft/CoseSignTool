// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verify command: validate a COSE_Sign1 message.

use clap::Args;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the COSE_Sign1 message file
    #[arg(short, long)]
    pub input: PathBuf,

    /// Path to detached payload (if not embedded)
    #[arg(short, long)]
    pub payload: Option<PathBuf>,

    /// Path to trusted root certificate (DER) — can specify multiple
    #[arg(long, action = clap::ArgAction::Append)]
    pub trust_root: Vec<PathBuf>,

    /// Allow embedded certificate chain as trusted (testing only)
    #[arg(long)]
    pub allow_embedded: bool,

    /// Require content-type header to be present
    #[arg(long)]
    pub require_content_type: bool,

    /// Required content-type value (implies --require-content-type)
    #[arg(long)]
    pub content_type: Option<String>,

    /// Require CWT claims header to be present
    #[arg(long)]
    pub require_cwt: bool,

    /// Required CWT issuer value
    #[arg(long)]
    pub require_issuer: Option<String>,

    /// Require MST receipt to be present
    #[cfg_attr(feature = "mst", arg(long))]
    #[cfg(feature = "mst")]
    pub require_mst_receipt: bool,

    /// Allowed certificate thumbprints (identity pinning)
    #[arg(long, action = clap::ArgAction::Append)]
    pub allowed_thumbprint: Vec<String>,

    /// Require Azure Key Vault KID pattern match
    #[cfg_attr(feature = "akv", arg(long))]
    #[cfg(feature = "akv")]
    pub require_akv_kid: bool,

    /// Allowed AKV KID patterns (repeatable)
    #[cfg_attr(feature = "akv", arg(long, action = clap::ArgAction::Append))]
    #[cfg(feature = "akv")]
    pub akv_allowed_vault: Vec<String>,

    /// Pinned MST signing keys JWKS JSON file
    #[cfg_attr(feature = "mst", arg(long))]
    #[cfg(feature = "mst")]
    pub mst_offline_keys: Option<PathBuf>,

    /// Allowed MST ledger instances (repeatable)
    #[cfg_attr(feature = "mst", arg(long, action = clap::ArgAction::Append))]
    #[cfg(feature = "mst")]
    pub mst_ledger_instance: Vec<String>,

    /// Output format
    #[arg(long, default_value = "text", value_parser = ["text", "json", "quiet"])]
    pub output_format: String,
}

pub fn run(args: VerifyArgs) -> i32 {
    #[cfg(not(feature = "certificates"))]
    {
        eprintln!("Verification requires the 'certificates' feature to be enabled");
        return 2;
    }
    
    #[cfg(feature = "certificates")]
    {
        run_with_certificates(args)
    }
}

#[cfg(feature = "certificates")]
fn run_with_certificates(args: VerifyArgs) -> i32 {
    use cose_sign1_validation::fluent::*;
    use cose_sign1_certificates::validation::facts::*;
    use cose_sign1_certificates::validation::fluent_ext::*;
    use crate::providers::verification::available_providers;
    use crate::providers::{VerificationProviderArgs};
    use crate::providers::output::{OutputFormat, OutputSection, render};
    
    tracing::info!(input = %args.input.display(), "Verifying COSE_Sign1 message");

    // 1. Read COSE bytes
    let cose_bytes = match fs::read(&args.input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading input: {}", e);
            return 2;
        }
    };

    // 2. Read detached payload if provided
    let detached_payload = args.payload.as_ref().map(|p| {
        match fs::read(p) {
            Ok(data) => {
                let memory_payload = cose_sign1_primitives::payload::MemoryPayload::new(data);
                cose_sign1_validation::fluent::Payload::Streaming(Box::new(memory_payload) as Box<dyn cose_sign1_validation::fluent::StreamingPayload>)
            },
            Err(e) => {
                eprintln!("Error reading payload: {}", e);
                std::process::exit(2);
            }
        }
    });

    // 3. Set up verification provider args
    #[cfg(feature = "mst")]
    let mst_offline_jwks = if let Some(path) = &args.mst_offline_keys {
        match std::fs::read_to_string(path) {
            Ok(content) => Some(content),
            Err(e) => {
                eprintln!("Error reading MST offline keys file: {}", e);
                return 2;
            }
        }
    } else {
        None
    };

    #[cfg(not(feature = "mst"))]
    let mst_offline_jwks = None;

    let provider_args = VerificationProviderArgs {
        allow_embedded: args.allow_embedded,
        trust_roots: args.trust_root,
        allowed_thumbprints: args.allowed_thumbprint.clone(),
        #[cfg(feature = "mst")]
        require_mst_receipt: args.require_mst_receipt,
        #[cfg(not(feature = "mst"))]
        require_mst_receipt: false,
        #[cfg(feature = "akv")]
        akv_kid_patterns: args.akv_allowed_vault.clone(),
        #[cfg(not(feature = "akv"))]
        akv_kid_patterns: Vec::new(),
        mst_offline_jwks,
        #[cfg(feature = "mst")]
        mst_ledger_instances: args.mst_ledger_instance.clone(),
        #[cfg(not(feature = "mst"))]
        mst_ledger_instances: Vec::new(),
    };

    // Determine trust model based on CLI flags:
    // - If --require-mst-receipt is set (and no explicit trust roots), MST receipt IS the trust.
    //   The MST receipt counter-signature provides trust, not X509 chain trust.
    // - Otherwise, use standard X509 chain trust.
    #[cfg(feature = "mst")]
    let mst_is_trust = args.require_mst_receipt && provider_args.trust_roots.is_empty();
    #[cfg(not(feature = "mst"))]
    let mst_is_trust = false;

    // 4. Collect trust packs from available providers
    // When MST is the trust model, skip the certificates provider — MST receipt
    // verification via counter-signatures provides trust instead of X509 chain trust.
    // The validator's counter-signature bypass path handles this automatically when
    // no primary key resolver is present.
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    let providers = available_providers();
    
    for provider in &providers {
        if mst_is_trust && provider.name() == "certificates" {
            tracing::info!(provider = provider.name(), "Skipping — MST receipt is the trust mechanism");
            continue;
        }
        match provider.create_trust_pack(&provider_args) {
            Ok(pack) => {
                tracing::info!(provider = provider.name(), "Added trust pack");
                trust_packs.push(pack);
            },
            Err(e) => {
                eprintln!("Failed to create trust pack for {}: {}", provider.name(), e);
                return 2;
            }
        }
    }

    if trust_packs.is_empty() {
        eprintln!("No trust packs available");
        return 2;
    }

    // 5. Build trust policy from CLI flags
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64;

    let mut trust_plan_builder = TrustPlanBuilder::new(trust_packs);

    // Add message-scope requirements based on CLI flags
    if args.require_content_type {
        trust_plan_builder = trust_plan_builder.for_message(|msg| {
            msg.require_content_type_non_empty()
        });
    }
    
    if let Some(content_type) = &args.content_type {
        trust_plan_builder = trust_plan_builder.for_message(|msg| {
            msg.require_content_type_eq(content_type)
        });
    }

    if args.require_cwt {
        trust_plan_builder = trust_plan_builder.for_message(|msg| {
            msg.require_cwt_claims_present()
        });
    }

    if let Some(issuer) = &args.require_issuer {
        let issuer_owned = issuer.clone();
        trust_plan_builder = trust_plan_builder.for_message(|msg| {
            msg.require_cwt_claim("iss", move |claim| {
                claim.try_as_str().map_or(false, |text| text == issuer_owned)
            })
        });
    }

    // Add MST receipt requirement if enabled
    #[cfg(feature = "mst")]
    {
        if args.require_mst_receipt {
            use cose_sign1_transparent_mst::validation::fluent_ext::*;
            use cose_sign1_transparent_mst::validation::facts::*;
            
            trust_plan_builder = trust_plan_builder.for_message(|msg| {
                msg.require::<MstReceiptPresentFact>(|f| f.require_receipt_present())
            });
        }
    }

    // Add AKV KID requirements if enabled
    #[cfg(feature = "akv")]
    {
        if args.require_akv_kid {
            use cose_sign1_azure_key_vault::validation::fluent_ext::*;
            use cose_sign1_azure_key_vault::validation::facts::*;
            
            trust_plan_builder = trust_plan_builder.for_message(|msg| {
                msg.require::<AzureKeyVaultKidDetectedFact>(|f| f.require_azure_key_vault_kid())
                   .and()
                   .require::<AzureKeyVaultKidAllowedFact>(|f| f.require_kid_allowed())
            });
        }
    }

    // Add primary signing key requirements based on trust model
    if mst_is_trust {
        // MST trust model: The MST receipt attests the signature was registered
        // in the transparency ledger, providing trust. We don't require X509
        // chain trust or cert validity — the receipt IS the trust anchor.
        // No for_primary_signing_key rules needed.
    } else {
        // Standard X509 trust model: require chain trust + valid cert identity.
        trust_plan_builder = trust_plan_builder.for_primary_signing_key(|key| {
            let mut rules = key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                .and()
                .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now));

            if let Some(first_thumbprint) = args.allowed_thumbprint.first() {
                rules = rules.and().require::<X509SigningCertificateIdentityFact>(|f| {
                    f.thumbprint_eq(first_thumbprint)
                });
            }

            rules
        });
    }

    let compiled_plan = match trust_plan_builder.compile() {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("Trust plan compilation failed: {}", e);
            return 2;
        }
    };

    // 6. Create validator with detached payload if provided
    let mut validator = CoseSign1Validator::new(compiled_plan);
    if let Some(payload) = detached_payload {
        validator = validator.with_options(|o| {
            o.detached_payload = Some(payload);
        });
    }
    // When MST is the trust model, bypass X509 trust evaluation.
    // MST receipt verification happens in the post-signature stage via the MST trust pack.
    if mst_is_trust {
        validator = validator.with_options(|o| {
            o.trust_evaluation_options.bypass_trust = true;
        });
    }

    // 7. Run validation
    let result = match validator.validate_bytes(cbor_primitives_everparse::EverParseCborProvider, Arc::from(cose_bytes.into_boxed_slice())) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Validation error: {}", e);
            return 2;
        }
    };

    // 8. Format output using structured formatter
    let output_format: OutputFormat = args.output_format.parse().unwrap_or(OutputFormat::Text);
    let mut section = OutputSection::new();
    
    section.insert("Input".to_string(), args.input.display().to_string());
    if let Some(payload_path) = &args.payload {
        section.insert("Payload".to_string(), payload_path.display().to_string());
    }
    section.insert("Resolution".to_string(), format!("{:?}", result.resolution.kind));
    section.insert("Trust".to_string(), format!("{:?}", result.trust.kind));
    section.insert("Signature".to_string(), format!("{:?}", result.signature.kind));
    section.insert("Post-signature".to_string(), format!("{:?}", result.post_signature_policy.kind));
    section.insert("Overall".to_string(), format!("{:?}", result.overall.kind));

    let rendered = render(output_format, &[("Verification Result".to_string(), section)]);
    if !rendered.is_empty() {
        print!("{}", rendered);
    }

    // Show any failures
    for stage in [&result.resolution, &result.trust, &result.signature, &result.post_signature_policy, &result.overall] {
        if stage.kind == ValidationResultKind::Failure {
            eprintln!("{} failures:", stage.validator_name);
            for failure in &stage.failures {
                eprintln!("  - {}", failure.message);
            }
        }
    }

    // Return appropriate exit code
    if result.overall.is_valid() {
        if output_format != OutputFormat::Quiet {
            eprintln!("✓ Signature verified successfully");
        }
        0
    } else {
        eprintln!("✗ Validation failed");
        1
    }
}