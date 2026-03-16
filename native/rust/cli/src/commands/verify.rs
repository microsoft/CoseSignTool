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

    /// Skip X.509 chain trust validation (verify signature only, testing/debugging)
    #[arg(long)]
    pub allow_untrusted: bool,

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

#[cfg_attr(coverage_nightly, coverage(off))]
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

    // 4. Collect trust packs from ALL available providers.
    // The trust plan DSL handles OR composition between different trust models.
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    let providers = available_providers();
    
    for provider in &providers {
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

    // 5. Build trust policy from CLI flags using AND/OR composition.
    //
    // The trust plan DSL composes different trust models:
    // - X509 chain trust:  for_primary_signing_key(chain_trusted AND cert_valid)
    // - MST receipt trust:  for_counter_signature(receipt_trusted)
    //
    // When both are requested, they compose as:
    //   (X509 chain trusted AND cert valid) OR (MST receipt trusted)
    //
    // This mirrors V2 C# where trust plan composition handles all combinations
    // without any pipeline bypasses or provider filtering.
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

    // Compose trust model(s) via OR semantics:
    //
    // X509 trust: for_primary_signing_key(chain_trusted AND cert_valid)
    // MST trust:  for_counter_signature(receipt_trusted)
    //
    // When --require-mst-receipt is set, MST receipt trust is an alternative
    // to X509 chain trust. The plan evaluates as:
    //   (X509 rules) OR (MST receipt rules)
    // If either path succeeds, trust passes.

    // X509 chain trust (always added when trust roots are provided or allow-embedded)
    let has_x509_trust = !args.allowed_thumbprint.is_empty()
        || !provider_args.trust_roots.is_empty()
        || args.allow_embedded
        || args.allow_untrusted;

    if has_x509_trust {
        trust_plan_builder = trust_plan_builder.for_primary_signing_key(|key| {
            // When --allow-untrusted, skip both chain trust AND cert validity checks.
            // Just require the signing key to be resolvable. Signature verification
            // happens in Stage 3 regardless.
            let mut rules = if args.allow_untrusted {
                key.allow_all()
            } else {
                key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now))
            };

            if let Some(first_thumbprint) = args.allowed_thumbprint.first() {
                rules = rules.and().require::<X509SigningCertificateIdentityFact>(|f| {
                    f.thumbprint_eq(first_thumbprint)
                });
            }

            rules
        });
    }

    // MST receipt trust (alternative via OR when --require-mst-receipt is set)
    #[cfg(feature = "mst")]
    {
        if args.require_mst_receipt {
            use cose_sign1_transparent_mst::validation::fluent_ext::*;
            use cose_sign1_transparent_mst::validation::facts::*;

            // If we already have X509 trust rules, compose with OR
            if has_x509_trust {
                trust_plan_builder = trust_plan_builder.or();
            }

            // MST receipt trust via counter-signature — mirrors MstTrustPack::default_trust_plan()
            trust_plan_builder = trust_plan_builder.for_counter_signature(|cs| {
                cs.require::<MstReceiptTrustedFact>(|f| f.require_receipt_trusted())
            });
        }
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
