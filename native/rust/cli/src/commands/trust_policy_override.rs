// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `--trust-policy` override (per design decision D8) — load a `.coseTrustPolicy.json`
//! document, validate + translate via `cose_sign1_trustfrontends_json`, bind any
//! `$param` references the document carries, compile against a registry assembled
//! from the configured trust packs' fact producers, and bundle the resulting plan
//! with the same packs.

use anyhow::{bail, Context, Result};
use cose_sign1_trust_policy_spec::{
    bind, compile, HandRolledFactRegistry, TrustPolicyTranslationContext,
    TrustPolicyTranslationResult,
};
use cose_sign1_trustfrontends_json::CoseTpJsonFrontend;
use cose_sign1_trustfrontends_rego::CoseTpRegoFrontend;
use cose_sign1_validation::fluent::{CoseSign1CompiledTrustPlan, CoseSign1TrustPack};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Load a trust-policy document from disk, translate it, and compile it into a
/// [`CoseSign1CompiledTrustPlan`] bundled with `trust_packs` for evaluation.
///
/// Errors surface as `anyhow::Error` carrying the diagnostic chain — every TPX code
/// from the frontend reaches the CLI verbatim.
///
/// Frontend dispatch (per design decision D8) is media-type-driven: the
/// `.coseTrustPolicy.rego` file extension or a leading
/// `package cose_trust_policy` header routes to
/// [`CoseTpRegoFrontend`]; everything else falls through to
/// [`CoseTpJsonFrontend`] (the default Phase 2 path).
pub fn compile_override(
    document_path: &str,
    parameter_args: &[String],
    trust_packs: Vec<Arc<dyn CoseSign1TrustPack>>,
) -> Result<CoseSign1CompiledTrustPlan> {
    let text = std::fs::read_to_string(document_path)
        .with_context(|| format!("Failed to read trust-policy document: {document_path}"))?;

    let parameters = parse_parameter_args(parameter_args)?;

    let mut ctx = TrustPolicyTranslationContext::empty();
    ctx.allow_unknown_facts = true; // hosts can advertise capability sets externally;
    // for the CLI we always trust the user's document and let `compile()` enforce the
    // capability check via the registry.

    let result = if is_rego_document(document_path, &text) {
        CoseTpRegoFrontend::new().translate_text(&text, &ctx, Some(document_path))
    } else {
        CoseTpJsonFrontend::new().translate_text(&text, &ctx, Some(document_path))
    };

    let result: TrustPolicyTranslationResult = result;
    if !result.is_success() {
        let message = result
            .diagnostics
            .iter()
            .map(|d| format!("[{}] {}", d.code, d.message))
            .collect::<Vec<_>>()
            .join("\n  ");
        bail!(
            "Trust-policy translation failed for {document_path}:\n  {message}",
        );
    }
    let spec = result
        .spec
        .expect("is_success guarantees Some(spec)");

    // Bind $param references against the user-supplied parameter map.
    let bound = bind(spec, &parameters)
        .map_err(|err| anyhow::anyhow!("Trust-policy parameter binding failed: {err}"))?;

    // Build a HandRolledFactRegistry from the configured packs' fact producers plus
    // the message-level facts shipped by validation/core.
    let registry = build_registry();

    let compiled = compile(&bound, &registry)
        .map_err(|err| anyhow::anyhow!("Trust-policy compile failed: {err}"))?;

    CoseSign1CompiledTrustPlan::from_parts(compiled, trust_packs).map_err(|err| {
        anyhow::anyhow!(
            "Trust-policy compile produced fact requirements that the configured packs cannot satisfy: {err}",
        )
    })
}

fn parse_parameter_args(args: &[String]) -> Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    for arg in args {
        let (key, raw_value) = arg
            .split_once('=')
            .with_context(|| format!("Invalid --trust-policy-param '{arg}': expected key=value"))?;
        if key.is_empty() {
            bail!("Invalid --trust-policy-param '{arg}': key must not be empty");
        }
        // Values try JSON parse first (so `--trust-policy-param max_age=5` binds as
        // a number); fall back to string literal when the JSON parse fails.
        let value: Value = serde_json::from_str(raw_value)
            .unwrap_or_else(|_| Value::String(raw_value.to_owned()));
        out.insert(key.to_owned(), value);
    }
    Ok(out)
}

fn build_registry() -> HandRolledFactRegistry {
    let mut packs: Vec<Vec<cose_sign1_validation_primitives::TrustFactDescriptor>> = Vec::new();
    packs.push(cose_sign1_validation::__cose_sign1_trust_facts());
    packs.push(cose_sign1_certificates::__cose_sign1_trust_facts());
    #[cfg(feature = "mst")]
    packs.push(cose_sign1_transparent_mst::__cose_sign1_trust_facts());

    HandRolledFactRegistry::from_packs(&packs)
        .expect("workspace fact registry must be construct-able from the bundled packs")
}

/// Frontend dispatch — recognises a `.coseTrustPolicy.rego` document by
/// extension OR by a leading `package cose_trust_policy` header (per
/// design decision D8 / §6.5.6).
///
/// The sniff is intentionally narrow: file-extension match is definitive,
/// and the package-header fallback handles documents that arrived without
/// a recognisable extension (e.g. piped from stdin via a future
/// `--trust-policy -` extension). Returning `false` falls through to the
/// JSON frontend, which preserves the Phase 2 default path verbatim.
fn is_rego_document(path: &str, source: &str) -> bool {
    cose_sign1_trustfrontends_rego::sniff_media_type(Some(path), Some(source))
        == Some(cose_sign1_trustfrontends_rego::MEDIA_TYPE_REGO)
}
