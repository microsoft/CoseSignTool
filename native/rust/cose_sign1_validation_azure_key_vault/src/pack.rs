// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use once_cell::sync::Lazy;
use regex::Regex;
use url::Url;

pub mod fluent_ext {
    pub use crate::fluent_ext::*;
}

pub const KID_HEADER_LABEL: i64 = 4;

#[derive(Debug, Clone)]
pub struct AzureKeyVaultTrustOptions {
    pub allowed_kid_patterns: Vec<String>,
    pub require_azure_key_vault_kid: bool,
}

impl Default for AzureKeyVaultTrustOptions {
    fn default() -> Self {
        // Secure-by-default: only allow Microsoft-owned Key Vault namespaces.
        Self {
            allowed_kid_patterns: vec![
                "https://*.vault.azure.net/keys/*".to_string(),
                "https://*.managedhsm.azure.net/keys/*".to_string(),
            ],
            require_azure_key_vault_kid: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AzureKeyVaultTrustPack {
    options: AzureKeyVaultTrustOptions,
    compiled_patterns: Option<Vec<Regex>>,
}

impl AzureKeyVaultTrustPack {
    pub fn new(options: AzureKeyVaultTrustOptions) -> Self {
        let mut compiled = Vec::new();

        for pattern in &options.allowed_kid_patterns {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                continue;
            }

            if pattern.to_ascii_lowercase().starts_with("regex:") {
                let re = Regex::new(&pattern["regex:".len()..])
                    .map_err(|e| TrustError::FactProduction(format!("invalid_regex: {e}")));
                if let Ok(re) = re {
                    compiled.push(re);
                }
                continue;
            }

            let escaped = regex::escape(pattern)
                .replace("\\*", ".*")
                .replace("\\?", ".");

            let re = Regex::new(&format!("^{escaped}(/.*)?$"))
                .map_err(|e| TrustError::FactProduction(format!("invalid_pattern_regex: {e}")));
            if let Ok(re) = re {
                compiled.push(re);
            }
        }

        let compiled_patterns = if compiled.is_empty() {
            None
        } else {
            Some(compiled)
        };
        Self {
            options,
            compiled_patterns,
        }
    }

    fn try_get_kid_utf8(ctx: &TrustFactContext<'_>) -> Option<String> {
        let msg = ctx.cose_sign1_message()?;

        if let Some(v) = msg.protected_header.get(KID_HEADER_LABEL) {
            if let Some(b) = v.as_bytes() {
                if let Ok(s) = std::str::from_utf8(b) {
                    if !s.trim().is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }

        if let Some(v) = msg.unprotected_header.get(KID_HEADER_LABEL) {
            if let Some(b) = v.as_bytes() {
                if let Ok(s) = std::str::from_utf8(b) {
                    if !s.trim().is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }

        None
    }

    fn looks_like_azure_key_vault_key_id(kid: &str) -> bool {
        if kid.trim().is_empty() {
            return false;
        }

        let Ok(uri) = Url::parse(kid) else {
            return false;
        };

        let host = uri.host_str().unwrap_or("").to_ascii_lowercase();
        (host.ends_with(".vault.azure.net") || host.ends_with(".managedhsm.azure.net"))
            && uri.path().to_ascii_lowercase().contains("/keys/")
    }
}

impl CoseSign1TrustPack for AzureKeyVaultTrustPack {
    fn name(&self) -> &'static str {
        "AzureKeyVaultTrustPack"
    }

    fn fact_producer(&self) -> std::sync::Arc<dyn TrustFactProducer> {
        std::sync::Arc::new(self.clone())
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        use crate::fluent_ext::{AzureKeyVaultKidAllowedWhereExt, AzureKeyVaultKidDetectedWhereExt};

        // Secure-by-default AKV policy:
        // - kid must look like an AKV key id
        // - kid must match allowed patterns (defaults cover Microsoft Key Vault namespaces)
        let bundled = TrustPlanBuilder::new(vec![std::sync::Arc::new(self.clone())])
            .for_message(|m| {
                m.require::<AzureKeyVaultKidDetectedFact>(|f| f.require_azure_key_vault_kid())
                    .and()
                    .require::<AzureKeyVaultKidAllowedFact>(|f| f.require_kid_allowed())
            })
            .compile()
            .expect("default trust plan should be satisfiable by the AKV trust pack");

        Some(bundled.plan().clone())
    }
}

impl TrustFactProducer for AzureKeyVaultTrustPack {
    fn name(&self) -> &'static str {
        "cose_sign1_validation_azure_key_vault::AzureKeyVaultTrustPack"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        if ctx.subject().kind != "Message" {
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidDetectedFact>());
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidAllowedFact>());
            return Ok(());
        }

        if ctx.cose_sign1_message().is_none() {
            ctx.mark_missing::<AzureKeyVaultKidDetectedFact>("MissingMessage");
            ctx.mark_missing::<AzureKeyVaultKidAllowedFact>("MissingMessage");
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidDetectedFact>());
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidAllowedFact>());
            return Ok(());
        }

        let Some(kid) = Self::try_get_kid_utf8(ctx) else {
            ctx.mark_missing::<AzureKeyVaultKidDetectedFact>("MissingKid");
            ctx.mark_missing::<AzureKeyVaultKidAllowedFact>("MissingKid");
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidDetectedFact>());
            ctx.mark_produced(FactKey::of::<AzureKeyVaultKidAllowedFact>());
            return Ok(());
        };

        let is_akv = Self::looks_like_azure_key_vault_key_id(&kid);
        ctx.observe(AzureKeyVaultKidDetectedFact {
            is_azure_key_vault_key: is_akv,
        })?;

        let (is_allowed, details) = if self.options.require_azure_key_vault_kid && !is_akv {
            (false, Some("NoPatternMatch".to_string()))
        } else if self.compiled_patterns.is_none() {
            (false, Some("NoAllowedPatterns".to_string()))
        } else {
            let matched = self
                .compiled_patterns
                .as_ref()
                .unwrap()
                .iter()
                .any(|re| re.is_match(&kid));
            (
                matched,
                Some(if matched {
                    "PatternMatched".to_string()
                } else {
                    "NoPatternMatch".to_string()
                }),
            )
        };

        ctx.observe(AzureKeyVaultKidAllowedFact {
            is_allowed,
            details,
        })?;

        ctx.mark_produced(FactKey::of::<AzureKeyVaultKidDetectedFact>());
        ctx.mark_produced(FactKey::of::<AzureKeyVaultKidAllowedFact>());
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: Lazy<[FactKey; 2]> = Lazy::new(|| {
            [
                FactKey::of::<AzureKeyVaultKidDetectedFact>(),
                FactKey::of::<AzureKeyVaultKidAllowedFact>(),
            ]
        });
        &*PROVIDED
    }
}
