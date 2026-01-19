// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, Context as _};
use cose_sign1_validation::{
    CoseSign1TrustPack, CoseSign1ValidationOptions, CoseSign1Validator, DetachedPayload,
    DetachedPayloadProvider, SigningKey, SigningKeyResolutionResult, SigningKeyResolver,
    SimpleTrustPack, TrustPlanBuilder,
};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn usage() -> &'static str {
    "cose_sign1_validation_demo\n\nUSAGE:\n  cose_sign1_validation_demo validate --cose <path> [--detached <path>] --insecure-accept-any-signature\n\nNOTES:\n  --insecure-accept-any-signature is required because this demo does not ship\n  a real crypto SigningKey implementation.\n"
}

struct AcceptAllSigningKey;

impl SigningKey for AcceptAllSigningKey {
    fn key_type(&self) -> &'static str {
        "AcceptAllSigningKey"
    }

    fn verify(&self, _alg: i64, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, String> {
        Ok(true)
    }
}

struct DemoSigningKeyResolver {
    allow_insecure: bool,
}

impl SigningKeyResolver for DemoSigningKeyResolver {
    fn resolve(
        &self,
        _message: &cose_sign1_validation::CoseSign1<'_>,
        _options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        if !self.allow_insecure {
            return SigningKeyResolutionResult::failure(
                Some("DEMO_INSECURE_MODE_REQUIRED".to_string()),
                Some(
                    "Pass --insecure-accept-any-signature to run the demo (NOT for production)"
                        .to_string(),
                ),
            );
        }
        SigningKeyResolutionResult::success(Arc::new(AcceptAllSigningKey))
    }
}

struct FileDetachedPayloadProvider {
    path: PathBuf,
    len: u64,
}

impl FileDetachedPayloadProvider {
    fn new(path: PathBuf) -> anyhow::Result<Self> {
        let meta = std::fs::metadata(&path)
            .with_context(|| format!("failed to stat detached payload: {}", path.display()))?;
        Ok(Self {
            path,
            len: meta.len(),
        })
    }
}

impl DetachedPayloadProvider for FileDetachedPayloadProvider {
    fn open(&self) -> Result<Box<dyn Read + Send>, String> {
        File::open(&self.path)
            .map(|f| Box::new(f) as Box<dyn Read + Send>)
            .map_err(|e| format!("failed_to_open_detached_payload: {e}"))
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.len)
    }
}

fn read_all(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("failed to open: {}", path.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("failed to read: {}", path.display()))?;
    Ok(buf)
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);

    let Some(cmd) = args.next() else {
        return Err(anyhow!(usage()));
    };

    if cmd != "validate" {
        return Err(anyhow!(usage()));
    }

    let mut cose_path: Option<PathBuf> = None;
    let mut detached_path: Option<PathBuf> = None;
    let mut allow_insecure = false;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--cose" => {
                let p = args
                    .next()
                    .ok_or_else(|| anyhow!("--cose requires a path"))?;
                cose_path = Some(PathBuf::from(p));
            }
            "--detached" => {
                let p = args
                    .next()
                    .ok_or_else(|| anyhow!("--detached requires a path"))?;
                detached_path = Some(PathBuf::from(p));
            }
            "--insecure-accept-any-signature" => {
                allow_insecure = true;
            }
            "--help" | "-h" => {
                return Err(anyhow!(usage()));
            }
            other => {
                return Err(anyhow!(format!("Unknown arg: {other}\n\n{}", usage())));
            }
        }
    }

    let cose_path = cose_path.ok_or_else(|| anyhow!("--cose is required\n\n{}", usage()))?;
    let cose_bytes = read_all(&cose_path)?;

    let detached_payload = if let Some(detached_path) = detached_path {
        let provider = FileDetachedPayloadProvider::new(detached_path)?;
        Some(DetachedPayload::Provider(Arc::new(provider)))
    } else {
        None
    };

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("demo_signing_key")
            .with_signing_key_resolver(Arc::new(DemoSigningKeyResolver { allow_insecure })),
    )];

    // For the demo we bypass real trust establishment.
    let bundled = TrustPlanBuilder::new(trust_packs)
        .for_message(|m| m.allow_all())
        .compile()
        .unwrap();

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = detached_payload;
    });

    let result = validator
        .validate_bytes(Arc::from(cose_bytes.into_boxed_slice()))
        .context("validation failed")?;

    println!("resolution: {:?}", result.resolution.kind);
    println!("trust: {:?}", result.trust.kind);
    println!("signature: {:?}", result.signature.kind);
    println!("post: {:?}", result.post_signature_policy.kind);
    println!("overall: {:?}", result.overall.kind);

    if result.overall.is_valid() {
        Ok(())
    } else {
        Err(anyhow!("overall validation failed"))
    }
}
