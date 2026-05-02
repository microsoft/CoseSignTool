// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, Context as _};
use cose_sign1_validation::fluent::*;
use cose_sign1_certificates::validation::facts::{
    X509ChainTrustedFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_certificates::validation::fluent_ext::{
    X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt,
};
use cose_sign1_certificates::validation::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_certificates_local::{
    CertificateFactory, CertificateOptions, EphemeralCertificateFactory, SoftwareKeyProvider,
};
// CBOR implementation – EverParse (formally verified by MSR)
use cbor_primitives_everparse::EverParseCborProvider;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use sha2::Digest as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use cbor_primitives::{CborEncoder, CborProvider};

/// Returns a static usage/help string for the CLI.
fn usage() -> &'static str {
    "cose_sign1_validation_demo\n\nUSAGE:\n  cose_sign1_validation_demo selftest\n  cose_sign1_validation_demo validate --cose <path> [--detached <path>] [--allow-thumbprint <sha256-hex>]\n\nCOMMANDS:\n  selftest\n    Generates an ephemeral ES256 key + self-signed cert, signs a COSE_Sign1 with\n    protected x5chain, and validates it using the real certificates trust pack\n    + a trust policy override that pins by signing cert thumbprint.\n\n  validate\n    Validates an existing COSE_Sign1 file. If --allow-thumbprint is provided,\n    trust is pinned to that signing certificate thumbprint.\n\nNOTES:\n  This demo currently treats embedded x5chain as trusted (deterministic, OS-agnostic).\n"
}



/// Read the entire file at `path` into memory.
fn read_all(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut f = File::open(path).with_context(|| format!("failed to open: {}", path.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .with_context(|| format!("failed to read: {}", path.display()))?;
    Ok(buf)
}

/// Current Unix timestamp in seconds.
fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

/// Compute uppercase SHA-1 hex for a byte slice.
fn sha256_hex_upper(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode_upper(hasher.finalize())
}

/// Encode a minimal protected header map containing `alg` and an `x5chain` leaf cert.
fn encode_protected_header_with_alg_and_x5chain(alg: i64, leaf_der: &[u8]) -> Vec<u8> {
    let mut enc = EverParseCborProvider.encoder();

    // { 1: alg, 33: bstr(cert_der) }
    enc.encode_map(2).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();
    enc.encode_i64(33).unwrap();
    enc.encode_bstr(leaf_der).unwrap();

    enc.into_bytes()
}

/// Encode the COSE `Sig_structure` used by the validator.
///
/// This mirrors the validator's streaming/buffered encoding by writing the prefix, then a CBOR
/// `bstr` length header, then the raw payload bytes.
fn encode_sig_structure(protected_header_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    // Match the validator's exact Sig_structure encoding:
    // - encode first 3 items with the CBOR provider
    // - append the CBOR bstr header for payload length
    // - append raw payload bytes
    /// Encode a CBOR major type 2 (byte string) length header.
    fn encode_cbor_bstr_len(len: u64) -> Vec<u8> {
        // Major type 2 (byte string).
        if len < 24 {
            return vec![(0b010_00000u8 | (len as u8))];
        }

        if len <= u8::MAX as u64 {
            return vec![0x58, len as u8];
        }

        if len <= u16::MAX as u64 {
            let v = len as u16;
            return vec![0x59, (v >> 8) as u8, (v & 0xff) as u8];
        }

        if len <= u32::MAX as u64 {
            let v = len as u32;
            return vec![
                0x5a,
                (v >> 24) as u8,
                (v >> 16) as u8,
                (v >> 8) as u8,
                (v & 0xff) as u8,
            ];
        }

        let v = len;
        vec![
            0x5b,
            (v >> 56) as u8,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            (v & 0xff) as u8,
        ]
    }

    let external_aad: &[u8] = &[];

    let mut enc = EverParseCborProvider.encoder();

    enc.encode_array(4).unwrap();
    enc.encode_tstr("Signature1").unwrap();
    enc.encode_bstr(protected_header_bytes).unwrap();
    enc.encode_bstr(external_aad).unwrap();

    let mut buf = enc.into_bytes();
    buf.extend_from_slice(&encode_cbor_bstr_len(payload.len() as u64));
    buf.extend_from_slice(payload);
    buf
}

/// Build a trust plan that requires a trusted chain and pins trust to a signing cert thumbprint.
fn build_thumbprint_pinned_trust_plan(
    pack: Arc<X509CertificateTrustPack>,
    allowed_thumbprint_sha256_hex: &str,
) -> CoseSign1CompiledTrustPlan {
    let now = now_unix_seconds();
    TrustPlanBuilder::new(vec![pack])
        .for_primary_signing_key(|key| {
            key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                .and()
                .require::<X509SigningCertificateIdentityFact>(|f| {
                    f.cert_valid_at(now)
                        .thumbprint_eq(allowed_thumbprint_sha256_hex.to_string())
                })
        })
        .compile()
        .expect("trust plan should compile")
}

/// Self-test command: generate an ephemeral key+cert, sign a COSE_Sign1, then validate it.
fn run_selftest() -> anyhow::Result<()> {
    // Generate an ephemeral ES256 key + self-signed cert using certificates_local (OpenSSL).
    let factory = EphemeralCertificateFactory::new(Box::new(SoftwareKeyProvider::new()));
    let cert = factory
        .create_certificate(
            CertificateOptions::new()
                .with_subject_name("CN=demo-ephemeral")
                .add_subject_alternative_name("demo-ephemeral"),
        )
        .map_err(|e| anyhow!("certificate creation failed: {}", e))?;
    let leaf_der = cert.cert_der.clone();
    let private_key_der = cert
        .private_key_der
        .clone()
        .ok_or_else(|| anyhow!("no private key in generated certificate"))?;

    let payload = b"hello from cose_sign1_validation_demo".as_slice();
    let protected_map_bytes = encode_protected_header_with_alg_and_x5chain(-7, leaf_der.as_slice());
    let sig_structure = encode_sig_structure(protected_map_bytes.as_slice(), payload);

    // Sign the Sig_structure using OpenSSL ECDSA P-256/SHA-256.
    let pkey =
        PKey::private_key_from_der(&private_key_der).context("failed to load private key")?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).context("failed to create signer")?;
    signer
        .update(sig_structure.as_slice())
        .context("signer update failed")?;
    let der_sig = signer.sign_to_vec().context("signing failed")?;

    // Convert DER-encoded ECDSA signature to fixed-length raw (r||s) format for COSE ES256.
    let ecdsa_sig = EcdsaSig::from_der(&der_sig).context("failed to parse ECDSA signature")?;
    let r_bytes = ecdsa_sig.r().to_vec();
    let s_bytes = ecdsa_sig.s().to_vec();
    let mut signature = vec![0u8; 64];
    signature[32 - r_bytes.len()..32].copy_from_slice(&r_bytes);
    signature[64 - s_bytes.len()..64].copy_from_slice(&s_bytes);

    let cose_bytes = {
        // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
        let mut enc = EverParseCborProvider.encoder();

        enc.encode_array(4).unwrap();
        enc.encode_bstr(protected_map_bytes.as_slice()).unwrap();
        enc.encode_map(0).unwrap();
        enc.encode_bstr(payload).unwrap();
        enc.encode_bstr(signature.as_slice()).unwrap();

        enc.into_bytes()
    };

    let thumbprint = sha256_hex_upper(&leaf_der);
    println!("ephemeral signing cert thumbprint (SHA256/HEX): {thumbprint}");

    // Use the real certificates trust pack.
    // For this demo we treat embedded x5chain as trusted (deterministic, OS-agnostic).
    let pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    let bundled = build_thumbprint_pinned_trust_plan(pack, thumbprint.as_str());

    let validator = CoseSign1Validator::new(bundled);
    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose_bytes.into_boxed_slice()))
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

/// CLI entrypoint.
fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);

    let Some(cmd) = args.next() else {
        return Err(anyhow!(usage()));
    };

    if cmd == "selftest" {
        return run_selftest();
    }

    if cmd != "validate" {
        return Err(anyhow!(usage()));
    }

    let mut cose_path: Option<PathBuf> = None;
    let mut detached_path: Option<PathBuf> = None;
    let mut allow_thumbprint: Option<String> = None;

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
            "--allow-thumbprint" => {
                let v = args
                    .next()
                    .ok_or_else(|| anyhow!("--allow-thumbprint requires a value"))?;
                allow_thumbprint = Some(v);
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
        let file_payload = FilePayload::new(detached_path)
            .with_context(|| "failed to create file payload")?;
        Some(Payload::Streaming(Box::new(file_payload)))
    } else {
        None
    };

    // Use the real certificates trust pack.
    // For this demo we treat embedded x5chain as trusted (OS-agnostic).
    let pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    let bundled = if let Some(tp) = allow_thumbprint {
        build_thumbprint_pinned_trust_plan(pack, tp.as_str())
    } else {
        let now = now_unix_seconds();
        TrustPlanBuilder::new(vec![pack])
            .for_primary_signing_key(|key| {
                key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now))
            })
            .compile()
            .expect("trust plan should compile")
    };

    let validator = CoseSign1Validator::new(bundled).with_options(|o| {
        o.detached_payload = detached_payload;
    });

    let result = validator
        .validate_bytes(EverParseCborProvider, Arc::from(cose_bytes.into_boxed_slice()))
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
