// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::{anyhow, bail, Context as _};
use base64::Engine as _;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_certificates::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use cose_sign1_validation_certificates::fluent_ext::{X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt};
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use ring::rand;
use ring::signature;
use sha1::Digest as _;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tinycbor::{Encode, Encoder};
use x509_parser::parse_x509_certificate;

fn usage() -> &'static str {
    "cose_sign1_validation_demo\n\nUSAGE:\n  cose_sign1_validation_demo selftest\n  cose_sign1_validation_demo validate --cose <path> [--detached <path>] [--allow-thumbprint <sha1-hex>]\n\nCOMMANDS:\n  selftest\n    Generates an ephemeral ES256 key + self-signed cert, signs a COSE_Sign1 with\n    protected x5chain, and validates it using the real certificates trust pack\n    + a trust policy override that pins by signing cert thumbprint.\n\n  validate\n    Validates an existing COSE_Sign1 file. If --allow-thumbprint is provided,\n    trust is pinned to that signing certificate thumbprint.\n\nNOTES:\n  This demo currently treats embedded x5chain as trusted (deterministic, OS-agnostic).\n"
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

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

fn sha1_hex_upper(bytes: &[u8]) -> String {
    let mut sha1 = sha1::Sha1::new();
    sha1.update(bytes);
    hex::encode_upper(sha1.finalize())
}

fn pkcs8_private_key_der_to_pem(pkcs8_der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 is utf8"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

fn encode_protected_header_with_alg_and_x5chain(alg: i64, leaf_der: &[u8]) -> Vec<u8> {
    let mut hdr_buf = vec![0u8; 4096];
    let hdr_len = hdr_buf.len();
    let mut hdr_enc = Encoder(hdr_buf.as_mut_slice());

    // { 1: alg, 33: bstr(cert_der) }
    hdr_enc.map(2).unwrap();
    (1i64).encode(&mut hdr_enc).unwrap();
    alg.encode(&mut hdr_enc).unwrap();
    (33i64).encode(&mut hdr_enc).unwrap();
    leaf_der.encode(&mut hdr_enc).unwrap();

    let used = hdr_len - hdr_enc.0.len();
    hdr_buf.truncate(used);
    hdr_buf
}

fn encode_sig_structure(protected_header_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    // Match the validator's exact Sig_structure encoding:
    // - encode first 3 items with tinycbor
    // - append the CBOR bstr header for payload length
    // - append raw payload bytes
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

    let mut buf = vec![0u8; protected_header_bytes.len() + external_aad.len() + payload.len() + 256];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4).unwrap();
    "Signature1".encode(&mut enc).unwrap();
    protected_header_bytes.encode(&mut enc).unwrap();
    external_aad.encode(&mut enc).unwrap();

    let used = buf_len - enc.0.len();
    buf.truncate(used);
    buf.extend_from_slice(&encode_cbor_bstr_len(payload.len() as u64));
    buf.extend_from_slice(payload);
    buf
}

fn extract_uncompressed_public_key_bytes(cert_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    let (_rem, cert) = parse_x509_certificate(cert_der)
        .map_err(|e| anyhow!(format!("x509_parse_failed: {e}")))?;

    let bytes = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();

    if bytes.len() != 65 {
        bail!("unexpected_public_key_len: {}", bytes.len());
    }
    if bytes.first().copied() != Some(0x04) {
        bail!("unexpected_public_key_format: expected uncompressed SEC1 (0x04)");
    }

    Ok(bytes)
}

fn build_thumbprint_pinned_trust_plan(
    pack: Arc<X509CertificateTrustPack>,
    allowed_thumbprint_sha1_hex: &str,
) -> CoseSign1CompiledTrustPlan {
    let now = now_unix_seconds();
    TrustPlanBuilder::new(vec![pack])
        .for_primary_signing_key(|key| {
            key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                .and()
                .require::<X509SigningCertificateIdentityFact>(|f| {
                    f.cert_valid_at(now)
                        .thumbprint_eq(allowed_thumbprint_sha1_hex.to_string())
                })
        })
        .compile()
        .expect("trust plan should compile")
}

fn run_selftest() -> anyhow::Result<()> {
    // Generate an ephemeral ES256 keypair using ring, then build a self-signed cert from it.
    // This keeps the cert public key guaranteed to match the signing key.
    let rng = rand::SystemRandom::new();
    let key_pair_pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .map_err(|_| anyhow!("ring key generation failed"))?;

    let signing_key = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        key_pair_pkcs8.as_ref(),
        &rng,
    )
    .map_err(|e| anyhow!(format!("ring key rejected: {e:?}")))?;

    let rcgen_pem = pkcs8_private_key_der_to_pem(key_pair_pkcs8.as_ref());
    let rcgen_key_pair = rcgen::KeyPair::from_pem(rcgen_pem.as_str())
        .context("rcgen KeyPair::from_pem")?;

    let params = rcgen::CertificateParams::new(vec!["demo-ephemeral".to_string()])
        .context("rcgen params")?;
    let cert = params
        .self_signed(&rcgen_key_pair)
        .context("rcgen self-signed")?;
    let leaf_der = cert.der().to_vec();

    let payload = b"hello from cose_sign1_validation_demo".as_slice();
    let protected_map_bytes = encode_protected_header_with_alg_and_x5chain(-7, leaf_der.as_slice());
    let sig_structure = encode_sig_structure(protected_map_bytes.as_slice(), payload);
    let signature = signing_key
        .sign(&rng, sig_structure.as_slice())
        .expect("ecdsa sign")
        .as_ref()
        .to_vec();

    let cose_bytes = {
        // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr, signature: bstr]
        let mut buf = vec![0u8; 4096 + payload.len() + signature.len() + leaf_der.len()];
        let buf_len = buf.len();
        let mut enc = Encoder(buf.as_mut_slice());

        enc.array(4).unwrap();
        protected_map_bytes.as_slice().encode(&mut enc).unwrap();
        enc.map(0).unwrap();
        payload.encode(&mut enc).unwrap();
        signature.as_slice().encode(&mut enc).unwrap();

        let used = buf_len - enc.0.len();
        buf.truncate(used);
        buf
    };

    let thumbprint = sha1_hex_upper(&leaf_der);
    println!("ephemeral signing cert thumbprint (SHA1/HEX): {thumbprint}");

    // Sanity-check: verify the signature with ring directly.
    {
        let pk_bytes = extract_uncompressed_public_key_bytes(leaf_der.as_slice())?;
        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_FIXED,
            pk_bytes.as_slice(),
        );
        pk.verify(sig_structure.as_slice(), signature.as_slice())
            .map_err(|_| anyhow!("local ring verify failed"))?;
        println!("local ring verify: ok");
    }

    // Use the real certificates trust pack.
    // For this demo we treat embedded x5chain as trusted (OS-agnostic), then pin trust by thumbprint.
    let pack = Arc::new(X509CertificateTrustPack::new(CertificateTrustOptions {
        trust_embedded_chain_as_trusted: true,
        ..CertificateTrustOptions::default()
    }));

    let bundled = build_thumbprint_pinned_trust_plan(pack, thumbprint.as_str());

    let validator = CoseSign1Validator::new(bundled);
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
        let provider = FileDetachedPayloadProvider::new(detached_path)?;
        Some(DetachedPayload::Provider(Arc::new(provider)))
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
