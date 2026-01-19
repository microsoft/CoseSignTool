// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::{
    CoseSign1, CoseSign1TrustPack, CoseSign1ValidationOptions, SigningKey,
    SigningKeyResolutionResult, SigningKeyResolver, TrustPlanBuilder,
};
use cose_sign1_validation_trust::facts::TrustFactProducer;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use cose_sign1_validation_trust::CoseHeaderLocation;
use ring::signature;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use crate::fluent_ext::{X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt};
use crate::pack::X509CertificateTrustPack;

const X5CHAIN_HEADER_LABEL: i64 = 33;

pub struct X509CertificateSigningKeyResolver;

impl SigningKeyResolver for X509CertificateSigningKeyResolver {
    fn resolve(
        &self,
        message: &CoseSign1<'_>,
        options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult {
        let chain = match parse_x5chain_from_message(message, options.certificate_header_location) {
            Ok(v) => v,
            Err(e) => {
                return SigningKeyResolutionResult::failure(
                    Some("X5CHAIN_NOT_FOUND".to_string()),
                    Some(e),
                )
            }
        };

        let Some(leaf) = chain.first() else {
            return SigningKeyResolutionResult::failure(
                Some("X5CHAIN_EMPTY".to_string()),
                Some("x5chain was present but empty".to_string()),
            );
        };

        let spki_der = match extract_spki_der(leaf.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return SigningKeyResolutionResult::failure(
                    Some("X509_PARSE_FAILED".to_string()),
                    Some(e),
                )
            }
        };

        SigningKeyResolutionResult::success(Arc::new(X509CertificateSigningKey { spki_der }))
    }
}

struct X509CertificateSigningKey {
    spki_der: Vec<u8>,
}

impl SigningKey for X509CertificateSigningKey {
    fn key_type(&self) -> &'static str {
        "X509CertificateSigningKey"
    }

    fn verify(&self, alg: i64, sig_structure: &[u8], signature_bytes: &[u8]) -> Result<bool, String> {
        // COSE alg values: ES256 = -7.
        // Keep this conservative: unsupported algorithms are rejected.
        if alg != -7 {
            return Err(format!("unsupported_alg: {alg}"));
        }

        let der_sig = cose_ecdsa_signature_to_asn1_der(signature_bytes)?;

        let pk = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            self.spki_der.as_slice(),
        );

        match pk.verify(sig_structure, der_sig.as_slice()) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_rem, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("x509_parse_failed: {e}"))?;

    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

fn parse_x5chain_from_message(
    message: &CoseSign1<'_>,
    loc: CoseHeaderLocation,
) -> Result<Vec<Vec<u8>>, String> {
    fn try_read_x5chain(map_bytes: &[u8]) -> Result<Option<Vec<Vec<u8>>>, String> {
        let mut d = tinycbor::Decoder(map_bytes);
        let mut map = d
            .map_visitor()
            .map_err(|e| format!("header_map_decode_failed: {e}"))?;

        while let Some(entry) = map.visit::<i64, tinycbor::Any>() {
            let (key, value_any) = entry.map_err(|e| format!("map_entry_decode_failed: {e}"))?;
            if key != X5CHAIN_HEADER_LABEL {
                continue;
            }

            // x5chain can be a single bstr or an array of bstr.
            let mut vd = tinycbor::Decoder(value_any.as_ref());

            // Single cert as bstr.
            if let Ok(it) = vd.bytes_iter() {
                let mut one = Vec::new();
                for part in it {
                    let part = part.map_err(|e| format!("x5chain_bytes_iter_failed: {e}"))?;
                    one.extend_from_slice(part);
                }
                return Ok(Some(vec![one]));
            }

            // Array of bstr.
            let mut arr = vd
                .array_visitor()
                .map_err(|e| format!("x5chain_array_decode_failed: {e}"))?;

            let mut certs = Vec::new();
            while let Some(item) = arr.visit::<&[u8]>() {
                let b = item.map_err(|e| format!("x5chain_item_decode_failed: {e}"))?;
                certs.push(b.to_vec());
            }

            return Ok(Some(certs));
        }

        Ok(None)
    }

    let protected_map_bytes = message.protected_header;
    let unprotected_map_bytes = message.unprotected_header.as_ref();

    match loc {
        CoseHeaderLocation::Protected => try_read_x5chain(protected_map_bytes)?.ok_or_else(|| {
            "x5chain not found in protected header".to_string()
        }),
        CoseHeaderLocation::Any => {
            if let Some(v) = try_read_x5chain(protected_map_bytes)? {
                return Ok(v);
            }
            if let Some(v) = try_read_x5chain(unprotected_map_bytes)? {
                return Ok(v);
            }
            Err("x5chain not found in protected or unprotected header".to_string())
        }
    }
}

fn cose_ecdsa_signature_to_asn1_der(sig: &[u8]) -> Result<Vec<u8>, String> {
    // For ES256, COSE uses raw r||s (32 bytes each).
    if sig.len() != 64 {
        return Err(format!("unexpected_signature_len: {}", sig.len()));
    }

    let (r, s) = sig.split_at(32);

    fn der_int(bytes: &[u8]) -> Vec<u8> {
        // Strip leading zeros.
        let mut v = bytes;
        while v.len() > 1 && v[0] == 0 {
            v = &v[1..];
        }

        // If highest bit is set, prefix 0x00 to make it positive.
        let mut out = Vec::new();
        if (v[0] & 0x80) != 0 {
            out.push(0);
        }
        out.extend_from_slice(v);
        out
    }

    let r_i = der_int(r);
    let s_i = der_int(s);

    let mut seq = Vec::new();
    seq.push(0x02);
    seq.push(r_i.len() as u8);
    seq.extend_from_slice(&r_i);
    seq.push(0x02);
    seq.push(s_i.len() as u8);
    seq.extend_from_slice(&s_i);

    let mut out = Vec::new();
    out.push(0x30);
    out.push(seq.len() as u8);
    out.extend_from_slice(&seq);
    Ok(out)
}

fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

impl CoseSign1TrustPack for X509CertificateTrustPack {
    fn name(&self) -> &'static str {
        "X509CertificateTrustPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(self.clone())
    }

    fn signing_key_resolvers(&self) -> Vec<Arc<dyn SigningKeyResolver>> {
        vec![Arc::new(X509CertificateSigningKeyResolver)]
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        let now = now_unix_seconds();

        // Secure-by-default certificate policy:
        // - chain must be trusted (until OS trust is implemented, this defaults to false unless
        //   configured to trust embedded chains)
        // - signing certificate must be currently time-valid
        let bundled = TrustPlanBuilder::new(vec![Arc::new(self.clone())])
            .for_primary_signing_key(|key| {
                key.require::<X509ChainTrustedFact>(|f| f.require_trusted())
                    .and()
                    .require::<X509SigningCertificateIdentityFact>(|f| f.cert_valid_at(now))
            })
            .compile()
            .expect("default trust plan should be satisfiable by the certificates trust pack");

        Some(bundled.plan().clone())
    }
}

