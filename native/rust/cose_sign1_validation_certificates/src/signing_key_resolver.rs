// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::*;
use cose_sign1_validation_trust::facts::TrustFactProducer;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use cose_sign1_validation_trust::CoseHeaderLocation;
use ring::signature;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::facts::{X509ChainTrustedFact, X509SigningCertificateIdentityFact};
use crate::fluent_ext::{X509ChainTrustedWhereExt, X509SigningCertificateIdentityWhereExt};
use crate::pack::X509CertificateTrustPack;

#[cfg(feature = "pqc-mldsa")]
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};

#[cfg(feature = "pqc-mldsa")]
use ml_dsa::signature::Verifier as _;

const X5CHAIN_HEADER_LABEL: i64 = 33;

// COSE algorithm values for ML-DSA (FIPS 204). These match the values used in the repo's
// other Rust implementation branch and draft COSE assignments.
const COSE_ALG_MLDSA_44: i64 = -48;
const COSE_ALG_MLDSA_65: i64 = -49;
const COSE_ALG_MLDSA_87: i64 = -50;

// SubjectPublicKeyInfo.algorithm.algorithm OIDs for ML-DSA (Dilithium) public keys.
const OID_MLDSA_44: &str = "2.16.840.1.101.3.4.3.17";
const OID_MLDSA_65: &str = "2.16.840.1.101.3.4.3.18";
const OID_MLDSA_87: &str = "2.16.840.1.101.3.4.3.19";

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

        let resolved_key = match extract_leaf_public_key_material(leaf.as_slice()) {
            Ok(v) => v,
            Err(e) => {
                return SigningKeyResolutionResult::failure(
                    Some("X509_PARSE_FAILED".to_string()),
                    Some(e),
                )
            }
        };

        let algorithm_oid = resolved_key.algorithm_oid;
        let mut out = SigningKeyResolutionResult::success(Arc::new(X509CertificateSigningKey {
            algorithm_oid: algorithm_oid.clone(),
            subject_public_key_bytes: resolved_key.subject_public_key_bytes,
        }));
        out.diagnostics
            .push(format!("x509_signing_key_alg_oid: {algorithm_oid}"));
        out
    }
}

struct X509CertificateSigningKey {
    /// X.509 SubjectPublicKeyInfo algorithm OID (e.g. id-ecPublicKey).
    ///
    /// We always capture this so resolution works for PQC/unknown algorithms too.
    algorithm_oid: String,

    /// Raw bytes of the X.509 `subjectPublicKey` BIT STRING (not SPKI DER).
    ///
    /// For EC keys this is typically the uncompressed SEC1 point (0x04||X||Y),
    /// but for PQC/other key types it will be algorithm-specific.
    subject_public_key_bytes: Vec<u8>,
}

impl SigningKey for X509CertificateSigningKey {
    fn key_type(&self) -> &'static str {
        "X509CertificateSigningKey"
    }

    fn verify(
        &self,
        alg: i64,
        sig_structure: &[u8],
        signature_bytes: &[u8],
    ) -> Result<bool, String> {
        match alg {
            // ES256 = -7
            -7 => {
                // For ES256 we expect an EC P-256 public key. If the embedded certificate contains a
                // different key type (including PQC), we can still *resolve* it, but we cannot use it
                // for ES256 signature verification.
                //
                // id-ecPublicKey = 1.2.840.10045.2.1
                if self.algorithm_oid != "1.2.840.10045.2.1" {
                    return Err(format!(
                        "certificate_public_key_alg_mismatch_for_es256: {}",
                        self.algorithm_oid
                    ));
                }

                // For P-256 the uncompressed point is 65 bytes: 0x04 || X(32) || Y(32)
                if self.subject_public_key_bytes.len() != 65 {
                    return Err(format!(
                        "unexpected_ec_public_key_len_for_es256: {}",
                        self.subject_public_key_bytes.len()
                    ));
                }
                if self.subject_public_key_bytes.first().copied() != Some(0x04) {
                    return Err("unexpected_ec_public_key_format_for_es256".to_string());
                }

                // COSE ES256 signatures are raw r||s and match ring's FIXED verifier.
                if signature_bytes.len() != 64 {
                    return Err(format!(
                        "unexpected_signature_len: {}",
                        signature_bytes.len()
                    ));
                }

                let pk = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_FIXED,
                    self.subject_public_key_bytes.as_slice(),
                );

                match pk.verify(sig_structure, signature_bytes) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }

            // ML-DSA (FIPS 204)
            COSE_ALG_MLDSA_44 => verify_ml_dsa_dispatch(
                self.algorithm_oid.as_str(),
                self.subject_public_key_bytes.as_slice(),
                sig_structure,
                signature_bytes,
                OID_MLDSA_44,
            ),
            COSE_ALG_MLDSA_65 => verify_ml_dsa_dispatch(
                self.algorithm_oid.as_str(),
                self.subject_public_key_bytes.as_slice(),
                sig_structure,
                signature_bytes,
                OID_MLDSA_65,
            ),
            COSE_ALG_MLDSA_87 => verify_ml_dsa_dispatch(
                self.algorithm_oid.as_str(),
                self.subject_public_key_bytes.as_slice(),
                sig_structure,
                signature_bytes,
                OID_MLDSA_87,
            ),

            _ => Err(format!("unsupported_alg: {alg}")),
        }
    }
}

#[cfg(not(feature = "pqc-mldsa"))]
fn verify_ml_dsa_dispatch(
    algorithm_oid: &str,
    public_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
    expected_spki_oid: &'static str,
) -> Result<bool, String> {
    let _ = (algorithm_oid, public_key_bytes, msg, sig, expected_spki_oid);
    Err("ml-dsa support is disabled (enable feature 'pqc-mldsa')".to_string())
}

#[cfg(feature = "pqc-mldsa")]
fn verify_ml_dsa_dispatch(
    algorithm_oid: &str,
    public_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
    expected_spki_oid: &'static str,
) -> Result<bool, String> {
    if algorithm_oid != expected_spki_oid {
        return Err(format!(
            "unexpected public key algorithm OID: expected {expected_spki_oid}, got {algorithm_oid}"
        ));
    }

    // Map COSE signature verification to the ml-dsa crate's key/signature decoders.
    let ok = match expected_spki_oid {
        OID_MLDSA_44 => verify_ml_dsa::<MlDsa44>(public_key_bytes, msg, sig)?,
        OID_MLDSA_65 => verify_ml_dsa::<MlDsa65>(public_key_bytes, msg, sig)?,
        OID_MLDSA_87 => verify_ml_dsa::<MlDsa87>(public_key_bytes, msg, sig)?,
        _ => return Err(format!("unsupported_mldsa_oid: {expected_spki_oid}")),
    };

    Ok(ok)
}

#[cfg(feature = "pqc-mldsa")]
fn verify_ml_dsa<P: ml_dsa::MlDsaParams>(
    public_key_bytes: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, String> {
    let enc_vk = ml_dsa::EncodedVerifyingKey::<P>::try_from(public_key_bytes)
        .map_err(|_| "bad ML-DSA public key bytes".to_string())?;
    let vk = ml_dsa::VerifyingKey::<P>::decode(&enc_vk);

    let signature = ml_dsa::Signature::<P>::try_from(sig)
        .map_err(|_| "bad ML-DSA signature bytes".to_string())?;

    match vk.verify(msg, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

struct LeafPublicKeyMaterial {
    algorithm_oid: String,
    subject_public_key_bytes: Vec<u8>,
}

fn extract_leaf_public_key_material(cert_der: &[u8]) -> Result<LeafPublicKeyMaterial, String> {
    let (_rem, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| format!("x509_parse_failed: {e}"))?;

    let algorithm_oid = cert
        .tbs_certificate
        .subject_pki
        .algorithm
        .algorithm
        .to_id_string();

    let subject_public_key_bytes = cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec();

    Ok(LeafPublicKeyMaterial {
        algorithm_oid,
        subject_public_key_bytes,
    })
}

#[cfg(all(test, feature = "pqc-mldsa"))]
mod tests {
    use super::*;
    use ml_dsa::signature::Signer as _;
    use ml_dsa::{KeyGen as _, MlDsa44};

    #[test]
    fn mldsa_44_verify_roundtrip_succeeds() {
        let seed: ml_dsa::B32 = [42u8; 32].into();
        let kp = MlDsa44::key_gen_internal(&seed);

        let msg = b"sig_structure";
        let sig = kp.signing_key().sign(msg);
        let pk = kp.verifying_key().encode();

        let ok = verify_ml_dsa_dispatch(
            OID_MLDSA_44,
            pk.as_ref(),
            msg,
            sig.encode().as_ref(),
            OID_MLDSA_44,
        )
        .expect("verify");
        assert!(ok);
    }

    #[test]
    fn mldsa_44_oid_mismatch_is_reported() {
        let seed: ml_dsa::B32 = [42u8; 32].into();
        let kp = MlDsa44::key_gen_internal(&seed);

        let msg = b"sig_structure";
        let sig = kp.signing_key().sign(msg);
        let pk = kp.verifying_key().encode();

        let err = verify_ml_dsa_dispatch(
            "1.2.3.4",
            pk.as_ref(),
            msg,
            sig.encode().as_ref(),
            OID_MLDSA_44,
        )
        .unwrap_err();
        assert!(err.contains("unexpected public key algorithm OID"));
    }
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
        CoseHeaderLocation::Protected => try_read_x5chain(protected_map_bytes)?
            .ok_or_else(|| "x5chain not found in protected header".to_string()),
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
