// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::*;
use cose_sign1_validation::CoseSign1;
use cose_sign1_validation::UnknownCounterSignatureBytesFact;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::TrustFactSet;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::CoseHeaderLocation;
use sha1::{Digest as _, Sha1};
use std::sync::Arc;
use x509_parser::prelude::*;

pub mod fluent_ext {
    pub use crate::fluent_ext::*;
}

#[derive(Debug, Clone, Default)]
pub struct CertificateTrustOptions {
    /// If set, only these thumbprints are allowed (case/whitespace insensitive).
    pub allowed_thumbprints: Vec<String>,

    /// If true, emit identity-allowed facts based on allow list.
    pub identity_pinning_enabled: bool,

    /// Optional OIDs that should be considered PQC algorithms.
    pub pqc_algorithm_oids: Vec<String>,

    /// If true, treat a well-formed embedded `x5chain` as trusted.
    ///
    /// This is deterministic across OSes and intended for scenarios where the `x5chain`
    /// is expected to include its own trust anchor (e.g., testing, pinned-root deployments).
    ///
    /// When false (default), the pack reports `is_trusted=false` because OS-native trust
    /// evaluation is not yet implemented.
    pub trust_embedded_chain_as_trusted: bool,
}

#[derive(Default, Clone)]
pub struct X509CertificateTrustPack {
    options: CertificateTrustOptions,
}

impl X509CertificateTrustPack {
    pub fn new(options: CertificateTrustOptions) -> Self {
        Self { options }
    }

    pub fn trust_embedded_chain_as_trusted() -> Self {
        Self::new(CertificateTrustOptions {
            trust_embedded_chain_as_trusted: true,
            ..CertificateTrustOptions::default()
        })
    }

    fn normalize_thumbprint(s: &str) -> String {
        s.chars()
            .filter(|c| !c.is_whitespace())
            .flat_map(|c| c.to_uppercase())
            .collect()
    }

    fn parse_message_chain(ctx: &TrustFactContext<'_>) -> Result<Vec<Arc<Vec<u8>>>, TrustError> {
        // COSE header label 33 = x5chain
        fn try_read_x5chain(map_bytes: &[u8]) -> Result<Vec<Arc<Vec<u8>>>, TrustError> {
            let mut d = tinycbor::Decoder(map_bytes);
            let mut map = d
                .map_visitor()
                .map_err(|e| TrustError::FactProduction(e.to_string()))?;

            while let Some(entry) = map.visit::<i64, tinycbor::Any>() {
                let (key, value_any) =
                    entry.map_err(|e| TrustError::FactProduction(e.to_string()))?;

                if key == 33 {
                    let mut vd = tinycbor::Decoder(value_any.as_ref());
                    // x5chain can be a single bstr or an array of bstr.
                    if let Ok(it) = vd.bytes_iter() {
                        let mut one = Vec::new();
                        for part in it {
                            let part =
                                part.map_err(|e| TrustError::FactProduction(e.to_string()))?;
                            one.extend_from_slice(part);
                        }
                        return Ok(vec![Arc::new(one)]);
                    }

                    let mut arr = vd
                        .array_visitor()
                        .map_err(|e| TrustError::FactProduction(e.to_string()))?;
                    let mut out = Vec::new();
                    while let Some(item) = arr.visit::<&[u8]>() {
                        let b = item.map_err(|e| TrustError::FactProduction(e.to_string()))?;
                        out.push(Arc::new(b.to_vec()));
                    }
                    return Ok(out);
                }
            }

            Ok(Vec::new())
        }

        fn try_parse_cose_signature_headers(
            bytes: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), TrustError> {
            // COSE_Signature = [protected: bstr, unprotected: map, signature: bstr]
            fn parse_array(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TrustError> {
                let mut d = tinycbor::Decoder(input);
                let mut arr = d
                    .array_visitor()
                    .map_err(|e| TrustError::FactProduction(e.to_string()))?;

                let protected = arr
                    .visit::<&[u8]>()
                    .ok_or_else(|| {
                        TrustError::FactProduction(
                            "countersignature missing protected header".to_string(),
                        )
                    })?
                    .map_err(|e| TrustError::FactProduction(e.to_string()))?;

                let unprotected = arr
                    .visit::<tinycbor::Any>()
                    .ok_or_else(|| {
                        TrustError::FactProduction(
                            "countersignature missing unprotected header".to_string(),
                        )
                    })?
                    .map_err(|e| TrustError::FactProduction(e.to_string()))?;

                // signature (ignored)
                let _ = arr
                    .visit::<&[u8]>()
                    .ok_or_else(|| {
                        TrustError::FactProduction(
                            "countersignature missing signature bytes".to_string(),
                        )
                    })?
                    .map_err(|e| TrustError::FactProduction(e.to_string()))?;

                Ok((protected.to_vec(), unprotected.as_ref().to_vec()))
            }

            // Some tooling wraps structures in a bstr.
            if let Ok((p, u)) = parse_array(bytes) {
                return Ok((p, u));
            }

            let mut d = tinycbor::Decoder(bytes);
            let wrapped = <&[u8] as tinycbor::Decode>::decode(&mut d)
                .map_err(|e| TrustError::FactProduction(e.to_string()))?;
            parse_array(wrapped)
        }

        // If evaluating a counter-signature signing key subject, parse x5chain from the
        // counter-signature bytes rather than from the outer message.
        if ctx.subject().kind == "CounterSignatureSigningKey" {
            let Some(bytes) = ctx.cose_sign1_bytes() else {
                return Ok(Vec::new());
            };

            let message_subject = TrustSubject::message(bytes);
            let unknowns =
                ctx.get_fact_set::<UnknownCounterSignatureBytesFact>(&message_subject)?;
            let TrustFactSet::Available(items) = unknowns else {
                return Ok(Vec::new());
            };

            for item in items {
                let raw = item.raw_counter_signature_bytes.as_ref();
                let counter_signature_subject =
                    TrustSubject::counter_signature(&message_subject, raw);
                let derived =
                    TrustSubject::counter_signature_signing_key(&counter_signature_subject);
                if derived.id == ctx.subject().id {
                    let (protected_map_bytes, unprotected_map_bytes) =
                        try_parse_cose_signature_headers(raw)?;

                    let mut all = Vec::new();
                    all.extend(try_read_x5chain(&protected_map_bytes)?);
                    if ctx.cose_header_location() == CoseHeaderLocation::Any {
                        all.extend(try_read_x5chain(&unprotected_map_bytes)?);
                    }
                    return Ok(all);
                }
            }

            return Ok(Vec::new());
        }

        if let Some(msg) = ctx.cose_sign1_message() {
            let mut all: Vec<Arc<Vec<u8>>> = Vec::new();

            if let Some(items) = msg.protected_header.get_bytes_one_or_many(33) {
                for b in items {
                    all.push(Arc::new(b.as_ref().to_vec()));
                }
            }

            // V2 default is protected-only. Unprotected headers are not covered by the signature.
            if ctx.cose_header_location() == CoseHeaderLocation::Any {
                if let Some(items) = msg.unprotected_header.get_bytes_one_or_many(33) {
                    for b in items {
                        all.push(Arc::new(b.as_ref().to_vec()));
                    }
                }
            }

            return Ok(all);
        }

        let Some(bytes) = ctx.cose_sign1_bytes() else {
            return Ok(Vec::new());
        };

        let msg =
            CoseSign1::from_cbor(bytes).map_err(|e| TrustError::FactProduction(e.to_string()))?;

        // Protected header is a bstr containing a CBOR map.
        let mut all = Vec::new();
        all.extend(try_read_x5chain(msg.protected_header)?);

        // V2 default is protected-only. Unprotected headers are not covered by the signature.
        if ctx.cose_header_location() == CoseHeaderLocation::Any {
            all.extend(try_read_x5chain(msg.unprotected_header.as_ref())?);
        }

        Ok(all)
    }

    fn parse_x509(der: Arc<Vec<u8>>) -> Result<ParsedCert, TrustError> {
        let (_, cert) = X509Certificate::from_der(der.as_slice())
            .map_err(|e| TrustError::FactProduction(format!("x509 parse failed: {e:?}")))?;

        let mut sha1 = Sha1::new();
        sha1.update(der.as_slice());
        let thumb = hex::encode_upper(sha1.finalize());

        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        let serial_hex = hex::encode_upper(cert.serial.to_bytes_be());

        let not_before_unix_seconds = cert.validity().not_before.timestamp();
        let not_after_unix_seconds = cert.validity().not_after.timestamp();

        Ok(ParsedCert {
            der,
            thumbprint_sha1_hex: thumb,
            subject,
            issuer,
            serial_hex,
            not_before_unix_seconds,
            not_after_unix_seconds,
        })
    }

    fn signing_cert(ctx: &TrustFactContext<'_>) -> Result<Option<ParsedCert>, TrustError> {
        let chain = Self::parse_message_chain(ctx)?;
        let Some(first) = chain.first().cloned() else {
            return Ok(None);
        };
        Ok(Some(Self::parse_x509(first)?))
    }

    fn subject_is_signing_key(ctx: &TrustFactContext<'_>) -> bool {
        matches!(
            ctx.subject().kind,
            "PrimarySigningKey" | "CounterSignatureSigningKey"
        )
    }

    fn mark_missing_for_signing_cert_facts(ctx: &TrustFactContext<'_>, reason: &str) {
        ctx.mark_missing::<X509SigningCertificateIdentityFact>(reason);
        ctx.mark_missing::<X509SigningCertificateIdentityAllowedFact>(reason);
        ctx.mark_missing::<X509SigningCertificateEkuFact>(reason);
        ctx.mark_missing::<X509SigningCertificateKeyUsageFact>(reason);
        ctx.mark_missing::<X509SigningCertificateBasicConstraintsFact>(reason);
        ctx.mark_missing::<X509PublicKeyAlgorithmFact>(reason);
    }

    fn mark_produced_for_signing_cert_facts(ctx: &TrustFactContext<'_>) {
        ctx.mark_produced(FactKey::of::<X509SigningCertificateIdentityFact>());
        ctx.mark_produced(FactKey::of::<X509SigningCertificateIdentityAllowedFact>());
        ctx.mark_produced(FactKey::of::<X509SigningCertificateEkuFact>());
        ctx.mark_produced(FactKey::of::<X509SigningCertificateKeyUsageFact>());
        ctx.mark_produced(FactKey::of::<X509SigningCertificateBasicConstraintsFact>());
        ctx.mark_produced(FactKey::of::<X509PublicKeyAlgorithmFact>());
    }

    fn is_allowed(&self, thumbprint: &str) -> bool {
        if !self.options.identity_pinning_enabled {
            return true;
        }
        let needle = Self::normalize_thumbprint(thumbprint);
        self.options
            .allowed_thumbprints
            .iter()
            .any(|t| Self::normalize_thumbprint(t) == needle)
    }

    fn is_pqc_oid(&self, oid: &str) -> bool {
        self.options
            .pqc_algorithm_oids
            .iter()
            .any(|o| o.trim() == oid)
    }

    fn produce_signing_certificate_facts(
        &self,
        ctx: &TrustFactContext<'_>,
    ) -> Result<(), TrustError> {
        if !Self::subject_is_signing_key(ctx) {
            // Non-applicable subjects are Available/empty for all certificate facts.
            Self::mark_produced_for_signing_cert_facts(ctx);
            return Ok(());
        }

        let Some(_) = ctx.cose_sign1_bytes() else {
            Self::mark_missing_for_signing_cert_facts(ctx, "input_unavailable");
            Self::mark_produced_for_signing_cert_facts(ctx);
            return Ok(());
        };

        let Some(cert) = Self::signing_cert(ctx)? else {
            Self::mark_missing_for_signing_cert_facts(ctx, "input_unavailable");
            Self::mark_produced_for_signing_cert_facts(ctx);
            return Ok(());
        };

        // Identity
        ctx.observe(X509SigningCertificateIdentityFact {
            certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            serial_number: cert.serial_hex.clone(),
            not_before_unix_seconds: cert.not_before_unix_seconds,
            not_after_unix_seconds: cert.not_after_unix_seconds,
        })?;

        // Identity allowed
        let allowed = self.is_allowed(&cert.thumbprint_sha1_hex);
        ctx.observe(X509SigningCertificateIdentityAllowedFact {
            certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            is_allowed: allowed,
        })?;

        // Parse extensions once
        let (_, parsed) = X509Certificate::from_der(cert.der.as_slice())
            .map_err(|e| TrustError::FactProduction(format!("x509 parse failed: {e:?}")))?;

        // Public key algorithm
        let oid = parsed
            .tbs_certificate
            .subject_pki
            .algorithm
            .algorithm
            .to_id_string();
        let is_pqc = self.is_pqc_oid(&oid);
        ctx.observe(X509PublicKeyAlgorithmFact {
            certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
            algorithm_oid: oid,
            algorithm_name: None,
            is_pqc,
        })?;

        // EKU: one fact per OID
        for ext in parsed.extensions() {
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                // x509-parser models common EKUs as booleans + keeps unknown OIDs in `other`.
                // Emit OIDs so callers don't depend on enum shapes.
                let emit = |oid: &str| {
                    ctx.observe(X509SigningCertificateEkuFact {
                        certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
                        oid_value: oid.to_string(),
                    })
                };

                // Common EKUs (RFC 5280 / .NET expectations)
                if eku.any {
                    emit("2.5.29.37.0")?;
                }
                if eku.server_auth {
                    emit("1.3.6.1.5.5.7.3.1")?;
                }
                if eku.client_auth {
                    emit("1.3.6.1.5.5.7.3.2")?;
                }
                if eku.code_signing {
                    emit("1.3.6.1.5.5.7.3.3")?;
                }
                if eku.email_protection {
                    emit("1.3.6.1.5.5.7.3.4")?;
                }
                if eku.time_stamping {
                    emit("1.3.6.1.5.5.7.3.8")?;
                }
                if eku.ocsp_signing {
                    emit("1.3.6.1.5.5.7.3.9")?;
                }

                // Unknown/custom EKUs
                for oid in eku.other.iter() {
                    emit(&oid.to_id_string())?;
                }
            }
        }

        // Key usage: represent as a stable list of enabled purposes.
        let mut usages: Vec<String> = Vec::new();
        for ext in parsed.extensions() {
            if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
                // These match RFC 5280 ordering and .NET flag names.
                if ku.digital_signature() {
                    usages.push("DigitalSignature".to_string());
                }
                if ku.non_repudiation() {
                    usages.push("NonRepudiation".to_string());
                }
                if ku.key_encipherment() {
                    usages.push("KeyEncipherment".to_string());
                }
                if ku.data_encipherment() {
                    usages.push("DataEncipherment".to_string());
                }
                if ku.key_agreement() {
                    usages.push("KeyAgreement".to_string());
                }
                if ku.key_cert_sign() {
                    usages.push("KeyCertSign".to_string());
                }
                if ku.crl_sign() {
                    usages.push("CrlSign".to_string());
                }
                if ku.encipher_only() {
                    usages.push("EncipherOnly".to_string());
                }
                if ku.decipher_only() {
                    usages.push("DecipherOnly".to_string());
                }
            }
        }

        ctx.observe(X509SigningCertificateKeyUsageFact {
            certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
            usages,
        })?;

        // Basic constraints
        let mut is_ca = false;
        let mut path_len_constraint: Option<u32> = None;
        for ext in parsed.extensions() {
            if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                is_ca = bc.ca;
                path_len_constraint = bc.path_len_constraint;
            }
        }
        ctx.observe(X509SigningCertificateBasicConstraintsFact {
            certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
            is_ca,
            path_len_constraint,
        })?;

        Self::mark_produced_for_signing_cert_facts(ctx);
        Ok(())
    }

    fn produce_chain_identity_facts(&self, ctx: &TrustFactContext<'_>) -> Result<(), TrustError> {
        if !Self::subject_is_signing_key(ctx) {
            ctx.mark_produced(FactKey::of::<X509X5ChainCertificateIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementValidityFact>());
            return Ok(());
        }

        let Some(_) = ctx.cose_sign1_bytes() else {
            ctx.mark_missing::<X509X5ChainCertificateIdentityFact>("input_unavailable");
            ctx.mark_missing::<X509ChainElementIdentityFact>("input_unavailable");
            ctx.mark_missing::<X509ChainElementValidityFact>("input_unavailable");
            ctx.mark_produced(FactKey::of::<X509X5ChainCertificateIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementValidityFact>());
            return Ok(());
        };

        let chain = Self::parse_message_chain(ctx)?;
        if chain.is_empty() {
            ctx.mark_missing::<X509X5ChainCertificateIdentityFact>("input_unavailable");
            ctx.mark_missing::<X509ChainElementIdentityFact>("input_unavailable");
            ctx.mark_missing::<X509ChainElementValidityFact>("input_unavailable");
            ctx.mark_produced(FactKey::of::<X509X5ChainCertificateIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementIdentityFact>());
            ctx.mark_produced(FactKey::of::<X509ChainElementValidityFact>());
            return Ok(());
        }

        for (idx, der) in chain.into_iter().enumerate() {
            let cert = Self::parse_x509(der)?;
            ctx.observe(X509X5ChainCertificateIdentityFact {
                certificate_thumbprint: cert.thumbprint_sha1_hex.clone(),
                subject: cert.subject.clone(),
                issuer: cert.issuer.clone(),
            })?;
            ctx.observe(X509ChainElementIdentityFact {
                index: idx,
                certificate_thumbprint: cert.thumbprint_sha1_hex,
                subject: cert.subject,
                issuer: cert.issuer,
            })?;

            ctx.observe(X509ChainElementValidityFact {
                index: idx,
                not_before_unix_seconds: cert.not_before_unix_seconds,
                not_after_unix_seconds: cert.not_after_unix_seconds,
            })?;
        }

        ctx.mark_produced(FactKey::of::<X509X5ChainCertificateIdentityFact>());
        ctx.mark_produced(FactKey::of::<X509ChainElementIdentityFact>());
        ctx.mark_produced(FactKey::of::<X509ChainElementValidityFact>());
        Ok(())
    }

    fn produce_chain_trust_facts(&self, ctx: &TrustFactContext<'_>) -> Result<(), TrustError> {
        if !Self::subject_is_signing_key(ctx) {
            ctx.mark_produced(FactKey::of::<X509ChainTrustedFact>());
            ctx.mark_produced(FactKey::of::<CertificateSigningKeyTrustFact>());
            return Ok(());
        }

        let Some(_) = ctx.cose_sign1_bytes() else {
            ctx.mark_missing::<X509ChainTrustedFact>("input_unavailable");
            ctx.mark_missing::<CertificateSigningKeyTrustFact>("input_unavailable");
            ctx.mark_produced(FactKey::of::<X509ChainTrustedFact>());
            ctx.mark_produced(FactKey::of::<CertificateSigningKeyTrustFact>());
            return Ok(());
        };

        let chain = Self::parse_message_chain(ctx)?;
        let Some(first) = chain.first().cloned() else {
            ctx.mark_missing::<X509ChainTrustedFact>("input_unavailable");
            ctx.mark_missing::<CertificateSigningKeyTrustFact>("input_unavailable");
            ctx.mark_produced(FactKey::of::<X509ChainTrustedFact>());
            ctx.mark_produced(FactKey::of::<CertificateSigningKeyTrustFact>());
            return Ok(());
        };

        let leaf = Self::parse_x509(first)?;

        // Deterministic evaluation: validate basic chain *shape* (name chaining + self-signed root).
        // OS-native trust evaluation is intentionally not used here to keep results stable across
        // CI runners.
        let mut parsed_chain = Vec::with_capacity(chain.len());
        for b in &chain {
            parsed_chain.push(Self::parse_x509(b.clone())?);
        }

        let element_count = parsed_chain.len();
        let chain_built = element_count > 0;

        let well_formed = if parsed_chain.is_empty() {
            false
        } else {
            let mut ok = true;
            for i in 0..(parsed_chain.len().saturating_sub(1)) {
                if parsed_chain[i].issuer != parsed_chain[i + 1].subject {
                    ok = false;
                    break;
                }
            }
            let root = parsed_chain.last().unwrap();
            ok && root.subject == root.issuer
        };

        let is_trusted = self.options.trust_embedded_chain_as_trusted && well_formed;
        let (status_flags, status_summary) = if is_trusted {
            (0u32, None)
        } else if self.options.trust_embedded_chain_as_trusted {
            (1u32, Some("EmbeddedChainNotWellFormed".to_string()))
        } else {
            (1u32, Some("TrustEvaluationDisabled".to_string()))
        };

        ctx.observe(X509ChainTrustedFact {
            chain_built,
            is_trusted,
            status_flags,
            status_summary: status_summary.clone(),
            element_count,
        })?;

        ctx.observe(CertificateSigningKeyTrustFact {
            thumbprint: leaf.thumbprint_sha1_hex.clone(),
            subject: leaf.subject.clone(),
            issuer: leaf.issuer.clone(),
            chain_built,
            chain_trusted: is_trusted,
            chain_status_flags: status_flags,
            chain_status_summary: status_summary,
        })?;

        ctx.mark_produced(FactKey::of::<X509ChainTrustedFact>());
        ctx.mark_produced(FactKey::of::<CertificateSigningKeyTrustFact>());
        Ok(())
    }
}

impl TrustFactProducer for X509CertificateTrustPack {
    fn name(&self) -> &'static str {
        "cose_sign1_validation_certificates::X509CertificateTrustPack"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        let requested = ctx.requested_fact();

        // Group-produce related signing cert facts.
        if requested.type_id == FactKey::of::<X509SigningCertificateIdentityFact>().type_id
            || requested.type_id
                == FactKey::of::<X509SigningCertificateIdentityAllowedFact>().type_id
            || requested.type_id == FactKey::of::<X509SigningCertificateEkuFact>().type_id
            || requested.type_id == FactKey::of::<X509SigningCertificateKeyUsageFact>().type_id
            || requested.type_id
                == FactKey::of::<X509SigningCertificateBasicConstraintsFact>().type_id
            || requested.type_id == FactKey::of::<X509PublicKeyAlgorithmFact>().type_id
        {
            return self.produce_signing_certificate_facts(ctx);
        }

        // Group-produce chain identity facts.
        if requested.type_id == FactKey::of::<X509X5ChainCertificateIdentityFact>().type_id
            || requested.type_id == FactKey::of::<X509ChainElementIdentityFact>().type_id
        {
            return self.produce_chain_identity_facts(ctx);
        }

        // Group-produce chain trust summary + signing key trust.
        if requested.type_id == FactKey::of::<X509ChainTrustedFact>().type_id
            || requested.type_id == FactKey::of::<CertificateSigningKeyTrustFact>().type_id
        {
            return self.produce_chain_trust_facts(ctx);
        }

        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            vec![
                FactKey::of::<X509SigningCertificateIdentityFact>(),
                FactKey::of::<X509SigningCertificateIdentityAllowedFact>(),
                FactKey::of::<X509SigningCertificateEkuFact>(),
                FactKey::of::<X509SigningCertificateKeyUsageFact>(),
                FactKey::of::<X509SigningCertificateBasicConstraintsFact>(),
                FactKey::of::<X509X5ChainCertificateIdentityFact>(),
                FactKey::of::<X509ChainTrustedFact>(),
                FactKey::of::<X509ChainElementIdentityFact>(),
                FactKey::of::<X509ChainElementValidityFact>(),
                FactKey::of::<CertificateSigningKeyTrustFact>(),
                FactKey::of::<X509PublicKeyAlgorithmFact>(),
            ]
        })
        .as_slice()
    }
}
