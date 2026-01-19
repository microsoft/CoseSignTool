// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
    MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
    MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::ids::sha256_of_bytes;
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use cose_sign1_validation_trust::subject::TrustSubject;
use once_cell::sync::Lazy;
use std::collections::HashSet;

use crate::receipt_verify::{verify_mst_receipt, ReceiptVerifyError, ReceiptVerifyInput};

pub mod fluent_ext {
    pub use crate::fluent_ext::*;
}

/// COSE header label used by MST receipts (matches .NET): 394.
pub const MST_RECEIPT_HEADER_LABEL: i64 = 394;

#[derive(Clone, Debug, Default)]
pub struct MstTrustPack {
    /// If true, allow the verifier to fetch JWKS online when offline keys are missing or do not
    /// contain the required `kid`.
    ///
    /// This is an operational switch. Trust decisions (e.g., issuer allowlisting) belong in policy.
    pub allow_network: bool,

    /// Offline JWKS JSON used to resolve receipt signing keys by `kid`.
    ///
    /// This enables deterministic verification for test vectors without requiring network access.
    pub offline_jwks_json: Option<String>,

    /// Optional api-version to use for the CodeTransparency `/jwks` endpoint.
    /// If not set, the verifier will try without an api-version parameter.
    pub jwks_api_version: Option<String>,
}

impl MstTrustPack {
    /// Create an MST pack configured for offline-only verification.
    ///
    /// This disables network fetching and uses the provided JWKS JSON to resolve receipt signing
    /// keys.
    pub fn offline_with_jwks(jwks_json: impl Into<String>) -> Self {
        Self {
            allow_network: false,
            offline_jwks_json: Some(jwks_json.into()),
            jwks_api_version: None,
        }
    }

    /// Create an MST pack configured to allow online JWKS fetching.
    ///
    /// This is an operational switch only; issuer allowlisting should still be expressed via trust
    /// policy.
    pub fn online() -> Self {
        Self {
            allow_network: true,
            ..Default::default()
        }
    }
}

impl TrustFactProducer for MstTrustPack {
    /// Stable producer name used for diagnostics/audit.
    fn name(&self) -> &'static str {
        "cose_sign1_validation_transparent_mst::MstTrustPack"
    }

    /// Produce MST-related facts for the current subject.
    ///
    /// - On `Message` subjects: projects each receipt into a derived `CounterSignature` subject.
    /// - On `CounterSignature` subjects: verifies the receipt and emits MST facts.
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // MST receipts are modeled as counter-signatures:
        // - On the Message subject, we *project* each receipt into a derived CounterSignature subject.
        // - On the CounterSignature subject, we produce MST-specific facts (present/trusted).

        match ctx.subject().kind {
            "Message" => {
                // If the COSE message is unavailable, counter-signature discovery is Missing.
                if ctx.cose_sign1_message().is_none() && ctx.cose_sign1_bytes().is_none() {
                    ctx.mark_missing::<CounterSignatureSubjectFact>("MissingMessage");
                    ctx.mark_missing::<CounterSignatureSigningKeySubjectFact>("MissingMessage");
                    ctx.mark_missing::<UnknownCounterSignatureBytesFact>("MissingMessage");

                    for k in self.provides() {
                        ctx.mark_produced(*k);
                    }
                    return Ok(());
                }

                let receipts = read_receipts(ctx)?;

                let message_subject = match ctx.cose_sign1_bytes() {
                    Some(bytes) => TrustSubject::message(bytes),
                    None => TrustSubject::message(b"seed"),
                };

                let mut seen: HashSet<cose_sign1_validation_trust::ids::SubjectId> = HashSet::new();

                for r in receipts {
                    let cs_subject =
                        TrustSubject::counter_signature(&message_subject, r.as_slice());
                    let cs_key_subject = TrustSubject::counter_signature_signing_key(&cs_subject);

                    ctx.observe(CounterSignatureSubjectFact {
                        subject: cs_subject,
                        is_protected_header: false,
                    })?;
                    ctx.observe(CounterSignatureSigningKeySubjectFact {
                        subject: cs_key_subject,
                        is_protected_header: false,
                    })?;

                    let id = sha256_of_bytes(r.as_slice());
                    if seen.insert(id) {
                        ctx.observe(UnknownCounterSignatureBytesFact {
                            counter_signature_id: id,
                            raw_counter_signature_bytes: std::sync::Arc::from(r.into_boxed_slice()),
                        })?;
                    }
                }

                for k in self.provides() {
                    ctx.mark_produced(*k);
                }
                Ok(())
            }
            "CounterSignature" => {
                // If the COSE message is unavailable, we can't map this subject to a receipt.
                if ctx.cose_sign1_message().is_none() && ctx.cose_sign1_bytes().is_none() {
                    ctx.mark_missing::<MstReceiptPresentFact>("MissingMessage");
                    ctx.mark_missing::<MstReceiptTrustedFact>("MissingMessage");
                    for k in self.provides() {
                        ctx.mark_produced(*k);
                    }
                    return Ok(());
                }

                let receipts = read_receipts(ctx)?;

                let Some(message_bytes) = ctx.cose_sign1_bytes() else {
                    // Fallback: without bytes we can't compute the same subject IDs.
                    for k in self.provides() {
                        ctx.mark_produced(*k);
                    }
                    return Ok(());
                };

                let message_subject = TrustSubject::message(message_bytes);

                let mut matched_receipt: Option<Vec<u8>> = None;
                for r in receipts {
                    let cs = TrustSubject::counter_signature(&message_subject, r.as_slice());
                    if cs.id == ctx.subject().id {
                        matched_receipt = Some(r);
                        break;
                    }
                }

                let Some(receipt_bytes) = matched_receipt else {
                    // Not an MST receipt counter-signature; leave as Available(empty).
                    for k in self.provides() {
                        ctx.mark_produced(*k);
                    }
                    return Ok(());
                };

                // Receipt identified.
                ctx.observe(MstReceiptPresentFact { present: true })?;

                let jwks_json = self.offline_jwks_json.as_deref();
                let out = verify_mst_receipt(ReceiptVerifyInput {
                    statement_bytes_with_receipts: message_bytes,
                    receipt_bytes: receipt_bytes.as_slice(),
                    offline_jwks_json: jwks_json,
                    allow_network_fetch: self.allow_network,
                    jwks_api_version: self.jwks_api_version.as_deref(),
                });

                match out {
                    Ok(v) => {
                        ctx.observe(MstReceiptTrustedFact {
                            trusted: v.trusted,
                            details: v.details.clone(),
                        })?;

                        ctx.observe(MstReceiptIssuerFact {
                            issuer: v.issuer.clone(),
                        })?;
                        ctx.observe(MstReceiptKidFact { kid: v.kid.clone() })?;
                        ctx.observe(MstReceiptStatementSha256Fact {
                            sha256_hex: hex::encode(v.statement_sha256),
                        })?;
                        ctx.observe(MstReceiptStatementCoverageFact {
                            coverage: "sha256(COSE_Sign1 bytes with unprotected headers cleared)"
                                .to_string(),
                        })?;
                        ctx.observe(MstReceiptSignatureVerifiedFact { verified: true })?;

                        ctx.observe(CounterSignatureEnvelopeIntegrityFact {
                            sig_structure_intact: v.trusted,
                            details: Some(
                                "covers: sha256(COSE_Sign1 bytes with unprotected headers cleared)"
                                    .to_string(),
                            ),
                        })?;
                    }
                    Err(e @ ReceiptVerifyError::UnsupportedVds(_)) => {
                        // Non-Microsoft receipts can coexist with MST receipts.
                        // Make the fact Available(false) so AnyOf semantics can still succeed.
                        ctx.observe(MstReceiptTrustedFact {
                            trusted: false,
                            details: Some(e.to_string()),
                        })?;
                    }
                    Err(e) => ctx.observe(MstReceiptTrustedFact {
                        trusted: false,
                        details: Some(e.to_string()),
                    })?,
                }

                for k in self.provides() {
                    ctx.mark_produced(*k);
                }
                Ok(())
            }
            _ => {
                for k in self.provides() {
                    ctx.mark_produced(*k);
                }
                Ok(())
            }
        }
    }

    /// Return the set of fact keys this pack can produce.
    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: Lazy<[FactKey; 11]> = Lazy::new(|| {
            [
                // Counter-signature projection (message-scoped)
                FactKey::of::<CounterSignatureSubjectFact>(),
                FactKey::of::<CounterSignatureSigningKeySubjectFact>(),
                FactKey::of::<UnknownCounterSignatureBytesFact>(),
                // MST-specific facts (counter-signature scoped)
                FactKey::of::<MstReceiptPresentFact>(),
                FactKey::of::<MstReceiptTrustedFact>(),
                FactKey::of::<MstReceiptIssuerFact>(),
                FactKey::of::<MstReceiptKidFact>(),
                FactKey::of::<MstReceiptStatementSha256Fact>(),
                FactKey::of::<MstReceiptStatementCoverageFact>(),
                FactKey::of::<MstReceiptSignatureVerifiedFact>(),
                FactKey::of::<CounterSignatureEnvelopeIntegrityFact>(),
            ]
        });
        &*PROVIDED
    }
}

impl CoseSign1TrustPack for MstTrustPack {
    /// Short display name for this trust pack.
    fn name(&self) -> &'static str {
        "MstTrustPack"
    }

    /// Return a `TrustFactProducer` instance for this pack.
    fn fact_producer(&self) -> std::sync::Arc<dyn TrustFactProducer> {
        std::sync::Arc::new(self.clone())
    }

    /// Return the default trust plan for MST-only validation.
    ///
    /// This plan requires that a counter-signature receipt is trusted.
    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        use crate::fluent_ext::MstReceiptTrustedWhereExt;

        // Secure-by-default MST policy:
        // - require a receipt to be trusted (verification must be enabled)
        let bundled = TrustPlanBuilder::new(vec![std::sync::Arc::new(self.clone())])
            .for_counter_signature(|cs| {
                cs.require::<MstReceiptTrustedFact>(|f| f.require_receipt_trusted())
            })
            .compile()
            .expect("default trust plan should be satisfiable by the MST trust pack");

        Some(bundled.plan().clone())
    }
}

/// Read all MST receipt blobs from the current message.
///
/// Prefers the parsed message view when available; falls back to decoding unprotected header bytes.
fn read_receipts(ctx: &TrustFactContext<'_>) -> Result<Vec<Vec<u8>>, TrustError> {
    if let Some(msg) = ctx.cose_sign1_message() {
        match msg.unprotected_header.get(MST_RECEIPT_HEADER_LABEL) {
            None => return Ok(Vec::new()),
            Some(cose_sign1_validation_trust::CoseHeaderValue::BytesArray(v)) => {
                return Ok(v.iter().map(|b| b.as_ref().to_vec()).collect());
            }
            Some(cose_sign1_validation_trust::CoseHeaderValue::Bytes(_)) => {
                return Err(TrustError::FactProduction("invalid header".to_string()));
            }
            Some(_) => {
                return Err(TrustError::FactProduction("invalid header".to_string()));
            }
        }
    }

    let Some(cose_bytes) = ctx.cose_sign1_bytes() else {
        return Ok(Vec::new());
    };

    let msg =
        CoseSign1::from_cbor(cose_bytes).map_err(|e| TrustError::FactProduction(e.to_string()))?;
    try_read_receipts(msg.unprotected_header.as_ref())
}

/// Parse the unprotected header map and extract receipt blobs under label 394.
///
/// The canonical encoding is an array of `bstr`. A single `bstr` value is treated as invalid.
fn try_read_receipts(unprotected_map_bytes: &[u8]) -> Result<Vec<Vec<u8>>, TrustError> {
    let mut d = tinycbor::Decoder(unprotected_map_bytes);
    let mut map = d
        .map_visitor()
        .map_err(|e| TrustError::FactProduction(e.to_string()))?;

    while let Some(entry) = map.visit::<i64, tinycbor::Any>() {
        let (key, value_any) = entry.map_err(|e| TrustError::FactProduction(e.to_string()))?;
        if key != MST_RECEIPT_HEADER_LABEL {
            continue;
        }

        // Receipt value can be either:
        // - CBOR array of bstr (canonical encoding).
        // A single bstr value is treated as invalid.

        let mut vd = tinycbor::Decoder(value_any.as_ref());
        let Ok(mut arr) = vd.array_visitor() else {
            return Err(TrustError::FactProduction("invalid header".to_string()));
        };

        let mut out = Vec::new();
        while let Some(item) = arr.visit::<&[u8]>() {
            let b = item.map_err(|e| TrustError::FactProduction(e.to_string()))?;
            out.push(b.to_vec());
        }

        return Ok(out);
    }

    Ok(Vec::new())
}
