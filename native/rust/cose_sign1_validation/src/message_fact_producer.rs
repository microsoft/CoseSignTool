// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::cose::CoseSign1;
use crate::message_facts::{
    ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact, CwtClaimScalar,
    CwtClaimsFact, CwtClaimsPresentFact, DetachedPayloadPresentFact, PrimarySigningKeySubjectFact,
    UnknownCounterSignatureBytesFact,
};
use crate::validator::CounterSignatureResolver;
use cose_sign1_validation_trust::error::TrustError;
use cose_sign1_validation_trust::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_trust::ids::sha256_of_bytes;
use cose_sign1_validation_trust::subject::TrustSubject;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Produces basic "message facts" from the COSE_Sign1 bytes in the engine context.
///
/// This mirrors the V2 pattern where fact producers can access the message, but keeps
/// everything as owned bytes so facts are cacheable without lifetimes.
#[derive(Default, Clone)]
pub struct CoseSign1MessageFactProducer {
    counter_signature_resolvers: Vec<Arc<dyn CounterSignatureResolver>>,
}

impl CoseSign1MessageFactProducer {
    /// Create a producer with default settings.
    ///
    /// By default, no counter-signature resolvers are configured; counter-signature discovery is
    /// therefore a no-op.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach counter-signature resolvers used to discover counter-signatures from message parts.
    ///
    /// These resolvers are only consulted when producing facts for the `Message` subject.
    pub fn with_counter_signature_resolvers(
        mut self,
        resolvers: Vec<Arc<dyn CounterSignatureResolver>>,
    ) -> Self {
        self.counter_signature_resolvers = resolvers;
        self
    }
}

impl TrustFactProducer for CoseSign1MessageFactProducer {
    /// A stable name used in diagnostics and audit trails.
    fn name(&self) -> &'static str {
        "cose_sign1_validation::CoseSign1MessageFactProducer"
    }

    /// Produce message-derived facts for the current subject.
    ///
    /// This producer is intentionally conservative:
    /// - It only produces facts for the `Message` subject kind.
    /// - It prefers the parsed message already available in the engine context.
    /// - When parsing fails, it marks appropriate facts as `Error`/`Missing` rather than panicking.
    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // V2 parity: core message facts only apply to the Message subject.
        if ctx.subject().kind != "Message" {
            for k in self.provides() {
                ctx.mark_produced(*k);
            }
            return Ok(());
        }

        let bytes = match ctx.cose_sign1_bytes() {
            Some(b) => b,
            None => {
                ctx.mark_missing::<CoseSign1MessageBytesFact>("MissingMessage");
                ctx.mark_missing::<CoseSign1MessagePartsFact>("MissingMessage");
                ctx.mark_missing::<DetachedPayloadPresentFact>("MissingMessage");
                ctx.mark_missing::<ContentTypeFact>("MissingMessage");
                ctx.mark_missing::<CwtClaimsPresentFact>("MissingMessage");
                ctx.mark_missing::<CwtClaimsFact>("MissingMessage");
                ctx.mark_missing::<CounterSignatureSubjectFact>("MissingMessage");
                ctx.mark_missing::<PrimarySigningKeySubjectFact>("MissingMessage");
                ctx.mark_missing::<CounterSignatureSigningKeySubjectFact>("MissingMessage");
                ctx.mark_missing::<UnknownCounterSignatureBytesFact>("MissingMessage");

                for k in self.provides() {
                    ctx.mark_produced(*k);
                }
                return Ok(());
            }
        };

        // Always produce bytes fact.
        ctx.observe(CoseSign1MessageBytesFact {
            bytes: Arc::from(bytes),
        })?;

        // Produce parts/content-type/detached/countersignature facts.
        // Prefer the already-parsed message from the engine context.
        if let Some(pm) = ctx.cose_sign1_message() {
            let protected_header = Arc::new(pm.protected_header_bytes.as_ref().to_vec());
            let unprotected_header = Arc::new(pm.unprotected_header_bytes.as_ref().to_vec());
            let payload = pm.payload.as_ref().map(|p| Arc::new(p.as_ref().to_vec()));
            let signature = Arc::new(pm.signature.as_ref().to_vec());

            ctx.observe(CoseSign1MessagePartsFact {
                protected_header,
                unprotected_header,
                payload,
                signature,
            })?;

            ctx.observe(DetachedPayloadPresentFact {
                present: pm.payload.is_none(),
            })?;

            if let Some(ct) = resolve_content_type_from_parsed(pm) {
                ctx.observe(ContentTypeFact { content_type: ct })?;
            }

            produce_cwt_claims_facts(ctx, pm)?;

            // V2 parity: provide a derived subject for the primary signing key.
            ctx.observe(PrimarySigningKeySubjectFact {
                subject: TrustSubject::primary_signing_key(ctx.subject()),
            })?;

            // V2 parity: counter-signatures are resolver-driven.
            self.produce_counter_signature_facts(ctx, pm)?;
        } else {
            let msg = match CoseSign1::from_cbor(bytes) {
                Ok(m) => m,
                Err(e) => {
                    ctx.mark_error::<CoseSign1MessagePartsFact>(format!("cose_decode_failed: {e}"));
                    for k in self.provides() {
                        ctx.mark_produced(*k);
                    }
                    return Ok(());
                }
            };

            let protected_header = Arc::new(msg.protected_header.to_vec());
            let unprotected_header = Arc::new(msg.unprotected_header.as_ref().to_vec());
            let payload = msg.payload.map(|p| Arc::new(p.to_vec()));
            let signature = Arc::new(msg.signature.to_vec());

            ctx.observe(CoseSign1MessagePartsFact {
                protected_header,
                unprotected_header,
                payload,
                signature,
            })?;

            ctx.observe(DetachedPayloadPresentFact {
                present: msg.payload.is_none(),
            })?;

            if let Ok(pm) = cose_sign1_validation_trust::CoseSign1ParsedMessage::from_parts(
                msg.protected_header,
                msg.unprotected_header.as_ref(),
                msg.payload,
                msg.signature,
            ) {
                if let Some(ct) = resolve_content_type_from_parsed(&pm) {
                    ctx.observe(ContentTypeFact { content_type: ct })?;
                }

                produce_cwt_claims_facts(ctx, &pm)?;

                // V2 parity: provide a derived subject for the primary signing key.
                ctx.observe(PrimarySigningKeySubjectFact {
                    subject: TrustSubject::primary_signing_key(ctx.subject()),
                })?;

                // V2 parity: counter-signatures are resolver-driven.
                self.produce_counter_signature_facts(ctx, &pm)?;
            }
        }

        for k in self.provides() {
            ctx.mark_produced(*k);
        }
        Ok(())
    }

    /// Declare the set of facts this producer can produce.
    fn provides(&self) -> &'static [FactKey] {
        static PROVIDED: Lazy<[FactKey; 10]> = Lazy::new(|| {
            [
                FactKey::of::<CoseSign1MessageBytesFact>(),
                FactKey::of::<CoseSign1MessagePartsFact>(),
                FactKey::of::<DetachedPayloadPresentFact>(),
                FactKey::of::<ContentTypeFact>(),
                FactKey::of::<CwtClaimsPresentFact>(),
                FactKey::of::<CwtClaimsFact>(),
                FactKey::of::<CounterSignatureSubjectFact>(),
                FactKey::of::<PrimarySigningKeySubjectFact>(),
                FactKey::of::<CounterSignatureSigningKeySubjectFact>(),
                FactKey::of::<UnknownCounterSignatureBytesFact>(),
            ]
        });
        &*PROVIDED
    }
}

/// Decode and emit CWT-claims facts from the message headers.
///
/// The claim set is carried in COSE header parameter label `15` and is expected to be a CBOR map.
/// For convenience, a subset of well-known claims are also exposed as typed fields (e.g. `iss`).
fn produce_cwt_claims_facts(
    ctx: &TrustFactContext<'_>,
    pm: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
) -> Result<(), TrustError> {
    // COSE header parameter label 15 = CWT Claims.
    const CWT_CLAIMS: i64 = 15;

    let raw = pm
        .protected_header
        .get(CWT_CLAIMS)
        .or_else(|| pm.unprotected_header.get(CWT_CLAIMS))
        .cloned();

    let Some(raw) = raw else {
        ctx.observe(CwtClaimsPresentFact { present: false })?;
        return Ok(());
    };

    ctx.observe(CwtClaimsPresentFact { present: true })?;

    // We expect a CBOR map. The header map parser stores non-scalar values as `Other`.
    let value_bytes: Arc<[u8]> = match raw {
        cose_sign1_validation_trust::CoseHeaderValue::Other(b) => b,
        // Unexpected shape: treat as present but unparseable.
        _ => {
            ctx.mark_error::<CwtClaimsFact>("CwtClaimsValueNotMap".to_string());
            return Ok(());
        }
    };

    let mut d = tinycbor::Decoder(value_bytes.as_ref());
    let mut map = d
        .map_visitor()
        .map_err(|e| TrustError::FactProduction(format!("cwt_claims_map_decode_failed: {e}")))?;

    let mut scalar_claims: BTreeMap<i64, CwtClaimScalar> = BTreeMap::new();
    let mut raw_claims: BTreeMap<i64, Arc<[u8]>> = BTreeMap::new();
    let mut raw_claims_text: BTreeMap<String, Arc<[u8]>> = BTreeMap::new();

    // Standard CWT claim labels (RFC 8392):
    // 1=iss, 2=sub, 3=aud, 4=exp, 5=nbf, 6=iat, 7=cti
    let mut iss: Option<String> = None;
    let mut sub: Option<String> = None;
    let mut aud: Option<String> = None;
    let mut exp: Option<i64> = None;
    let mut nbf: Option<i64> = None;
    let mut iat: Option<i64> = None;

    while let Some(entry) = map.visit::<tinycbor::Any<'_>, tinycbor::Any<'_>>() {
        let (key_any, value_any) = entry.map_err(|e| {
            TrustError::FactProduction(format!("cwt_claim_entry_decode_failed: {e}"))
        })?;

        let key_bytes = key_any.as_ref();
        let value_bytes = value_any.as_ref();

        // CWT standard claim keys are typically integers (RFC 8392), but some profiles may
        // emit text keys. Handle both.
        let key_i64 = decode_cbor_i64_one(key_bytes);
        let key_text = decode_cbor_text_one(key_bytes);

        // Try scalar value types.
        let value_str =
            <String as tinycbor::Decode>::decode(&mut tinycbor::Decoder(value_bytes)).ok();
        let value_i64 = decode_cbor_i64_one(value_bytes);
        let value_bool = match value_bytes {
            [0xF4] => Some(false),
            [0xF5] => Some(true),
            _ => None,
        };

        // Preserve raw bytes for both numeric and text keys.
        if let Some(k) = key_i64 {
            raw_claims.insert(k, Arc::from(value_bytes.to_vec().into_boxed_slice()));

            // Store numeric-keyed scalar claims.
            if let Some(s) = &value_str {
                scalar_claims.insert(k, CwtClaimScalar::Str(s.clone()));
            } else if let Some(n) = value_i64 {
                scalar_claims.insert(k, CwtClaimScalar::I64(n));
            } else if let Some(b) = value_bool {
                scalar_claims.insert(k, CwtClaimScalar::Bool(b));
            }

            match (k, &value_str, value_i64) {
                (1, Some(s), _) => iss = Some(s.clone()),
                (2, Some(s), _) => sub = Some(s.clone()),
                (3, Some(s), _) => aud = Some(s.clone()),
                (4, _, Some(n)) => exp = Some(n),
                (5, _, Some(n)) => nbf = Some(n),
                (6, _, Some(n)) => iat = Some(n),
                _ => {}
            }

            continue;
        }

        // Store a few well-known text-keyed claims as first-class fields.
        if let Some(k) = key_text.as_deref() {
            raw_claims_text.insert(
                k.to_string(),
                Arc::from(value_bytes.to_vec().into_boxed_slice()),
            );

            match (k, &value_str, value_i64) {
                ("iss", Some(s), _) => iss = Some(s.clone()),
                ("sub", Some(s), _) => sub = Some(s.clone()),
                ("aud", Some(s), _) => aud = Some(s.clone()),
                ("exp", _, Some(n)) => exp = Some(n),
                ("nbf", _, Some(n)) => nbf = Some(n),
                ("iat", _, Some(n)) => iat = Some(n),
                _ => {}
            }
        }
    }

    ctx.observe(CwtClaimsFact {
        scalar_claims,
        raw_claims,
        raw_claims_text,
        iss,
        sub,
        aud,
        exp,
        nbf,
        iat,
    })?;

    Ok(())
}

/// Decode a single CBOR text string from `bytes`.
///
/// Returns `None` if decoding fails.
fn decode_cbor_text_one(bytes: &[u8]) -> Option<String> {
    let mut d = tinycbor::Decoder(bytes);
    <String as tinycbor::Decode>::decode(&mut d).ok()
}

/// Decode a single CBOR integer (major type 0/1) from `bytes`.
///
/// Returns `None` if decoding fails.
fn decode_cbor_i64_one(bytes: &[u8]) -> Option<i64> {
    decode_cbor_i64(bytes).map(|(n, _used)| n)
}

/// Decode a CBOR integer (major type 0/1) and return the value plus bytes consumed.
///
/// This is a small, allocation-free helper used when parsing CBOR map keys/values that may be
/// embedded in COSE headers.
fn decode_cbor_i64(bytes: &[u8]) -> Option<(i64, usize)> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 0x1f;

    let (unsigned, used) = decode_cbor_uint_value(ai, &bytes[1..])?;

    match major {
        0 => i64::try_from(unsigned).ok().map(|v| (v, 1 + used)),
        1 => {
            // Negative integer is encoded as -1 - n.
            let n = i64::try_from(unsigned).ok()?;
            Some((-1 - n, 1 + used))
        }
        _ => None,
    }
}

/// Decode the unsigned-integer argument for a CBOR additional information (AI) value.
///
/// Returns `(value, bytes_consumed_from_rest)`.
fn decode_cbor_uint_value(ai: u8, rest: &[u8]) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, 0)),
        24 => Some((u64::from(*rest.first()?), 1)),
        25 => {
            let b = rest.get(0..2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 2))
        }
        26 => {
            let b = rest.get(0..4)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4))
        }
        27 => {
            let b = rest.get(0..8)?;
            Some((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                8,
            ))
        }
        _ => None,
    }
}

impl CoseSign1MessageFactProducer {
    /// Produce counter-signature-derived subjects and unknown raw bytes facts.
    ///
    /// This uses the configured [`CounterSignatureResolver`]s to discover counter-signatures from
    /// the message, then derives stable trust subjects:
    /// - `CounterSignature` subjects are derived from the message subject and raw bytes.
    /// - `CounterSignatureSigningKey` subjects are derived from each counter-signature subject.
    ///
    /// When resolvers are configured but all fail, the relevant fact keys are marked as `Missing`
    /// with aggregated failure reasons (mirrors the V2 behavior).
    fn produce_counter_signature_facts(
        &self,
        ctx: &TrustFactContext<'_>,
        pm: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> Result<(), TrustError> {
        if self.counter_signature_resolvers.is_empty() {
            // No resolver-driven discovery configured.
            // Treat this as Available(empty) rather than Missing so that other producers
            // may contribute counter-signature subjects.
            return Ok(());
        }

        let mut subjects = Vec::new();
        let mut signing_key_subjects = Vec::new();
        let mut unknowns = Vec::new();
        let mut seen_ids: HashSet<cose_sign1_validation_trust::ids::SubjectId> = HashSet::new();
        let mut any_success = false;
        let mut failure_reasons: Vec<String> = Vec::new();

        for resolver in &self.counter_signature_resolvers {
            let result = resolver.resolve(pm);

            if !result.is_success {
                let mut reason = format!("ProducerFailed:{}", resolver.name());
                if let Some(msg) = result.error_message {
                    if !msg.trim().is_empty() {
                        reason = format!("{reason}:{msg}");
                    }
                }
                failure_reasons.push(reason);
                continue;
            }

            any_success = true;

            for cs in result.counter_signatures {
                let raw = cs.raw_counter_signature_bytes();
                let is_protected_header = cs.is_protected_header();

                let subject = TrustSubject::counter_signature(ctx.subject(), raw.as_ref());
                let signing_key_subject = TrustSubject::counter_signature_signing_key(&subject);
                signing_key_subjects.push(CounterSignatureSigningKeySubjectFact {
                    subject: signing_key_subject,
                    is_protected_header,
                });

                subjects.push(CounterSignatureSubjectFact {
                    subject,
                    is_protected_header,
                });

                let counter_signature_id = sha256_of_bytes(raw.as_ref());
                if seen_ids.insert(counter_signature_id) {
                    unknowns.push(UnknownCounterSignatureBytesFact {
                        counter_signature_id,
                        raw_counter_signature_bytes: raw,
                    });
                }
            }
        }

        for f in subjects {
            ctx.observe(f)?;
        }
        for f in signing_key_subjects {
            ctx.observe(f)?;
        }
        for f in unknowns {
            ctx.observe(f)?;
        }

        if !any_success && !failure_reasons.is_empty() {
            // If we had resolvers but none succeeded, surface a Missing reason like V2.
            ctx.mark_missing::<CounterSignatureSubjectFact>(failure_reasons.join(" | "));
            ctx.mark_missing::<CounterSignatureSigningKeySubjectFact>(failure_reasons.join(" | "));
            ctx.mark_missing::<UnknownCounterSignatureBytesFact>(failure_reasons.join(" | "));
        }

        Ok(())
    }
}

/// Resolve a user-friendly content type string from COSE headers.
///
/// This mirrors the V2 behavior and supports the `CoseHashEnvelope` marker semantics, where the
/// preimage content type (label `259`) is preferred.
fn resolve_content_type_from_parsed(
    pm: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
) -> Option<String> {
    // Mirrors V2 CoseSign1MessageExtensions.TryGetContentType.
    // Header labels:
    // - 3 = content-type
    // - 258 = CoseHashEnvelope payload hash alg (signature format marker)
    // - 259 = CoseHashEnvelope preimage content type
    const CONTENT_TYPE: i64 = 3;
    const PAYLOAD_HASH_ALG: i64 = 258;
    const PREIMAGE_CONTENT_TYPE: i64 = 259;

    let has_envelope_marker = pm.protected_header.get(PAYLOAD_HASH_ALG).is_some();

    let raw_ct = get_text_or_utf8_bytes(&pm.protected_header, CONTENT_TYPE)
        .or_else(|| get_text_or_utf8_bytes(&pm.unprotected_header, CONTENT_TYPE));

    if has_envelope_marker {
        if let Some(ct) = get_text_or_utf8_bytes(&pm.protected_header, PREIMAGE_CONTENT_TYPE)
            .or_else(|| get_text_or_utf8_bytes(&pm.unprotected_header, PREIMAGE_CONTENT_TYPE))
        {
            return Some(ct);
        }

        if let Some(i) = pm
            .protected_header
            .get_i64(PREIMAGE_CONTENT_TYPE)
            .or_else(|| pm.unprotected_header.get_i64(PREIMAGE_CONTENT_TYPE))
        {
            return Some(format!("coap/{i}"));
        }

        return None;
    }

    let ct = raw_ct?;

    static COSE_HASH_V: Lazy<Regex> = Lazy::new(|| Regex::new("(?i)\\+cose-hash-v").unwrap());
    static HASH_LEGACY: Lazy<Regex> = Lazy::new(|| Regex::new("(?i)\\+hash-([\\w_]+)").unwrap());

    if COSE_HASH_V.is_match(&ct) {
        let stripped = COSE_HASH_V.replace_all(&ct, "");
        let stripped = stripped.trim();
        return (!stripped.is_empty()).then(|| stripped.to_string());
    }

    if HASH_LEGACY.is_match(&ct) {
        let stripped = HASH_LEGACY.replace_all(&ct, "");
        let stripped = stripped.trim();
        return (!stripped.is_empty()).then(|| stripped.to_string());
    }

    Some(ct)
}

/// Read a header value as either a text string or UTF-8 bytes.
///
/// Some producers encode string-ish values as CBOR bstr containing UTF-8 bytes; this helper
/// provides a tolerant accessor.
fn get_text_or_utf8_bytes(
    map: &cose_sign1_validation_trust::CoseHeaderMap,
    label: i64,
) -> Option<String> {
    if let Some(s) = map.get_text(label) {
        if !s.trim().is_empty() {
            return Some(s.to_string());
        }
    }

    let b = map.get(label).and_then(|v| v.as_bytes())?;
    let s = std::str::from_utf8(b).ok()?;
    (!s.trim().is_empty()).then(|| s.to_string())
}
