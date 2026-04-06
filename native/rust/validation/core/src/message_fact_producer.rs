// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::message_facts::{
    ContentTypeFact, CoseSign1MessageBytesFact, CoseSign1MessagePartsFact,
    CounterSignatureSigningKeySubjectFact, CounterSignatureSubjectFact, CwtClaimScalar,
    CwtClaimsFact, CwtClaimsPresentFact, DetachedPayloadPresentFact, PrimarySigningKeySubjectFact,
    UnknownCounterSignatureBytesFact,
};
use crate::validator::CounterSignatureResolver;
use cbor_primitives::{CborDecoder, CborEncoder};
use cose_sign1_primitives::{CoseHeaderLabel, CoseHeaderMap, CoseHeaderValue, CoseSign1Message};
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_primitives::ids::sha256_of_bytes;
use cose_sign1_validation_primitives::subject::TrustSubject;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::sync::Arc;

/// Produces basic "message facts" from the COSE_Sign1 bytes in the engine context.
///
/// This producer operates directly on [`CoseSign1Message`] from `cose_sign1_primitives`,
/// eliminating duplicate parsing and type conversion.
#[derive(Clone, Default)]
pub struct CoseSign1MessageFactProducer {
    counter_signature_resolvers: Vec<Arc<dyn CounterSignatureResolver>>,
}

impl CoseSign1MessageFactProducer {
    /// Create a producer.
    ///
    /// By default, no counter-signature resolvers are configured; counter-signature discovery is
    /// therefore a no-op.
    pub fn new() -> Self {
        Self {
            counter_signature_resolvers: Vec::new(),
        }
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
    fn name(&self) -> &'static str {
        "cose_sign1_validation::CoseSign1MessageFactProducer"
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // Core message facts only apply to the Message subject.
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

        // Parse or use already-parsed message
        let msg: Arc<CoseSign1Message> = if let Some(m) = ctx.cose_sign1_message_arc() {
            m
        } else {
            // Message should always be available from the validator
            ctx.mark_error::<CoseSign1MessagePartsFact>("no parsed message in context".to_string());
            for k in self.provides() {
                ctx.mark_produced(*k);
            }
            return Ok(());
        };

        // Produce the parts fact wrapping the message
        ctx.observe(CoseSign1MessagePartsFact::new(Arc::clone(&msg)))?;

        ctx.observe(DetachedPayloadPresentFact {
            present: msg.payload().is_none(),
        })?;

        // Content type
        if let Some(ct) = resolve_content_type(&msg) {
            ctx.observe(ContentTypeFact { content_type: ct })?;
        }

        // CWT claims
        produce_cwt_claims_facts(ctx, &msg)?;

        // Primary signing key subject
        ctx.observe(PrimarySigningKeySubjectFact {
            subject: TrustSubject::primary_signing_key(ctx.subject()),
        })?;

        // Counter-signatures
        self.produce_counter_signature_facts(ctx, &msg)?;

        for k in self.provides() {
            ctx.mark_produced(*k);
        }
        Ok(())
    }

    fn provides(&self) -> &'static [FactKey] {
        provided_fact_keys()
    }
}

/// Returns the static set of fact keys provided by the message fact producer.
pub(crate) fn provided_fact_keys() -> &'static [FactKey] {
    static PROVIDED: std::sync::LazyLock<[FactKey; 10]> = std::sync::LazyLock::new(|| {
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

/// Decode and emit CWT-claims facts from the message headers.
fn produce_cwt_claims_facts(
    ctx: &TrustFactContext<'_>,
    msg: &CoseSign1Message,
) -> Result<(), TrustError> {
    const CWT_CLAIMS: i64 = 15;
    let cwt_label = CoseHeaderLabel::Int(CWT_CLAIMS);

    // Check protected then unprotected headers
    let raw = msg
        .protected
        .headers()
        .get(&cwt_label)
        .or_else(|| msg.unprotected.get(&cwt_label));

    let Some(raw) = raw else {
        ctx.observe(CwtClaimsPresentFact { present: false })?;
        return Ok(());
    };

    ctx.observe(CwtClaimsPresentFact { present: true })?;

    // CWT claims can be either raw bytes (not yet decoded) or an already-decoded Map
    match raw {
        CoseHeaderValue::Raw(b) => {
            // Parse from raw bytes
            produce_cwt_claims_from_bytes(ctx, b.as_ref())
        }
        CoseHeaderValue::Map(pairs) => {
            // Already decoded - extract claims directly
            produce_cwt_claims_from_map(ctx, pairs)
        }
        _ => {
            ctx.mark_error::<CwtClaimsFact>("CwtClaimsValueNotMap".to_string());
            Ok(())
        }
    }
}

/// Extract CWT claims from an already-decoded Map.
fn produce_cwt_claims_from_map(
    ctx: &TrustFactContext<'_>,
    pairs: &[(CoseHeaderLabel, CoseHeaderValue)],
) -> Result<(), TrustError> {
    let mut scalar_claims: BTreeMap<i64, CwtClaimScalar> = BTreeMap::new();
    let mut raw_claims: BTreeMap<i64, Arc<[u8]>> = BTreeMap::new();
    let mut raw_claims_text: BTreeMap<Arc<str>, Arc<[u8]>> = BTreeMap::new();

    let mut iss: Option<Arc<str>> = None;
    let mut sub: Option<Arc<str>> = None;
    let mut aud: Option<Arc<str>> = None;
    let mut exp: Option<i64> = None;
    let mut nbf: Option<i64> = None;
    let mut iat: Option<i64> = None;

    for (key, value) in pairs {
        // Extract scalar values
        let value_str = extract_string(value);
        let value_i64 = extract_i64(value);
        let value_bool = extract_bool(value);

        // Re-encode value to raw bytes for raw_claims
        let value_bytes = encode_value_to_bytes(value);

        match key {
            CoseHeaderLabel::Int(k) => {
                if let Some(bytes) = value_bytes {
                    raw_claims.insert(*k, Arc::from(bytes.into_boxed_slice()));
                }

                if let Some(s) = &value_str {
                    scalar_claims.insert(*k, CwtClaimScalar::Str(s.clone()));
                } else if let Some(n) = value_i64 {
                    scalar_claims.insert(*k, CwtClaimScalar::I64(n));
                } else if let Some(b) = value_bool {
                    scalar_claims.insert(*k, CwtClaimScalar::Bool(b));
                }

                match (*k, &value_str, value_i64) {
                    (1, Some(s), _) => iss = Some(s.clone()),
                    (2, Some(s), _) => sub = Some(s.clone()),
                    (3, Some(s), _) => aud = Some(s.clone()),
                    (4, _, Some(n)) => exp = Some(n),
                    (5, _, Some(n)) => nbf = Some(n),
                    (6, _, Some(n)) => iat = Some(n),
                    _ => {}
                }
            }
            CoseHeaderLabel::Text(k) => {
                if let Some(bytes) = value_bytes {
                    raw_claims_text.insert(Arc::from(k.as_str()), Arc::from(bytes.into_boxed_slice()));
                }

                match (k.as_str(), &value_str, value_i64) {
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

/// Extract a string from a CoseHeaderValue.
fn extract_string(value: &CoseHeaderValue) -> Option<Arc<str>> {
    match value {
        CoseHeaderValue::Text(s) => Some(Arc::from(&**s)),
        CoseHeaderValue::Bytes(b) => std::str::from_utf8(b.as_ref()).ok().map(Arc::from),
        _ => None,
    }
}

/// Extract an i64 from a CoseHeaderValue.
fn extract_i64(value: &CoseHeaderValue) -> Option<i64> {
    match value {
        CoseHeaderValue::Int(n) => Some(*n),
        CoseHeaderValue::Uint(n) if *n <= i64::MAX as u64 => Some(*n as i64),
        _ => None,
    }
}

/// Extract a bool from a CoseHeaderValue.
fn extract_bool(value: &CoseHeaderValue) -> Option<bool> {
    match value {
        CoseHeaderValue::Bool(b) => Some(*b),
        _ => None,
    }
}

/// Re-encode a CoseHeaderValue to bytes.
fn encode_value_to_bytes(value: &CoseHeaderValue) -> Option<Vec<u8>> {
    let mut enc = cose_sign1_primitives::provider::encoder();
    encode_value_recursive(&mut enc, value).ok()?;
    Some(enc.into_bytes())
}

/// Recursively encode a CoseHeaderValue.
fn encode_value_recursive(
    enc: &mut cose_sign1_primitives::provider::Encoder,
    value: &CoseHeaderValue,
) -> Result<(), String> {
    match value {
        CoseHeaderValue::Int(n) => enc.encode_i64(*n).map_err(|e| e.to_string()),
        CoseHeaderValue::Uint(n) => enc.encode_u64(*n).map_err(|e| e.to_string()),
        CoseHeaderValue::Bytes(b) => enc.encode_bstr(b).map_err(|e| e.to_string()),
        CoseHeaderValue::Text(s) => enc.encode_tstr(s).map_err(|e| e.to_string()),
        CoseHeaderValue::Bool(b) => enc.encode_bool(*b).map_err(|e| e.to_string()),
        CoseHeaderValue::Null => enc.encode_null().map_err(|e| e.to_string()),
        CoseHeaderValue::Undefined => enc.encode_undefined().map_err(|e| e.to_string()),
        CoseHeaderValue::Float(f) => enc.encode_f64(*f).map_err(|e| e.to_string()),
        CoseHeaderValue::Raw(b) => enc.encode_raw(b).map_err(|e| e.to_string()),
        CoseHeaderValue::Array(arr) => {
            enc.encode_array(arr.len()).map_err(|e| e.to_string())?;
            for v in arr {
                encode_value_recursive(enc, v)?;
            }
            Ok(())
        }
        CoseHeaderValue::Map(pairs) => {
            enc.encode_map(pairs.len()).map_err(|e| e.to_string())?;
            for (k, v) in pairs {
                match k {
                    CoseHeaderLabel::Int(n) => enc.encode_i64(*n).map_err(|e| e.to_string())?,
                    CoseHeaderLabel::Text(s) => enc.encode_tstr(s).map_err(|e| e.to_string())?,
                }
                encode_value_recursive(enc, v)?;
            }
            Ok(())
        }
        CoseHeaderValue::Tagged(tag, inner) => {
            enc.encode_tag(*tag).map_err(|e| e.to_string())?;
            encode_value_recursive(enc, inner)
        }
    }
}

/// Parse CWT claims from raw CBOR bytes.
fn produce_cwt_claims_from_bytes(
    ctx: &TrustFactContext<'_>,
    value_bytes: &[u8],
) -> Result<(), TrustError> {
    let mut d = cose_sign1_primitives::provider::decoder(value_bytes);
    let map_len = match d.decode_map_len() {
        Ok(Some(len)) => len,
        Ok(None) => {
            ctx.mark_error::<CwtClaimsFact>("cwt_claims indefinite map not supported".to_string());
            return Ok(());
        }
        Err(e) => {
            ctx.mark_error::<CwtClaimsFact>(format!("cwt_claims_map_decode_failed: {e}"));
            return Ok(());
        }
    };

    let mut scalar_claims: BTreeMap<i64, CwtClaimScalar> = BTreeMap::new();
    let mut raw_claims: BTreeMap<i64, Arc<[u8]>> = BTreeMap::new();
    let mut raw_claims_text: BTreeMap<Arc<str>, Arc<[u8]>> = BTreeMap::new();

    let mut iss: Option<Arc<str>> = None;
    let mut sub: Option<Arc<str>> = None;
    let mut aud: Option<Arc<str>> = None;
    let mut exp: Option<i64> = None;
    let mut nbf: Option<i64> = None;
    let mut iat: Option<i64> = None;

    for _ in 0..map_len {
        let key_bytes = match d.decode_raw() {
            Ok(b) => b.to_vec(),
            Err(e) => {
                ctx.mark_error::<CwtClaimsFact>(format!("cwt_claim_key_decode_failed: {e}"));
                return Ok(());
            }
        };
        let value_bytes = match d.decode_raw() {
            Ok(b) => b.to_vec(),
            Err(e) => {
                ctx.mark_error::<CwtClaimsFact>(format!("cwt_claim_value_decode_failed: {e}"));
                return Ok(());
            }
        };

        let key_i64 = cbor_primitives::RawCbor::new(&key_bytes).try_as_i64();
        let key_text = cbor_primitives::RawCbor::new(&key_bytes)
            .try_as_str()
            .map(Arc::<str>::from);

        let value_raw = cbor_primitives::RawCbor::new(&value_bytes);
        let value_str = value_raw.try_as_str().map(Arc::<str>::from);
        let value_i64 = value_raw.try_as_i64();
        let value_bool = value_raw.try_as_bool();

        if let Some(k) = key_i64 {
            if let Some(s) = &value_str {
                scalar_claims.insert(k, CwtClaimScalar::Str(Arc::clone(s)));
            } else if let Some(n) = value_i64 {
                scalar_claims.insert(k, CwtClaimScalar::I64(n));
            } else if let Some(b) = value_bool {
                scalar_claims.insert(k, CwtClaimScalar::Bool(b));
            }

            match (k, &value_str, value_i64) {
                (1, Some(s), _) => iss = Some(Arc::clone(s)),
                (2, Some(s), _) => sub = Some(Arc::clone(s)),
                (3, Some(s), _) => aud = Some(Arc::clone(s)),
                (4, _, Some(n)) => exp = Some(n),
                (5, _, Some(n)) => nbf = Some(n),
                (6, _, Some(n)) => iat = Some(n),
                _ => {}
            }

            raw_claims.insert(k, Arc::from(value_bytes.into_boxed_slice()));
            continue;
        }

        if let Some(k) = key_text {
            if let Some(s) = &value_str {
                match &*k {
                    "iss" => iss = Some(Arc::clone(s)),
                    "sub" => sub = Some(Arc::clone(s)),
                    "aud" => aud = Some(Arc::clone(s)),
                    _ => {}
                }
            } else {
                match &*k {
                    "exp" => {
                        if let Some(n) = value_i64 {
                            exp = Some(n);
                        }
                    }
                    "nbf" => {
                        if let Some(n) = value_i64 {
                            nbf = Some(n);
                        }
                    }
                    "iat" => {
                        if let Some(n) = value_i64 {
                            iat = Some(n);
                        }
                    }
                    _ => {}
                }
            }

            raw_claims_text.insert(k, Arc::from(value_bytes.into_boxed_slice()));
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

impl CoseSign1MessageFactProducer {
    fn produce_counter_signature_facts(
        &self,
        ctx: &TrustFactContext<'_>,
        msg: &CoseSign1Message,
    ) -> Result<(), TrustError> {
        if self.counter_signature_resolvers.is_empty() {
            return Ok(());
        }

        let mut subjects = Vec::new();
        let mut signing_key_subjects = Vec::new();
        let mut unknowns = Vec::new();
        let mut seen_ids: HashSet<cose_sign1_validation_primitives::ids::SubjectId> =
            HashSet::new();
        let mut any_success = false;
        let mut failure_reasons: Vec<String> = Vec::new();

        for resolver in &self.counter_signature_resolvers {
            let result = resolver.resolve(msg);

            if !result.is_success {
                let mut reason = format!("ProducerFailed:{}", resolver.name());
                if let Some(err_msg) = result.error_message {
                    if !err_msg.trim().is_empty() {
                        reason = format!("{reason}:{err_msg}");
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
            ctx.mark_missing::<CounterSignatureSubjectFact>(failure_reasons.join(" | "));
            ctx.mark_missing::<CounterSignatureSigningKeySubjectFact>(failure_reasons.join(" | "));
            ctx.mark_missing::<UnknownCounterSignatureBytesFact>(failure_reasons.join(" | "));
        }

        Ok(())
    }
}

/// Resolve content type from COSE headers.
fn resolve_content_type(msg: &CoseSign1Message) -> Option<Arc<str>> {
    const CONTENT_TYPE: i64 = 3;
    const PAYLOAD_HASH_ALG: i64 = 258;
    const PREIMAGE_CONTENT_TYPE: i64 = 259;

    let protected = msg.protected.headers();
    let unprotected = msg.unprotected.headers();

    let ct_label = CoseHeaderLabel::Int(CONTENT_TYPE);
    let hash_alg_label = CoseHeaderLabel::Int(PAYLOAD_HASH_ALG);
    let preimage_ct_label = CoseHeaderLabel::Int(PREIMAGE_CONTENT_TYPE);

    let has_envelope_marker = protected.get(&hash_alg_label).is_some();

    let raw_ct =
        get_header_text(protected, &ct_label).or_else(|| get_header_text(unprotected, &ct_label));

    if has_envelope_marker {
        if let Some(ct) = get_header_text(protected, &preimage_ct_label)
            .or_else(|| get_header_text(unprotected, &preimage_ct_label))
        {
            return Some(ct);
        }

        if let Some(i) = get_header_int(protected, &preimage_ct_label)
            .or_else(|| get_header_int(unprotected, &preimage_ct_label))
        {
            return Some(Arc::from(format!("coap/{i}").as_str()));
        }

        return None;
    }

    let ct = raw_ct?;

    // Check for +cose-hash-v suffix (case-insensitive) and strip it
    let lower = ct.to_ascii_lowercase();
    if lower.contains("+cose-hash-v") {
        let pos = lower.find("+cose-hash-v").unwrap();
        let stripped = ct[..pos].trim();
        return (!stripped.is_empty()).then(|| Arc::from(stripped));
    }

    // Check for +hash-<alg> suffix (case-insensitive) and strip it
    if let Some(pos) = lower.find("+hash-") {
        let stripped = ct[..pos].trim();
        return (!stripped.is_empty()).then(|| Arc::from(stripped));
    }

    Some(ct)
}

/// Get a text value from headers.
fn get_header_text(map: &CoseHeaderMap, label: &CoseHeaderLabel) -> Option<Arc<str>> {
    match map.get(label)? {
        CoseHeaderValue::Text(s) if !s.trim().is_empty() => Some(Arc::from(&**s)),
        CoseHeaderValue::Bytes(b) => {
            let s = std::str::from_utf8(b.as_ref()).ok()?;
            (!s.trim().is_empty()).then(|| Arc::from(s))
        }
        _ => None,
    }
}

/// Get an integer value from headers.
fn get_header_int(map: &CoseHeaderMap, label: &CoseHeaderLabel) -> Option<i64> {
    match map.get(label)? {
        CoseHeaderValue::Int(i) => Some(*i),
        _ => None,
    }
}
