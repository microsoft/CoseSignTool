// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::Arc;
use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// An opaque, borrow-based reader over a CBOR-encoded value.
///
/// This is intended for custom policy predicates that need to inspect a claim value
/// without the library interpreting its schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborValueReader<'a> {
    bytes: &'a [u8],
}

impl<'a> CborValueReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Best-effort decode helper for callers who want a typed view.
    ///
    /// Note: this does not enforce full consumption of the input.
    pub fn decode<T: tinycbor::Decode<'a>>(&self) -> Option<T> {
        let mut d = tinycbor::Decoder(self.bytes);
        T::decode(&mut d).ok()
    }
}

/// Parsed, owned view of a COSE_Sign1 message.
///
/// This is intentionally "boring" and ownership-heavy so it can be stored as a trust fact
/// without lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1MessagePartsFact {
    pub protected_header: Arc<Vec<u8>>,
    pub unprotected_header: Arc<Vec<u8>>,
    pub payload: Option<Arc<Vec<u8>>>,
    pub signature: Arc<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1MessageBytesFact {
    pub bytes: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetachedPayloadPresentFact {
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentTypeFact {
    pub content_type: String,
}

/// Indicates whether the COSE header parameter for CWT Claims (label 15) is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwtClaimsPresentFact {
    pub present: bool,
}

/// Parsed view of a CWT Claims map from the COSE header parameter (label 15).
///
/// This exposes common standard claims as optional fields, and also preserves any scalar
/// (string/int/bool) claim values in `scalar_claims` keyed by claim label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CwtClaimsFact {
    pub scalar_claims: BTreeMap<i64, CwtClaimScalar>,

    /// Raw CBOR bytes for each numeric claim label.
    pub raw_claims: BTreeMap<i64, Arc<[u8]>>,

    /// Raw CBOR bytes for each text claim key.
    pub raw_claims_text: BTreeMap<String, Arc<[u8]>>,

    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CwtClaimScalar {
    Str(String),
    I64(i64),
    Bool(bool),
}

impl CwtClaimsFact {
    pub fn claim_value_i64(&self, label: i64) -> Option<CborValueReader<'_>> {
        self.raw_claims
            .get(&label)
            .map(|b| CborValueReader::new(b.as_ref()))
    }

    pub fn claim_value_text(&self, key: &str) -> Option<CborValueReader<'_>> {
        self.raw_claims_text
            .get(key)
            .map(|b| CborValueReader::new(b.as_ref()))
    }
}

/// Field-name constants for declarative trust policies.
pub mod fields {
    pub mod detached_payload_present {
        pub const PRESENT: &str = "present";
    }

    pub mod content_type {
        pub const CONTENT_TYPE: &str = "content_type";
    }

    pub mod cwt_claims_present {
        pub const PRESENT: &str = "present";
    }

    pub mod cwt_claims {
        pub const ISS: &str = "iss";
        pub const SUB: &str = "sub";
        pub const AUD: &str = "aud";
        pub const EXP: &str = "exp";
        pub const NBF: &str = "nbf";
        pub const IAT: &str = "iat";

        /// Scalar claim values can also be addressed by numeric label.
        ///
        /// Format: `claim_<label>` (e.g. `claim_42`).
        pub const CLAIM_PREFIX: &str = "claim_";
    }
}

/// Typed fields for fluent trust-policy authoring.
pub mod typed_fields {
    use super::{ContentTypeFact, CwtClaimsFact, CwtClaimsPresentFact, DetachedPayloadPresentFact};
    use cose_sign1_validation_trust::field::Field;

    pub mod detached_payload_present {
        use super::*;
        pub const PRESENT: Field<DetachedPayloadPresentFact, bool> =
            Field::new(crate::message_facts::fields::detached_payload_present::PRESENT);
    }

    pub mod content_type {
        use super::*;
        pub const CONTENT_TYPE: Field<ContentTypeFact, String> =
            Field::new(crate::message_facts::fields::content_type::CONTENT_TYPE);
    }

    pub mod cwt_claims_present {
        use super::*;
        pub const PRESENT: Field<CwtClaimsPresentFact, bool> =
            Field::new(crate::message_facts::fields::cwt_claims_present::PRESENT);
    }

    pub mod cwt_claims {
        use super::*;

        pub const ISS: Field<CwtClaimsFact, String> =
            Field::new(crate::message_facts::fields::cwt_claims::ISS);
        pub const SUB: Field<CwtClaimsFact, String> =
            Field::new(crate::message_facts::fields::cwt_claims::SUB);
        pub const AUD: Field<CwtClaimsFact, String> =
            Field::new(crate::message_facts::fields::cwt_claims::AUD);
        pub const EXP: Field<CwtClaimsFact, i64> =
            Field::new(crate::message_facts::fields::cwt_claims::EXP);
        pub const NBF: Field<CwtClaimsFact, i64> =
            Field::new(crate::message_facts::fields::cwt_claims::NBF);
        pub const IAT: Field<CwtClaimsFact, i64> =
            Field::new(crate::message_facts::fields::cwt_claims::IAT);
    }
}

/// Fluent helper methods for common message-fact filters.
///
/// Usage:
/// `use cose_sign1_validation::message_facts::fluent_ext::*;`
pub mod fluent_ext {
    use super::{
        typed_fields as msg_typed, CborValueReader, ContentTypeFact, CwtClaimsFact,
        CwtClaimsPresentFact, DetachedPayloadPresentFact,
    };
    use cose_sign1_validation_trust::facts::FactKey;
    use cose_sign1_validation_trust::fluent::{MessageScope, ScopeRules, Where};
    use cose_sign1_validation_trust::rules::require_any;

    pub trait DetachedPayloadPresentWhereExt {
        fn require_detached_payload_present(self) -> Self;
        fn require_detached_payload_absent(self) -> Self;
    }

    impl DetachedPayloadPresentWhereExt for Where<DetachedPayloadPresentFact> {
        fn require_detached_payload_present(self) -> Self {
            self.r#true(msg_typed::detached_payload_present::PRESENT)
        }

        fn require_detached_payload_absent(self) -> Self {
            self.r#false(msg_typed::detached_payload_present::PRESENT)
        }
    }

    pub trait ContentTypeWhereExt {
        fn content_type_eq(self, content_type: impl Into<String>) -> Self;
        fn content_type_non_empty(self) -> Self;
    }

    impl ContentTypeWhereExt for Where<ContentTypeFact> {
        fn content_type_eq(self, content_type: impl Into<String>) -> Self {
            self.str_eq(msg_typed::content_type::CONTENT_TYPE, content_type)
        }

        fn content_type_non_empty(self) -> Self {
            self.str_non_empty(msg_typed::content_type::CONTENT_TYPE)
        }
    }

    pub trait CwtClaimsPresentWhereExt {
        fn require_cwt_claims_present(self) -> Self;
        fn require_cwt_claims_absent(self) -> Self;
    }

    impl CwtClaimsPresentWhereExt for Where<CwtClaimsPresentFact> {
        fn require_cwt_claims_present(self) -> Self {
            self.r#true(msg_typed::cwt_claims_present::PRESENT)
        }

        fn require_cwt_claims_absent(self) -> Self {
            self.r#false(msg_typed::cwt_claims_present::PRESENT)
        }
    }

    pub trait CwtClaimsWhereExt {
        fn iss_eq(self, iss: impl Into<String>) -> Self;
        fn sub_eq(self, sub: impl Into<String>) -> Self;
        fn aud_eq(self, aud: impl Into<String>) -> Self;
    }

    impl CwtClaimsWhereExt for Where<CwtClaimsFact> {
        fn iss_eq(self, iss: impl Into<String>) -> Self {
            self.str_eq(msg_typed::cwt_claims::ISS, iss)
        }

        fn sub_eq(self, sub: impl Into<String>) -> Self {
            self.str_eq(msg_typed::cwt_claims::SUB, sub)
        }

        fn aud_eq(self, aud: impl Into<String>) -> Self {
            self.str_eq(msg_typed::cwt_claims::AUD, aud)
        }
    }

    /// Fluent helper methods for message-scope rules.
    ///
    /// These are intentionally "one click down" from `TrustPlanBuilder::for_message(...)` so
    /// policy authoring doesn't need to reference fact types or typed-field constants.
    pub trait MessageScopeRulesExt {
        fn require_content_type_non_empty(self) -> Self;
        fn require_content_type_eq(self, content_type: impl Into<String>) -> Self;
        fn require_detached_payload_present(self) -> Self;
        fn require_detached_payload_absent(self) -> Self;

        fn require_cwt_claims_present(self) -> Self;
        fn require_cwt_claims_absent(self) -> Self;

        /// Require that a CWT claim exists and satisfies a custom predicate.
        ///
        /// Supports both numeric claim labels (e.g. `6` for `iat`) and text claim keys
        /// (e.g. `"iat"`), so callers don't need to choose between separate helpers.
        fn require_cwt_claim<K, P>(self, key: K, predicate: P) -> Self
        where
            K: Into<CwtClaimKey>,
            P: for<'a> Fn(CborValueReader<'a>) -> bool + Send + Sync + 'static;
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum CwtClaimKey {
        Label(i64),
        Text(String),
    }

    impl From<i64> for CwtClaimKey {
        fn from(value: i64) -> Self {
            Self::Label(value)
        }
    }

    impl From<String> for CwtClaimKey {
        fn from(value: String) -> Self {
            Self::Text(value)
        }
    }

    impl From<&str> for CwtClaimKey {
        fn from(value: &str) -> Self {
            Self::Text(value.to_string())
        }
    }

    impl MessageScopeRulesExt for ScopeRules<MessageScope> {
        fn require_content_type_non_empty(self) -> Self {
            self.require::<ContentTypeFact>(|w| w.content_type_non_empty())
        }

        fn require_content_type_eq(self, content_type: impl Into<String>) -> Self {
            self.require::<ContentTypeFact>(|w| w.content_type_eq(content_type))
        }

        fn require_detached_payload_present(self) -> Self {
            self.require::<DetachedPayloadPresentFact>(|w| w.require_detached_payload_present())
        }

        fn require_detached_payload_absent(self) -> Self {
            self.require::<DetachedPayloadPresentFact>(|w| w.require_detached_payload_absent())
        }

        fn require_cwt_claims_present(self) -> Self {
            self.require::<CwtClaimsPresentFact>(|w| w.require_cwt_claims_present())
        }

        fn require_cwt_claims_absent(self) -> Self {
            self.require::<CwtClaimsPresentFact>(|w| w.require_cwt_claims_absent())
        }

        fn require_cwt_claim<K, P>(self, key: K, predicate: P) -> Self
        where
            K: Into<CwtClaimKey>,
            P: for<'a> Fn(CborValueReader<'a>) -> bool + Send + Sync + 'static,
        {
            let key = key.into();
            let rule = require_any::<CwtClaimsFact, _, _>(
                "cwt_claim",
                |s| s.clone(),
                move |fact: &CwtClaimsFact| {
                    let Some(reader) = (match &key {
                        CwtClaimKey::Label(label) => fact.claim_value_i64(*label),
                        CwtClaimKey::Text(text) => fact.claim_value_text(text.as_str()),
                    }) else {
                        return false;
                    };

                    predicate(reader)
                },
                "CwtClaimNotSatisfied",
            );

            self.require_rule(rule, [FactKey::of::<CwtClaimsFact>()])
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSignatureSubjectFact {
    pub subject: cose_sign1_validation_trust::subject::TrustSubject,
    pub is_protected_header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrimarySigningKeySubjectFact {
    pub subject: cose_sign1_validation_trust::subject::TrustSubject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSignatureSigningKeySubjectFact {
    pub subject: cose_sign1_validation_trust::subject::TrustSubject,
    pub is_protected_header: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCounterSignatureBytesFact {
    pub counter_signature_id: cose_sign1_validation_trust::ids::SubjectId,
    pub raw_counter_signature_bytes: Arc<[u8]>,
}

/// Indicates that a counter-signature verifier has cryptographically verified the integrity of the
/// outer COSE_Sign1 envelope (i.e., the bytes that the verifier considers to be covered).
///
/// This fact is intended to allow the validator to bypass primary signature verification when
/// configured trust sources (e.g., MST receipts) already attest to envelope integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSignatureEnvelopeIntegrityFact {
    pub sig_structure_intact: bool,
    pub details: Option<String>,
}

impl FactProperties for DetachedPayloadPresentFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "present" => Some(FactValue::Bool(self.present)),
            _ => None,
        }
    }
}

impl FactProperties for ContentTypeFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "content_type" => Some(FactValue::Str(Cow::Borrowed(self.content_type.as_str()))),
            _ => None,
        }
    }
}

impl FactProperties for CwtClaimsPresentFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "present" => Some(FactValue::Bool(self.present)),
            _ => None,
        }
    }
}

impl FactProperties for CwtClaimsFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::cwt_claims::ISS => self
                .iss
                .as_deref()
                .map(|v| FactValue::Str(Cow::Borrowed(v))),
            fields::cwt_claims::SUB => self
                .sub
                .as_deref()
                .map(|v| FactValue::Str(Cow::Borrowed(v))),
            fields::cwt_claims::AUD => self
                .aud
                .as_deref()
                .map(|v| FactValue::Str(Cow::Borrowed(v))),
            fields::cwt_claims::EXP => self.exp.map(FactValue::I64),
            fields::cwt_claims::NBF => self.nbf.map(FactValue::I64),
            fields::cwt_claims::IAT => self.iat.map(FactValue::I64),
            _ => {
                if let Some(rest) = name.strip_prefix(fields::cwt_claims::CLAIM_PREFIX) {
                    if let Ok(label) = rest.parse::<i64>() {
                        return self.scalar_claims.get(&label).and_then(|v| match v {
                            CwtClaimScalar::Str(s) => {
                                Some(FactValue::Str(Cow::Borrowed(s.as_str())))
                            }
                            CwtClaimScalar::I64(n) => Some(FactValue::I64(*n)),
                            CwtClaimScalar::Bool(b) => Some(FactValue::Bool(*b)),
                        });
                    }
                }
                None
            }
        }
    }
}

impl FactProperties for CounterSignatureEnvelopeIntegrityFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "sig_structure_intact" => Some(FactValue::Bool(self.sig_structure_intact)),
            _ => None,
        }
    }
}
