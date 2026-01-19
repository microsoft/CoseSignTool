// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::cose::CoseSign1;
use crate::trust_plan_builder::CoseSign1CompiledTrustPlan;
use crate::trust_packs::CoseSign1TrustPack;
use cose_sign1_validation_trust::facts::{TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_trust::plan::CompiledTrustPlan;
use cose_sign1_validation_trust::subject::TrustSubject;
use cose_sign1_validation_trust::{
    CoseHeaderLocation, CoseSign1ParsedMessage, TrustDecision, TrustEvaluationOptions,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;
use tinycbor::{Encode, Encoder};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResultKind {
    Success,
    Failure,
    NotApplicable,
}

impl Default for ValidationResultKind {
    fn default() -> Self {
        Self::NotApplicable
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationFailure {
    pub message: String,
    pub error_code: Option<String>,
    pub property_name: Option<String>,
    pub attempted_value: Option<String>,
    pub exception: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationResult {
    pub kind: ValidationResultKind,
    pub validator_name: String,
    pub failures: Vec<ValidationFailure>,
    pub metadata: BTreeMap<String, String>,
}

impl ValidationResult {
    pub const METADATA_REASON_KEY: &'static str = "Reason";

    pub fn is_valid(&self) -> bool {
        matches!(self.kind, ValidationResultKind::Success)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self.kind, ValidationResultKind::Failure)
    }

    pub fn success(
        validator_name: impl Into<String>,
        metadata: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self {
            kind: ValidationResultKind::Success,
            validator_name: validator_name.into(),
            failures: Vec::new(),
            metadata: metadata.unwrap_or_default(),
        }
    }

    pub fn not_applicable(validator_name: impl Into<String>, reason: Option<&str>) -> Self {
        let mut metadata = BTreeMap::new();
        if let Some(r) = reason {
            if !r.trim().is_empty() {
                metadata.insert(Self::METADATA_REASON_KEY.to_string(), r.to_string());
            }
        }
        Self {
            kind: ValidationResultKind::NotApplicable,
            validator_name: validator_name.into(),
            failures: Vec::new(),
            metadata,
        }
    }

    pub fn failure(validator_name: impl Into<String>, failures: Vec<ValidationFailure>) -> Self {
        Self {
            kind: ValidationResultKind::Failure,
            validator_name: validator_name.into(),
            failures,
            metadata: BTreeMap::new(),
        }
    }

    pub fn failure_message(
        validator_name: impl Into<String>,
        message: impl Into<String>,
        error_code: Option<&str>,
    ) -> Self {
        Self::failure(
            validator_name,
            vec![ValidationFailure {
                message: message.into(),
                error_code: error_code.map(|s| s.to_string()),
                ..ValidationFailure::default()
            }],
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1ValidationResult {
    pub resolution: ValidationResult,
    pub trust: ValidationResult,
    pub signature: ValidationResult,
    pub post_signature_policy: ValidationResult,
    pub overall: ValidationResult,
}

#[derive(Debug, Clone, Default)]
pub struct CoseSign1ValidationOptions {
    pub detached_payload: Option<DetachedPayload>,
    pub associated_data: Option<Arc<[u8]>>,
    pub certificate_header_location: CoseHeaderLocation,
    pub skip_post_signature_validation: bool,
    pub trust_evaluation_options: TrustEvaluationOptions,
}

/// Provides detached payload bytes.
///
/// This is designed to let callers supply a stream-like source without forcing the validator
/// to own an un-cloneable reader.
pub trait DetachedPayloadProvider: Send + Sync {
    /// Opens a fresh reader for the detached payload.
    fn open(&self) -> Result<Box<dyn Read + Send>, String>;

    /// Optional length hint. If unknown, return `None`.
    fn len_hint(&self) -> Option<u64> {
        None
    }
}

/// Detached payload input.
#[derive(Clone)]
pub enum DetachedPayload {
    Bytes(Arc<[u8]>),
    Provider(Arc<dyn DetachedPayloadProvider>),
}

impl std::fmt::Debug for DetachedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetachedPayload::Bytes(b) => f
                .debug_struct("DetachedPayload::Bytes")
                .field("len", &b.len())
                .finish(),
            DetachedPayload::Provider(_) => f.debug_struct("DetachedPayload::Provider").finish(),
        }
    }
}

impl DetachedPayload {
    pub fn bytes(bytes: Arc<[u8]>) -> Self {
        Self::Bytes(bytes)
    }
}

/// Helper provider that opens a new reader via a closure.
pub struct DetachedPayloadFnProvider<F>
where
    F: Fn() -> Result<Box<dyn Read + Send>, String> + Send + Sync + 'static,
{
    opener: F,
    len_hint: Option<u64>,
}

impl<F> DetachedPayloadFnProvider<F>
where
    F: Fn() -> Result<Box<dyn Read + Send>, String> + Send + Sync + 'static,
{
    pub fn new(opener: F) -> Self {
        Self {
            opener,
            len_hint: None,
        }
    }

    pub fn with_len_hint(mut self, len_hint: u64) -> Self {
        self.len_hint = Some(len_hint);
        self
    }
}

impl<F> DetachedPayloadProvider for DetachedPayloadFnProvider<F>
where
    F: Fn() -> Result<Box<dyn Read + Send>, String> + Send + Sync + 'static,
{
    fn open(&self) -> Result<Box<dyn Read + Send>, String> {
        (self.opener)()
    }

    fn len_hint(&self) -> Option<u64> {
        self.len_hint
    }
}

#[derive(Clone, Default)]
pub struct SigningKeyResolutionResult {
    pub is_success: bool,
    pub signing_key: Option<Arc<dyn SigningKey>>,
    pub candidate_keys: Vec<Arc<dyn SigningKey>>,
    pub key_id: Option<Arc<[u8]>>,
    pub thumbprint: Option<Arc<[u8]>>,
    pub diagnostics: Vec<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl SigningKeyResolutionResult {
    pub fn success(signing_key: Arc<dyn SigningKey>) -> Self {
        Self {
            is_success: true,
            signing_key: Some(signing_key),
            ..Self::default()
        }
    }

    pub fn failure(error_code: Option<String>, error_message: Option<String>) -> Self {
        Self {
            is_success: false,
            error_code,
            error_message,
            ..Self::default()
        }
    }
}

pub trait SigningKeyResolver: Send + Sync {
    fn resolve(
        &self,
        message: &CoseSign1<'_>,
        options: &CoseSign1ValidationOptions,
    ) -> SigningKeyResolutionResult;

    fn resolve_async<'a>(
        &'a self,
        message: &'a CoseSign1<'a>,
        options: &'a CoseSign1ValidationOptions,
    ) -> BoxFuture<'a, SigningKeyResolutionResult> {
        Box::pin(async move { self.resolve(message, options) })
    }
}

pub trait SigningKey: Send + Sync {
    fn key_type(&self) -> &'static str;

    /// Verify the COSE signature for the given `Sig_structure` bytes.
    fn verify(&self, alg: i64, sig_structure: &[u8], signature: &[u8]) -> Result<bool, String>;

    /// Verify the COSE signature for a streaming `Sig_structure`.
    ///
    /// Default implementation buffers the stream into memory and calls `verify`.
    /// Implementations may override to avoid allocating large buffers.
    fn verify_reader(
        &self,
        alg: i64,
        sig_structure: &mut dyn Read,
        signature: &[u8],
    ) -> Result<bool, String> {
        let mut buf = Vec::new();
        sig_structure
            .read_to_end(&mut buf)
            .map_err(|e| format!("sig_structure_read_failed: {e}"))?;
        self.verify(alg, &buf, signature)
    }
}

/// Mirrors V2 `ICounterSignature` at the abstraction layer.
pub trait CounterSignature: Send + Sync {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]>;

    /// Whether the counter signature was found in the protected header.
    fn is_protected_header(&self) -> bool;

    /// Signing key material for the counter signature.
    /// Mirrors V2 where a resolved counter signature carries its signing key.
    fn signing_key(&self) -> Arc<dyn SigningKey>;
}

#[derive(Clone, Default)]
pub struct CounterSignatureResolutionResult {
    pub is_success: bool,
    pub counter_signatures: Vec<Arc<dyn CounterSignature>>,
    pub diagnostics: Vec<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl CounterSignatureResolutionResult {
    pub fn success(counter_signatures: Vec<Arc<dyn CounterSignature>>) -> Self {
        Self {
            is_success: true,
            counter_signatures,
            ..Self::default()
        }
    }

    pub fn failure(error_code: Option<String>, error_message: Option<String>) -> Self {
        Self {
            is_success: false,
            error_code,
            error_message,
            ..Self::default()
        }
    }
}

/// Mirrors V2 `ICounterSignatureResolver` semantics: resolver-driven discovery.
pub trait CounterSignatureResolver: Send + Sync {
    fn name(&self) -> &'static str;

    fn resolve(
        &self,
        message: &cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> CounterSignatureResolutionResult;

    fn resolve_async<'a>(
        &'a self,
        message: &'a cose_sign1_validation_trust::CoseSign1ParsedMessage,
    ) -> BoxFuture<'a, CounterSignatureResolutionResult> {
        Box::pin(async move { self.resolve(message) })
    }
}

pub trait PostSignatureValidator: Send + Sync {
    fn validate(&self, context: &PostSignatureValidationContext<'_>) -> ValidationResult;

    fn validate_async<'a>(
        &'a self,
        context: &'a PostSignatureValidationContext<'a>,
    ) -> BoxFuture<'a, ValidationResult> {
        Box::pin(async move { self.validate(context) })
    }
}

pub struct PostSignatureValidationContext<'a> {
    pub message: &'a CoseSign1<'a>,
    pub trust_decision: &'a TrustDecision,
    pub signature_metadata: &'a BTreeMap<String, String>,
    pub options: &'a CoseSign1ValidationOptions,
    pub signing_key: Option<&'a Arc<dyn SigningKey>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CoseSign1ValidationError {
    #[error("COSE decode failed: {0}")]
    CoseDecode(String),

    #[error("trust evaluation failed: {0}")]
    Trust(String),
}

/// Staged validator matching V2 ordering/semantics.
pub struct CoseSign1Validator {
    signing_key_resolvers: Vec<Arc<dyn SigningKeyResolver>>,
    post_signature_validators: Vec<Arc<dyn PostSignatureValidator>>,
    trust_plan: CompiledTrustPlan,
    trust_producers: Vec<Arc<dyn TrustFactProducer>>,
    options: CoseSign1ValidationOptions,
}

/// Input to [`CoseSign1Validator::new`].
///
/// This exists to emulate two constructor overloads:
/// - pass a bundled compiled plan
/// - or pass a list of trust packs (secure-by-default plans are OR-composed)
pub enum CoseSign1ValidatorInit {
    CompiledPlan(CoseSign1CompiledTrustPlan),
    TrustPacks(Vec<Arc<dyn CoseSign1TrustPack>>),
}

impl From<CoseSign1CompiledTrustPlan> for CoseSign1ValidatorInit {
    fn from(value: CoseSign1CompiledTrustPlan) -> Self {
        Self::CompiledPlan(value)
    }
}

impl From<Vec<Arc<dyn CoseSign1TrustPack>>> for CoseSign1ValidatorInit {
    fn from(value: Vec<Arc<dyn CoseSign1TrustPack>>) -> Self {
        Self::TrustPacks(value)
    }
}

impl CoseSign1Validator {
    const METADATA_KEY_SIGNATURE_VERIFICATION_MODE: &'static str = "SignatureVerificationMode";
    const METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED: &'static str =
        "BypassedByCounterSignature";
    const METADATA_KEY_SIGNATURE_BYPASS_DETAILS: &'static str = "SignatureBypassDetails";

    pub const VALIDATOR_NAME_OVERALL: &'static str = "Validate";

    pub const STAGE_NAME_KEY_MATERIAL_RESOLUTION: &'static str = "Key Material Resolution";
    pub const STAGE_NAME_KEY_MATERIAL_TRUST: &'static str = "Signing Key Trust";
    pub const STAGE_NAME_SIGNATURE: &'static str = "Signature";
    pub const STAGE_NAME_POST_SIGNATURE: &'static str = "Post-Signature Validation";

    pub const NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED: &'static str = "Prior stage failed";
    pub const NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED: &'static str =
        "Signing key not trusted";
    pub const NOT_APPLICABLE_REASON_SIGNATURE_VALIDATION_FAILED: &'static str =
        "Signature validation failed";

    pub const METADATA_PREFIX_RESOLUTION: &'static str = "Resolution";
    pub const METADATA_PREFIX_TRUST: &'static str = "Trust";
    pub const METADATA_PREFIX_SIGNATURE: &'static str = "Signature";
    pub const METADATA_PREFIX_POST: &'static str = "Post";
    pub const METADATA_KEY_SEPARATOR: &'static str = ".";

    pub const ERROR_CODE_TRUST_PLAN_NOT_SATISFIED: &'static str = "TRUST_PLAN_NOT_SATISFIED";
    pub const ERROR_MESSAGE_TRUST_PLAN_NOT_SATISFIED: &'static str = "Trust plan was not satisfied";

    pub const ERROR_CODE_NO_SIGNING_KEY_RESOLVED: &'static str = "NO_SIGNING_KEY_RESOLVED";
    pub const ERROR_MESSAGE_NO_SIGNING_KEY_RESOLVED: &'static str =
        "No signing key could be resolved from the message";

    pub const ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR: &'static str =
        "NO_APPLICABLE_SIGNATURE_VALIDATOR";
    pub const ERROR_MESSAGE_NO_APPLICABLE_SIGNATURE_VALIDATOR: &'static str =
        "No applicable signature validator was found for this message";

    pub const ERROR_CODE_SIGNATURE_VERIFICATION_FAILED: &'static str =
        "SIGNATURE_VERIFICATION_FAILED";
    pub const ERROR_MESSAGE_SIGNATURE_VERIFICATION_FAILED: &'static str =
        "Cryptographic signature verification failed";

    pub const ERROR_CODE_SIGNATURE_MISSING_PAYLOAD: &'static str = "SIGNATURE_MISSING_PAYLOAD";
    pub const ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD: &'static str =
        "Message has detached content but no payload was provided for verification";

    /// Threshold in bytes above which we prefer streaming Sig_structure construction.
    /// Mirrors V2's 85KB LOH-related threshold.
    pub const LARGE_STREAM_THRESHOLD: u64 = 85_000;

    pub const METADATA_KEY_SELECTED_VALIDATOR: &'static str = "SelectedValidator";

    pub fn new(init: impl Into<CoseSign1ValidatorInit>) -> Self {
        let init = init.into();

        let bundled = match init {
            CoseSign1ValidatorInit::CompiledPlan(bundled) => bundled,
            CoseSign1ValidatorInit::TrustPacks(trust_packs) => {
                // OR-compose all packs' secure-by-default plans.
                let mut default_plans = Vec::new();
                for pack in trust_packs.iter() {
                    if let Some(p) = pack.default_trust_plan() {
                        default_plans.push(p);
                    }
                }

                let trust_plan = CompiledTrustPlan::or_plans(default_plans);
                CoseSign1CompiledTrustPlan::from_parts(trust_plan, trust_packs)
                    .expect("default trust plan should be satisfiable by the provided trust packs")
            }
        };

        Self::from_bundled_plan(bundled)
    }

    /// Less-fluent construction for callers who prefer a single entrypoint.
    ///
    /// Prefer [`CoseSign1Validator::new`] + [`CoseSign1Validator::with_options`] in most cases.
    pub fn advanced(init: impl Into<CoseSign1ValidatorInit>, options: CoseSign1ValidationOptions) -> Self {
        let mut v = Self::new(init);
        v.options = options;
        v
    }

    fn from_bundled_plan(trust_plan: CoseSign1CompiledTrustPlan) -> Self {
        let (plan, trust_packs) = trust_plan.into_parts();

        let mut signing_key_resolvers: Vec<Arc<dyn SigningKeyResolver>> = Vec::new();
        let mut post_signature_validators: Vec<Arc<dyn PostSignatureValidator>> = Vec::new();

        // Always include message fact production for trust plans.
        let mut trust_producers: Vec<Arc<dyn TrustFactProducer>> = vec![Arc::new(
            crate::message_fact_producer::CoseSign1MessageFactProducer::new(),
        )];

        for pack in trust_packs {
            trust_producers.push(pack.fact_producer());
            signing_key_resolvers.extend(pack.signing_key_resolvers());
            post_signature_validators.extend(pack.post_signature_validators());
        }

        Self {
            signing_key_resolvers,
            post_signature_validators,
            trust_plan: plan,
            trust_producers,
            options: CoseSign1ValidationOptions::default(),
        }
    }

    /// Configure validator options starting from safe defaults.
    ///
    /// Callers should not need to manually initialize default values.
    pub fn with_options(mut self, configure: impl FnOnce(&mut CoseSign1ValidationOptions)) -> Self {
        configure(&mut self.options);
        self
    }

    pub fn validate_bytes(
        &self,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        let bytes = cose_sign1_bytes;
        let message = CoseSign1::from_cbor(&bytes)
            .map_err(|e| CoseSign1ValidationError::CoseDecode(e.to_string()))?;

        let parsed_message = CoseSign1ParsedMessage::from_parts(
            message.protected_header,
            message.unprotected_header.as_ref(),
            message.payload,
            message.signature,
        )
        .map_err(CoseSign1ValidationError::CoseDecode)?;

        self.validate_internal(&message, bytes.clone(), Arc::new(parsed_message))
    }

    pub async fn validate_bytes_async(
        &self,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        let bytes = cose_sign1_bytes;
        let message = CoseSign1::from_cbor(&bytes)
            .map_err(|e| CoseSign1ValidationError::CoseDecode(e.to_string()))?;

        let parsed_message = CoseSign1ParsedMessage::from_parts(
            message.protected_header,
            message.unprotected_header.as_ref(),
            message.payload,
            message.signature,
        )
        .map_err(CoseSign1ValidationError::CoseDecode)?;

        self.validate_internal_async(&message, bytes.clone(), Arc::new(parsed_message))
            .await
    }

    fn validate_internal(
        &self,
        message: &CoseSign1<'_>,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1ParsedMessage>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        // Stage 1: Key Material Resolution
        let (resolution_result, signing_key) = self.run_resolution_stage(message);

        // If signing key resolution fails, we may still be able to validate via trusted
        // counter-signatures that attest to envelope integrity.
        let attempt_signature_bypass = !resolution_result.is_valid();

        // Stage 2: Key Material Trust
        let (trust_result, trust_decision, signature_stage_metadata) = self
            .run_trust_stage(
                message,
                cose_sign1_bytes.clone(),
                cose_sign1_parsed.clone(),
                attempt_signature_bypass,
            )
            .map_err(CoseSign1ValidationError::Trust)?;

        if attempt_signature_bypass {
            // Preserve existing behavior when key resolution fails and we don't have an
            // integrity-attesting counter-signature to fall back to.
            let bypassed = signature_stage_metadata
                .get(Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE)
                .map(|v| v.as_str())
                == Some(Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED);

            if !trust_result.is_valid() || !bypassed {
                return Ok(CoseSign1ValidationResult {
                    resolution: resolution_result.clone(),
                    trust: ValidationResult::not_applicable(
                        Self::STAGE_NAME_KEY_MATERIAL_TRUST,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    signature: ValidationResult::not_applicable(
                        Self::STAGE_NAME_SIGNATURE,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    post_signature_policy: ValidationResult::not_applicable(
                        Self::STAGE_NAME_POST_SIGNATURE,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    overall: resolution_result,
                });
            }

            // Bypass primary signature verification.
            let mut resolution_metadata = BTreeMap::new();
            resolution_metadata.insert(
                Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE.to_string(),
                Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED.to_string(),
            );
            let resolution_result =
                ValidationResult::success(Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION, Some(resolution_metadata));

            let signature_result =
                ValidationResult::success(Self::STAGE_NAME_SIGNATURE, Some(signature_stage_metadata.clone()));

            let post_signature_result = self.run_post_signature_stage(
                message,
                None,
                &trust_decision,
                &signature_stage_metadata,
            );

            if !post_signature_result.is_valid() {
                return Ok(CoseSign1ValidationResult {
                    resolution: resolution_result,
                    trust: trust_result,
                    signature: signature_result,
                    post_signature_policy: post_signature_result.clone(),
                    overall: post_signature_result,
                });
            }

            // Overall: merge metadata
            let mut combined_metadata = BTreeMap::new();
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_RESOLUTION,
                &resolution_result,
            );
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_TRUST, &trust_result);
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_SIGNATURE,
                &signature_result,
            );
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_POST,
                &post_signature_result,
            );

            let overall =
                ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result,
                overall,
            });
        }

        if !trust_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result.clone(),
                signature: ValidationResult::not_applicable(
                    Self::STAGE_NAME_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED),
                ),
                post_signature_policy: ValidationResult::not_applicable(
                    Self::STAGE_NAME_POST_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED),
                ),
                overall: trust_result,
            });
        }

        // Stage 3: Signature Verification
        let signature_result =
            self.run_signature_stage(cose_sign1_parsed.as_ref(), signing_key.as_ref().unwrap());
        if !signature_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result.clone(),
                post_signature_policy: ValidationResult::not_applicable(
                    Self::STAGE_NAME_POST_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNATURE_VALIDATION_FAILED),
                ),
                overall: signature_result,
            });
        }

        // Stage 4: Post-Signature Policy
        let post_signature_result = self.run_post_signature_stage(
            message,
            signing_key.as_ref(),
            &trust_decision,
            &signature_stage_metadata,
        );

        if !post_signature_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result.clone(),
                overall: post_signature_result,
            });
        }

        // Overall: merge metadata
        let mut combined_metadata = BTreeMap::new();
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_RESOLUTION,
            &resolution_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_TRUST,
            &trust_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_SIGNATURE,
            &signature_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_POST,
            &post_signature_result,
        );

        let overall =
            ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

        Ok(CoseSign1ValidationResult {
            resolution: resolution_result,
            trust: trust_result,
            signature: signature_result,
            post_signature_policy: post_signature_result,
            overall,
        })
    }

    async fn validate_internal_async(
        &self,
        message: &CoseSign1<'_>,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1ParsedMessage>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        // Stage 1: Key Material Resolution
        let (resolution_result, signing_key) = self.run_resolution_stage_async(message).await;

        let attempt_signature_bypass = !resolution_result.is_valid();

        // Stage 2: Key Material Trust
        let (trust_result, trust_decision, signature_stage_metadata) = self
            .run_trust_stage(
                message,
                cose_sign1_bytes.clone(),
                cose_sign1_parsed.clone(),
                attempt_signature_bypass,
            )
            .map_err(CoseSign1ValidationError::Trust)?;

        if attempt_signature_bypass {
            let bypassed = signature_stage_metadata
                .get(Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE)
                .map(|v| v.as_str())
                == Some(Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED);

            if !trust_result.is_valid() || !bypassed {
                return Ok(CoseSign1ValidationResult {
                    resolution: resolution_result.clone(),
                    trust: ValidationResult::not_applicable(
                        Self::STAGE_NAME_KEY_MATERIAL_TRUST,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    signature: ValidationResult::not_applicable(
                        Self::STAGE_NAME_SIGNATURE,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    post_signature_policy: ValidationResult::not_applicable(
                        Self::STAGE_NAME_POST_SIGNATURE,
                        Some(Self::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED),
                    ),
                    overall: resolution_result,
                });
            }

            let mut resolution_metadata = BTreeMap::new();
            resolution_metadata.insert(
                Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE.to_string(),
                Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED.to_string(),
            );
            let resolution_result =
                ValidationResult::success(Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION, Some(resolution_metadata));

            let signature_result =
                ValidationResult::success(Self::STAGE_NAME_SIGNATURE, Some(signature_stage_metadata.clone()));

            let post_signature_result = self
                .run_post_signature_stage_async(
                    message,
                    None,
                    &trust_decision,
                    &signature_stage_metadata,
                )
                .await;

            if !post_signature_result.is_valid() {
                return Ok(CoseSign1ValidationResult {
                    resolution: resolution_result,
                    trust: trust_result,
                    signature: signature_result,
                    post_signature_policy: post_signature_result.clone(),
                    overall: post_signature_result,
                });
            }

            let mut combined_metadata = BTreeMap::new();
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_RESOLUTION,
                &resolution_result,
            );
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_TRUST, &trust_result);
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_SIGNATURE,
                &signature_result,
            );
            merge_stage_metadata(
                &mut combined_metadata,
                Self::METADATA_PREFIX_POST,
                &post_signature_result,
            );

            let overall =
                ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result,
                overall,
            });
        }

        if !trust_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result.clone(),
                signature: ValidationResult::not_applicable(
                    Self::STAGE_NAME_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED),
                ),
                post_signature_policy: ValidationResult::not_applicable(
                    Self::STAGE_NAME_POST_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED),
                ),
                overall: trust_result,
            });
        }

        // Stage 3: Signature Verification
        let signature_result =
            self.run_signature_stage(cose_sign1_parsed.as_ref(), signing_key.as_ref().unwrap());
        if !signature_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result.clone(),
                post_signature_policy: ValidationResult::not_applicable(
                    Self::STAGE_NAME_POST_SIGNATURE,
                    Some(Self::NOT_APPLICABLE_REASON_SIGNATURE_VALIDATION_FAILED),
                ),
                overall: signature_result,
            });
        }

        // Stage 4: Post-Signature Policy
        let post_signature_result = self
            .run_post_signature_stage_async(
                message,
                signing_key.as_ref(),
                &trust_decision,
                &signature_stage_metadata,
            )
            .await;

        if !post_signature_result.is_valid() {
            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result.clone(),
                overall: post_signature_result,
            });
        }

        // Overall: merge metadata
        let mut combined_metadata = BTreeMap::new();
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_RESOLUTION,
            &resolution_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_TRUST,
            &trust_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_SIGNATURE,
            &signature_result,
        );
        merge_stage_metadata(
            &mut combined_metadata,
            Self::METADATA_PREFIX_POST,
            &post_signature_result,
        );

        let overall =
            ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

        Ok(CoseSign1ValidationResult {
            resolution: resolution_result,
            trust: trust_result,
            signature: signature_result,
            post_signature_policy: post_signature_result,
            overall,
        })
    }

    fn run_resolution_stage(
        &self,
        message: &CoseSign1<'_>,
    ) -> (ValidationResult, Option<Arc<dyn SigningKey>>) {
        if self.signing_key_resolvers.is_empty() {
            return (
                ValidationResult::failure_message(
                    Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION,
                    Self::ERROR_MESSAGE_NO_SIGNING_KEY_RESOLVED,
                    Some(Self::ERROR_CODE_NO_SIGNING_KEY_RESOLVED),
                ),
                None,
            );
        }

        let mut diagnostics: Vec<String> = Vec::new();
        for resolver in &self.signing_key_resolvers {
            let result = resolver.resolve(message, &self.options);
            diagnostics.extend(result.diagnostics);
            if result.is_success {
                if let Some(key) = result.signing_key {
                    return (
                        ValidationResult::success(Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION, None),
                        Some(key),
                    );
                }
            }
        }

        let mut metadata = BTreeMap::new();
        if !diagnostics.is_empty() {
            metadata.insert("Diagnostics".to_string(), diagnostics.join("\n"));
        }

        (
            ValidationResult {
                kind: ValidationResultKind::Failure,
                validator_name: Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION.to_string(),
                failures: vec![ValidationFailure {
                    message: Self::ERROR_MESSAGE_NO_SIGNING_KEY_RESOLVED.to_string(),
                    error_code: Some(Self::ERROR_CODE_NO_SIGNING_KEY_RESOLVED.to_string()),
                    ..ValidationFailure::default()
                }],
                metadata,
            },
            None,
        )
    }

    async fn run_resolution_stage_async(
        &self,
        message: &CoseSign1<'_>,
    ) -> (ValidationResult, Option<Arc<dyn SigningKey>>) {
        if self.signing_key_resolvers.is_empty() {
            return (
                ValidationResult::failure_message(
                    Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION,
                    Self::ERROR_MESSAGE_NO_SIGNING_KEY_RESOLVED,
                    Some(Self::ERROR_CODE_NO_SIGNING_KEY_RESOLVED),
                ),
                None,
            );
        }

        let mut diagnostics = Vec::new();
        for r in &self.signing_key_resolvers {
            let result = r.resolve_async(message, &self.options).await;
            diagnostics.extend(result.diagnostics.clone());
            if result.is_success {
                if let Some(k) = result.signing_key {
                    return (
                        ValidationResult::success(Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION, None),
                        Some(k),
                    );
                }
            }
        }

        let mut failure = ValidationFailure {
            message: Self::ERROR_MESSAGE_NO_SIGNING_KEY_RESOLVED.to_string(),
            error_code: Some(Self::ERROR_CODE_NO_SIGNING_KEY_RESOLVED.to_string()),
            ..ValidationFailure::default()
        };
        if !diagnostics.is_empty() {
            failure.exception = Some(diagnostics.join(";"));
        }

        (
            ValidationResult::failure(Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION, vec![failure]),
            None,
        )
    }

    fn run_trust_stage(
        &self,
        _message: &CoseSign1<'_>,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1ParsedMessage>,
        attempt_signature_bypass: bool,
    ) -> Result<(ValidationResult, TrustDecision, BTreeMap<String, String>), String> {
        // Mirror V2: trust is evaluated on the Message subject (MessageId = SHA-256 of bytes).
        let message_subject = TrustSubject::message(cose_sign1_bytes.as_ref());

        let engine = TrustFactEngine::new(self.trust_producers.clone())
            .with_cose_sign1_bytes(cose_sign1_bytes)
            .with_cose_sign1_message(cose_sign1_parsed)
            .with_cose_header_location(self.options.certificate_header_location)
            .with_evaluation_options(&self.options.trust_evaluation_options);

        // For now, we evaluate on the Message subject (V2 does) and allow rules to derive signing key subjects.
        // Packs that want the signing key can use `TrustSubject::derived`.
        let (decision, audit) = self
            .trust_plan
            .evaluate_with_audit(&engine, &message_subject, &self.options.trust_evaluation_options)
            .map_err(|e| e.to_string())?;

        if !decision.is_trusted {
            let failures = if decision.reasons.is_empty() {
                vec![ValidationFailure {
                    error_code: Some(Self::ERROR_CODE_TRUST_PLAN_NOT_SATISFIED.to_string()),
                    message: Self::ERROR_MESSAGE_TRUST_PLAN_NOT_SATISFIED.to_string(),
                    ..ValidationFailure::default()
                }]
            } else {
                decision
                    .reasons
                    .iter()
                    .map(|r| ValidationFailure {
                        error_code: Some(Self::ERROR_CODE_TRUST_PLAN_NOT_SATISFIED.to_string()),
                        message: r.clone(),
                        ..ValidationFailure::default()
                    })
                    .collect()
            };

            let mut metadata = BTreeMap::new();
            if self.options.trust_evaluation_options.bypass_trust {
                metadata.insert("BypassTrust".to_string(), "true".to_string());
            }
            metadata.insert("TrustDecision".to_string(), format!("{decision:?}"));
            if let Some(a) = audit {
                metadata.insert("TrustDecisionAudit".to_string(), format!("{a:?}"));
            }

            return Ok((
                ValidationResult {
                    kind: ValidationResultKind::Failure,
                    validator_name: Self::STAGE_NAME_KEY_MATERIAL_TRUST.to_string(),
                    failures,
                    metadata,
                },
                decision,
                BTreeMap::new(),
            ));
        }

        let mut metadata = BTreeMap::new();
        if self.options.trust_evaluation_options.bypass_trust {
            metadata.insert("BypassTrust".to_string(), "true".to_string());
        }
        metadata.insert("TrustDecision".to_string(), format!("{decision:?}"));
        if let Some(a) = audit {
            metadata.insert("TrustDecisionAudit".to_string(), format!("{a:?}"));
        }

        let signature_stage_metadata = if attempt_signature_bypass {
            Self::signature_bypass_metadata_from_counter_signatures(&engine, &message_subject)
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };

        Ok((
            ValidationResult::success(Self::STAGE_NAME_KEY_MATERIAL_TRUST, Some(metadata)),
            decision,
            signature_stage_metadata,
        ))
    }

    fn signature_bypass_metadata_from_counter_signatures(
        engine: &TrustFactEngine,
        message_subject: &TrustSubject,
    ) -> Option<BTreeMap<String, String>> {
        let counter_signature_subjects = match engine
            .get_facts::<crate::message_facts::CounterSignatureSubjectFact>(message_subject)
        {
            Ok(v) => v,
            Err(_) => return None,
        };

        for cs in counter_signature_subjects {
            let integrity_facts = match engine.get_facts::<
                crate::message_facts::CounterSignatureEnvelopeIntegrityFact,
            >(&cs.subject)
            {
                Ok(v) => v,
                Err(_) => continue,
            };

            if integrity_facts.iter().any(|f| f.sig_structure_intact) {
                let mut metadata = BTreeMap::new();
                metadata.insert(
                    Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE.to_string(),
                    Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED.to_string(),
                );

                if let Some(details) = integrity_facts
                    .iter()
                    .find_map(|f| f.details.as_deref())
                    .map(str::to_string)
                {
                    metadata.insert(Self::METADATA_KEY_SIGNATURE_BYPASS_DETAILS.to_string(), details);
                }

                return Some(metadata);
            }
        }

        None
    }

    fn run_signature_stage(
        &self,
        message: &CoseSign1ParsedMessage,
        signing_key: &Arc<dyn SigningKey>,
    ) -> ValidationResult {
        // Determine embedded vs detached content.
        let detached_payload = if message.payload.is_none() {
            self.options.detached_payload.clone()
        } else {
            None
        };

        if message.payload.is_none() {
            let Some(p) = detached_payload.as_ref() else {
                return ValidationResult::failure_message(
                    Self::STAGE_NAME_SIGNATURE,
                    Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD,
                    Some(Self::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD),
                );
            };

            // If we have a provider with a known large length, prefer streaming Sig_structure.
            if let DetachedPayload::Provider(provider) = p {
                if let Some(len) = provider.len_hint() {
                    if len > Self::LARGE_STREAM_THRESHOLD {
                        let associated_data =
                            self.options.associated_data.as_deref().unwrap_or(&[]);

                        let Some(alg) = message.try_alg() else {
                            return ValidationResult::failure_message(
                                Self::STAGE_NAME_SIGNATURE,
                                Self::ERROR_MESSAGE_NO_APPLICABLE_SIGNATURE_VALIDATOR,
                                Some(Self::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR),
                            );
                        };

                        let mut sig_reader = match SigStructureReader::new_detached(
                            message.protected_header_bytes.as_ref(),
                            associated_data,
                            provider.clone(),
                            len,
                        ) {
                            Ok(r) => r,
                            Err(e) => {
                                return ValidationResult::failure_message(
                                    Self::STAGE_NAME_SIGNATURE,
                                    e,
                                    Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                                )
                            }
                        };

                        let mut metadata = BTreeMap::new();
                        metadata.insert(
                            Self::METADATA_KEY_SELECTED_VALIDATOR.to_string(),
                            signing_key.key_type().to_string(),
                        );

                        return match signing_key.verify_reader(
                            alg,
                            &mut sig_reader,
                            message.signature.as_ref(),
                        ) {
                            Ok(true) => ValidationResult::success(
                                Self::STAGE_NAME_SIGNATURE,
                                Some(metadata),
                            ),
                            Ok(false) => ValidationResult::failure_message(
                                Self::STAGE_NAME_SIGNATURE,
                                Self::ERROR_MESSAGE_SIGNATURE_VERIFICATION_FAILED,
                                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                            ),
                            Err(ex) => ValidationResult::failure_message(
                                Self::STAGE_NAME_SIGNATURE,
                                ex,
                                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                            ),
                        };
                    }
                }
            }
        }

        // Fallback: buffer payload bytes and build full Sig_structure.
        let payload_bytes: Arc<[u8]> = if let Some(embedded) = message.payload.as_ref() {
            embedded.clone()
        } else {
            let Some(p) = detached_payload.as_ref() else {
                return ValidationResult::failure_message(
                    Self::STAGE_NAME_SIGNATURE,
                    Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD,
                    Some(Self::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD),
                );
            };
            match self.read_detached_payload_bytes(p) {
                Ok(v) => v,
                Err(err) => {
                    return ValidationResult::failure_message(
                        Self::STAGE_NAME_SIGNATURE,
                        err,
                        Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                    )
                }
            }
        };

        let associated_data = self.options.associated_data.as_deref().unwrap_or(&[]);

        let Some(alg) = message.try_alg() else {
            return ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                Self::ERROR_MESSAGE_NO_APPLICABLE_SIGNATURE_VALIDATOR,
                Some(Self::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR),
            );
        };

        let sig_structure = match build_sig_structure(
            message.protected_header_bytes.as_ref(),
            associated_data,
            &payload_bytes,
        ) {
            Ok(v) => v,
            Err(e) => {
                return ValidationResult::failure_message(
                    Self::STAGE_NAME_SIGNATURE,
                    e,
                    Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                )
            }
        };

        let mut metadata = BTreeMap::new();
        metadata.insert(
            Self::METADATA_KEY_SELECTED_VALIDATOR.to_string(),
            signing_key.key_type().to_string(),
        );

        match signing_key.verify(alg, &sig_structure, message.signature.as_ref()) {
            Ok(true) => ValidationResult::success(Self::STAGE_NAME_SIGNATURE, Some(metadata)),
            Ok(false) => ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                Self::ERROR_MESSAGE_SIGNATURE_VERIFICATION_FAILED,
                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
            ),
            Err(ex) => ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                ex,
                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
            ),
        }
    }

    fn run_post_signature_stage(
        &self,
        message: &CoseSign1<'_>,
        signing_key: Option<&Arc<dyn SigningKey>>,
        trust_decision: &TrustDecision,
        signature_metadata: &BTreeMap<String, String>,
    ) -> ValidationResult {
        if self.options.skip_post_signature_validation {
            return ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None);
        }

        if self.post_signature_validators.is_empty() {
            return ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None);
        }

        let context = PostSignatureValidationContext {
            message,
            trust_decision,
            signature_metadata,
            options: &self.options,
            signing_key,
        };

        let mut failures = Vec::new();
        for v in &self.post_signature_validators {
            let r = v.validate(&context);
            if r.is_failure() {
                failures.extend(r.failures);
            }
        }

        if failures.is_empty() {
            ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None)
        } else {
            ValidationResult::failure(Self::STAGE_NAME_POST_SIGNATURE, failures)
        }
    }

    async fn run_post_signature_stage_async(
        &self,
        message: &CoseSign1<'_>,
        signing_key: Option<&Arc<dyn SigningKey>>,
        trust_decision: &TrustDecision,
        signature_metadata: &BTreeMap<String, String>,
    ) -> ValidationResult {
        if self.options.skip_post_signature_validation {
            return ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None);
        }

        if self.post_signature_validators.is_empty() {
            return ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None);
        }

        let context = PostSignatureValidationContext {
            message,
            trust_decision,
            signature_metadata,
            options: &self.options,
            signing_key,
        };

        let mut failures = Vec::new();
        for v in &self.post_signature_validators {
            let r = v.validate_async(&context).await;
            if r.is_failure() {
                failures.extend(r.failures);
            }
        }

        if failures.is_empty() {
            ValidationResult::success(Self::STAGE_NAME_POST_SIGNATURE, None)
        } else {
            ValidationResult::failure(Self::STAGE_NAME_POST_SIGNATURE, failures)
        }
    }

    fn read_detached_payload_bytes(&self, payload: &DetachedPayload) -> Result<Arc<[u8]>, String> {
        match payload {
            DetachedPayload::Bytes(b) => {
                if b.is_empty() {
                    return Err(Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD.to_string());
                }
                Ok(b.clone())
            }
            DetachedPayload::Provider(p) => {
                let mut reader = p.open()?;
                let mut buf = Vec::new();
                reader
                    .read_to_end(&mut buf)
                    .map_err(|e| format!("detached_payload_read_failed: {e}"))?;
                if buf.is_empty() {
                    return Err(Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD.to_string());
                }
                Ok(Arc::from(buf.into_boxed_slice()))
            }
        }
    }
}

struct SigStructureReader {
    prefix: std::io::Cursor<Vec<u8>>,
    payload: Box<dyn Read + Send>,
    done: bool,
}

impl SigStructureReader {
    fn new_detached(
        protected: &[u8],
        external_aad: &[u8],
        provider: Arc<dyn DetachedPayloadProvider>,
        payload_len: u64,
    ) -> Result<Self, String> {
        let payload = provider.open()?;
        let prefix = build_sig_structure_prefix(protected, external_aad, payload_len)?;
        Ok(Self {
            prefix: std::io::Cursor::new(prefix),
            payload,
            done: false,
        })
    }
}

impl Read for SigStructureReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }

        // Drain prefix first.
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let n = self.prefix.read(buf)?;
            if n > 0 {
                return Ok(n);
            }
        }

        // Then stream payload bytes.
        let n = self.payload.read(buf)?;
        if n == 0 {
            self.done = true;
        }
        Ok(n)
    }
}

fn build_sig_structure_prefix(
    protected: &[u8],
    external_aad: &[u8],
    payload_len: u64,
) -> Result<Vec<u8>, String> {
    // Sig_structure = ["Signature1", body_protected, external_aad, payload]
    // Encode first 3 items and the payload bstr header, then stream raw payload bytes.
    let mut buf = vec![0u8; protected.len() + external_aad.len() + 128];
    let buf_len = buf.len();
    let mut enc = Encoder(buf.as_mut_slice());

    enc.array(4)
        .map_err(|e| format!("sig_structure_encode_failed: {e}"))?;
    "Signature1"
        .encode(&mut enc)
        .map_err(|e| format!("sig_structure_encode_failed: {e}"))?;
    protected
        .encode(&mut enc)
        .map_err(|e| format!("sig_structure_encode_failed: {e}"))?;
    external_aad
        .encode(&mut enc)
        .map_err(|e| format!("sig_structure_encode_failed: {e}"))?;

    let used = buf_len - enc.0.len();
    buf.truncate(used);

    // Append CBOR bstr header for payload.
    buf.extend_from_slice(&encode_cbor_bstr_len(payload_len));
    Ok(buf)
}

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

pub type CoseSign1MessageValidator = CoseSign1Validator;

fn merge_stage_metadata(
    combined: &mut BTreeMap<String, String>,
    prefix: &'static str,
    stage: &ValidationResult,
) {
    for (k, v) in &stage.metadata {
        combined.insert(
            format!(
                "{prefix}{}{}",
                CoseSign1Validator::METADATA_KEY_SEPARATOR,
                k
            ),
            v.clone(),
        );
    }
}

fn build_sig_structure(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    // Sig_structure = ["Signature1", body_protected, external_aad, payload]
    // where `body_protected` is the serialized protected header map (as bstr).
    //
    // Use the same prefix + bstr-length encoding as the streaming implementation,
    // then append raw payload bytes.
    let mut out = build_sig_structure_prefix(protected, external_aad, payload.len() as u64)?;
    out.extend_from_slice(payload);
    Ok(out)
}
