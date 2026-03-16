// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Core validator pipeline implementation.
//!
//! The validator runs a staged pipeline:
//! 1) resolve signing key material from the COSE message
//! 2) evaluate trust policy over the message (and derived subjects)
//! 3) verify the cryptographic signature (embedded or detached payload)
//! 4) run any post-signature validators contributed by trust packs
//!
//! Most callers should use `cose_sign1_validation::fluent` to build and run a validator.

use tracing::{debug, info, error};

use crate::trust_packs::CoseSign1TrustPack;
use crate::trust_plan_builder::CoseSign1CompiledTrustPlan;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::{
    CoseHeaderLocation, CoseSign1Message, TrustDecision, TrustEvaluationOptions,
};
use cose_sign1_primitives::payload::{Payload, StreamingPayload};
use cose_sign1_primitives::{build_sig_structure, build_sig_structure_prefix};
use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome classification for a single validation stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResultKind {
    /// Stage ran and succeeded.
    Success,
    /// Stage ran and failed.
    Failure,
    /// Stage did not run because it was not applicable (usually due to a prior stage).
    NotApplicable,
}

impl Default for ValidationResultKind {
    /// Default stage outcome.
    ///
    /// Defaults to [`ValidationResultKind::NotApplicable`] to mirror the pipeline behavior where
    /// later stages may not run depending on earlier outcomes.
    fn default() -> Self {
        Self::NotApplicable
    }
}

/// A single validation failure, optionally annotated with an error code and details.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationFailure {
    /// Human-readable failure message.
    pub message: String,
    /// Optional stable error code for programmatic handling.
    pub error_code: Option<String>,
    /// Optional property/field name associated with the failure.
    pub property_name: Option<String>,
    /// Optional attempted value (as string) associated with the failure.
    pub attempted_value: Option<String>,
    /// Optional exception/debug details.
    pub exception: Option<String>,
}

/// Result for a single validation stage.
///
/// Stages may attach structured `metadata` to aid troubleshooting and auditing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationResult {
    /// Stage outcome.
    pub kind: ValidationResultKind,
    /// Friendly stage name (e.g. "Signature").
    pub validator_name: String,
    /// Failures when `kind == Failure`.
    pub failures: Vec<ValidationFailure>,
    /// Arbitrary stage metadata.
    pub metadata: BTreeMap<String, String>,
}

impl ValidationResult {
    pub const METADATA_REASON_KEY: &'static str = "Reason";

    /// Returns true when this stage succeeded.
    pub fn is_valid(&self) -> bool {
        matches!(self.kind, ValidationResultKind::Success)
    }

    /// Returns true when this stage failed.
    pub fn is_failure(&self) -> bool {
        matches!(self.kind, ValidationResultKind::Failure)
    }

    /// Create a successful stage result.
    ///
    /// If `metadata` is `None`, the metadata map is empty.
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

    /// Create a not-applicable stage result.
    ///
    /// If `reason` is `Some` and non-empty, it is stored under [`Self::METADATA_REASON_KEY`].
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

    /// Create a failed stage result.
    pub fn failure(validator_name: impl Into<String>, failures: Vec<ValidationFailure>) -> Self {
        Self {
            kind: ValidationResultKind::Failure,
            validator_name: validator_name.into(),
            failures,
            metadata: BTreeMap::new(),
        }
    }

    /// Convenience helper for a single failure message.
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

/// Full validator output, including each stage result and an overall roll-up.
///
/// The `overall` result mirrors the final outcome of the pipeline, and may include merged
/// metadata from the component stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseSign1ValidationResult {
    pub resolution: ValidationResult,
    pub trust: ValidationResult,
    pub signature: ValidationResult,
    pub post_signature_policy: ValidationResult,
    pub overall: ValidationResult,
}

/// Options controlling how COSE_Sign1 validation is performed.
///
/// Defaults are chosen to be safe; most callers should start with the fluent API and tweak only
/// what they need (e.g. detached payload or trust evaluation options).
#[derive(Debug, Default)]
pub struct CoseSign1ValidationOptions {
    /// Detached payload (when the COSE message has a `nil` payload).
    pub detached_payload: Option<Payload>,
    /// Optional external AAD used in `Sig_structure`.
    pub associated_data: Option<Arc<[u8]>>,
    /// Which header location to consult for certificate-related headers.
    pub certificate_header_location: CoseHeaderLocation,
    /// If true, skip post-signature validation.
    pub skip_post_signature_validation: bool,
    /// Trust evaluation controls (timeouts, bypass for experiments, etc.).
    pub trust_evaluation_options: TrustEvaluationOptions,
}

/// Result of attempting to resolve a signing key from a message.
///
/// Resolution is separate from trust: a key may be resolved but later rejected by the trust plan.
#[derive(Clone, Default)]
pub struct CoseKeyResolutionResult {
    /// True when the resolver produced a usable key.
    pub is_success: bool,
    /// The selected COSE key (if successful).
    pub cose_key: Option<Arc<dyn crypto_primitives::CryptoVerifier>>,
    /// Optional additional candidate keys (for diagnostics / future selection).
    pub candidate_keys: Vec<Arc<dyn crypto_primitives::CryptoVerifier>>,
    /// Optional key identifier as raw bytes.
    pub key_id: Option<Arc<[u8]>>,
    /// Optional certificate thumbprint / key thumbprint.
    pub thumbprint: Option<Arc<[u8]>>,
    /// Human-readable diagnostics from resolution attempts.
    pub diagnostics: Vec<String>,
    /// Optional stable error code.
    pub error_code: Option<String>,
    /// Optional human-readable error message.
    pub error_message: Option<String>,
}

impl CoseKeyResolutionResult {
    /// Successful resolution with a concrete COSE key.
    pub fn success(cose_key: Arc<dyn crypto_primitives::CryptoVerifier>) -> Self {
        Self {
            is_success: true,
            cose_key: Some(cose_key),
            ..Self::default()
        }
    }

    /// Failed resolution with optional diagnostic fields.
    pub fn failure(error_code: Option<String>, error_message: Option<String>) -> Self {
        Self {
            is_success: false,
            error_code,
            error_message,
            ..Self::default()
        }
    }
}

/// Resolves a COSE key from a COSE_Sign1 message.
///
/// Implementations are typically contributed by trust packs (e.g. X.509, transparent signing).
pub trait CoseKeyResolver: Send + Sync {
    /// Synchronously resolve a COSE key.
    fn resolve(
        &self,
        message: &CoseSign1Message,
        options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult;

    /// Asynchronously resolve a COSE key.
    ///
    /// Default implementation delegates to the synchronous path.
    fn resolve_async<'a>(
        &'a self,
        message: &'a CoseSign1Message,
        options: &'a CoseSign1ValidationOptions,
    ) -> BoxFuture<'a, CoseKeyResolutionResult> {
        Box::pin(async move { self.resolve(message, options) })
    }
}

/// A resolved counter-signature associated with a COSE_Sign1 message.
///
/// Counter-signatures can be used as additional integrity/trust signals (e.g. to attest to
/// envelope integrity when the primary signing key cannot be resolved).
pub trait CounterSignature: Send + Sync {
    /// Raw encoded counter-signature bytes.
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]>;

    /// Whether the counter signature was found in the protected header.
    fn is_protected_header(&self) -> bool;

    /// COSE key material for the counter signature.
    fn cose_key(&self) -> Arc<dyn crypto_primitives::CryptoVerifier>;
}

/// Result of attempting to discover and resolve counter-signatures.
#[derive(Clone, Default)]
pub struct CounterSignatureResolutionResult {
    /// True when discovery succeeded.
    pub is_success: bool,
    /// Resolved counter-signatures.
    pub counter_signatures: Vec<Arc<dyn CounterSignature>>,
    /// Human-readable diagnostics.
    pub diagnostics: Vec<String>,
    /// Optional stable error code.
    pub error_code: Option<String>,
    /// Optional human-readable error message.
    pub error_message: Option<String>,
}

impl CounterSignatureResolutionResult {
    /// Successful counter-signature discovery.
    pub fn success(counter_signatures: Vec<Arc<dyn CounterSignature>>) -> Self {
        Self {
            is_success: true,
            counter_signatures,
            ..Self::default()
        }
    }

    /// Failed counter-signature discovery.
    pub fn failure(error_code: Option<String>, error_message: Option<String>) -> Self {
        Self {
            is_success: false,
            error_code,
            error_message,
            ..Self::default()
        }
    }
}

/// Discovers counter-signatures from a parsed COSE message.
///
/// Implementations are typically contributed by trust packs.
pub trait CounterSignatureResolver: Send + Sync {
    /// Stable resolver name.
    fn name(&self) -> &'static str;

    /// Discover counter-signatures from the message.
    fn resolve(
        &self,
        message: &CoseSign1Message,
    ) -> CounterSignatureResolutionResult;

    /// Asynchronously discover counter-signatures from the message.
    ///
    /// Default implementation delegates to the synchronous path.
    fn resolve_async<'a>(
        &'a self,
        message: &'a CoseSign1Message,
    ) -> BoxFuture<'a, CounterSignatureResolutionResult> {
        Box::pin(async move { self.resolve(message) })
    }
}

/// Runs additional checks after a signature has been verified (or bypassed).
///
/// Post-signature validators may enforce policies that require a verified signature, trust
/// decisions, or signature metadata.
pub trait PostSignatureValidator: Send + Sync {
    /// Validate synchronously.
    fn validate(&self, context: &PostSignatureValidationContext<'_>) -> ValidationResult;

    /// Validate asynchronously.
    ///
    /// Default implementation delegates to the synchronous path.
    fn validate_async<'a>(
        &'a self,
        context: &'a PostSignatureValidationContext<'a>,
    ) -> BoxFuture<'a, ValidationResult> {
        Box::pin(async move { self.validate(context) })
    }
}

/// Inputs to a post-signature validation step.
pub struct PostSignatureValidationContext<'a> {
    /// The parsed COSE_Sign1 message from primitives.
    pub message: &'a CoseSign1Message,
    /// Final trust decision from the trust plan.
    pub trust_decision: &'a TrustDecision,
    /// Metadata produced by the signature stage (e.g. selected validator, bypass details).
    pub signature_metadata: &'a BTreeMap<String, String>,
    /// Validator options.
    pub options: &'a CoseSign1ValidationOptions,
    /// Resolved COSE key, when available.
    pub cose_key: Option<&'a Arc<dyn crypto_primitives::CryptoVerifier>>,
}

/// Top-level validation errors (as opposed to per-stage failures).
///
/// Stage failures are represented by [`ValidationResult`] within [`CoseSign1ValidationResult`].
#[derive(Debug)]
pub enum CoseSign1ValidationError {
    CoseDecode(String),
    Trust(String),
}

impl std::fmt::Display for CoseSign1ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CoseDecode(s) => write!(f, "COSE decode failed: {}", s),
            Self::Trust(s) => write!(f, "trust evaluation failed: {}", s),
        }
    }
}

impl std::error::Error for CoseSign1ValidationError {}

/// Staged validator matching V2 ordering/semantics.
///
/// This type is intentionally explicit about its stages and outputs to aid diagnostics.
pub struct CoseSign1Validator {
    cose_key_resolvers: Vec<Arc<dyn CoseKeyResolver>>,
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
    /// Wrap a bundled compiled plan as a validator init input.
    fn from(value: CoseSign1CompiledTrustPlan) -> Self {
        Self::CompiledPlan(value)
    }
}

impl From<Vec<Arc<dyn CoseSign1TrustPack>>> for CoseSign1ValidatorInit {
    /// Wrap trust packs as a validator init input.
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

    pub const ERROR_CODE_ALGORITHM_MISMATCH: &'static str = "ALGORITHM_MISMATCH";
    pub const ERROR_MESSAGE_ALGORITHM_MISMATCH: &'static str =
        "Key algorithm does not match message algorithm";

    /// Threshold in bytes above which we prefer streaming Sig_structure construction.
    /// Mirrors V2's 85KB LOH-related threshold.
    pub const LARGE_STREAM_THRESHOLD: u64 = 85_000;

    pub const METADATA_KEY_SELECTED_VALIDATOR: &'static str = "SelectedValidator";

    /// Create a new validator from either a bundled plan or a set of trust packs.
    ///
    /// When initialized from packs, the validator OR-composes all `default_trust_plan()` values
    /// into a single secure-by-default plan.
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
    pub fn advanced(
        init: impl Into<CoseSign1ValidatorInit>,
        options: CoseSign1ValidationOptions,
    ) -> Self {
        let mut v = Self::new(init);
        v.options = options;
        v
    }

    /// Build the validator's producer/resolver/validator lists from a bundled plan.
    fn from_bundled_plan(trust_plan: CoseSign1CompiledTrustPlan) -> Self {
        let (plan, trust_packs) = trust_plan.into_parts();

        let mut cose_key_resolvers: Vec<Arc<dyn CoseKeyResolver>> = Vec::new();
        let mut post_signature_validators: Vec<Arc<dyn PostSignatureValidator>> =
            vec![Arc::new(crate::indirect_signature::IndirectSignaturePostSignatureValidator)];

        // Always include message fact production for trust plans.
        let mut trust_producers: Vec<Arc<dyn TrustFactProducer>> = vec![Arc::new(
            crate::message_fact_producer::CoseSign1MessageFactProducer::new(),
        )];

        for pack in trust_packs {
            trust_producers.push(pack.fact_producer());
            cose_key_resolvers.extend(pack.cose_key_resolvers());
            post_signature_validators.extend(pack.post_signature_validators());
        }

        Self {
            cose_key_resolvers,
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

    /// Validate an already-parsed COSE_Sign1 message.
    ///
    /// This is the primary entrypoint - callers parse the message and pass it here.
    /// The message's internal CBOR provider is used for any further decoding.
    ///
    /// # Arguments
    ///
    /// * `message` - The parsed COSE_Sign1 message
    /// * `cose_sign1_bytes` - The original raw bytes (needed for trust fact production)
    pub fn validate(
        &self,
        message: &CoseSign1Message,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        self.validate_internal(cose_sign1_bytes, Arc::new(message.clone()))
    }

    /// Async variant of [`Self::validate`].
    pub async fn validate_async(
        &self,
        message: &CoseSign1Message,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        self.validate_internal_async(cose_sign1_bytes, Arc::new(message.clone()))
            .await
    }

    /// Validate a COSE_Sign1 message from raw CBOR bytes.
    ///
    /// Convenience method that parses the message using the provided CBOR provider,
    /// then validates it.
    ///
    /// # Arguments
    ///
    /// * `provider` - CBOR provider for parsing the message
    /// * `cose_sign1_bytes` - The raw CBOR bytes to parse and validate
    pub fn validate_bytes<P: cbor_primitives::CborProvider>(
        &self,
        _provider: P,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        info!(stage = "validate", payload_len = cose_sign1_bytes.len(), "Starting COSE_Sign1 validation");
        
        let parsed_message = CoseSign1Message::parse(&cose_sign1_bytes)
            .map_err(|e| {
                error!(stage = "parse", error = %e, "Failed to parse COSE_Sign1 message");
                CoseSign1ValidationError::CoseDecode(e.to_string())
            })?;

        debug!(stage = "parse", algorithm = ?parsed_message.alg(), is_detached = parsed_message.is_detached(), "Message parsed");

        self.validate_internal(cose_sign1_bytes, Arc::new(parsed_message))
    }

    /// Async variant of [`Self::validate_bytes`].
    pub async fn validate_bytes_async<P: cbor_primitives::CborProvider>(
        &self,
        _provider: P,
        cose_sign1_bytes: Arc<[u8]>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        info!(stage = "validate", payload_len = cose_sign1_bytes.len(), "Starting COSE_Sign1 validation");
        
        let parsed_message = CoseSign1Message::parse(&cose_sign1_bytes)
            .map_err(|e| {
                error!(stage = "parse", error = %e, "Failed to parse COSE_Sign1 message");
                CoseSign1ValidationError::CoseDecode(e.to_string())
            })?;

        debug!(stage = "parse", algorithm = ?parsed_message.alg(), is_detached = parsed_message.is_detached(), "Message parsed");

        self.validate_internal_async(cose_sign1_bytes, Arc::new(parsed_message))
            .await
    }

    /// Internal synchronous pipeline entrypoint.
    ///
    /// Callers provide:
    /// - the owned raw bytes + parsed message used for trust fact production.
    fn validate_internal(
        &self,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1Message>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        // Stage 1: Key Material Resolution
        let (resolution_result, cose_key) = self.run_resolution_stage(&cose_sign1_parsed);
        info!(stage = "key_resolution", resolved = resolution_result.is_valid(), "Key resolution complete");

        // If signing key resolution fails, we may still be able to validate via trusted
        // counter-signatures that attest to envelope integrity.
        // We also attempt bypass when resolution succeeds, because trust may have been
        // achieved via counter-signatures (e.g. MST receipts in an OR plan) rather than
        // via the primary signing key path.
        let attempt_signature_bypass_on_resolution_failure = !resolution_result.is_valid();

        // Stage 2: Key Material Trust
        let (trust_result, trust_decision, signature_stage_metadata) = self
            .run_trust_stage(
                cose_sign1_bytes.clone(),
                cose_sign1_parsed.clone(),
                // Always attempt to check for counter-sig bypass, not just on resolution failure.
                // This enables OR-composed trust plans where trust may come from counter-sigs
                // (e.g. MST receipts) even when the primary key was resolved.
                true,
            )
            .map_err(CoseSign1ValidationError::Trust)?;
        info!(stage = "trust_evaluation", is_trusted = trust_decision.is_trusted, "Trust evaluation complete");

        // Check if counter-signatures provide integrity attestation (signature bypass).
        // This is true when trust was achieved via counter-signatures rather than primary key.
        let counter_sig_bypassed = signature_stage_metadata
            .get(Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE)
            .map(|v| v.as_str())
            == Some(Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED);

        if attempt_signature_bypass_on_resolution_failure {
            // Preserve existing behavior when key resolution fails and we don't have an
            // integrity-attesting counter-signature to fall back to.
            if !trust_result.is_valid() || !counter_sig_bypassed {
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
            let resolution_result = ValidationResult::success(
                Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION,
                Some(resolution_metadata),
            );

            let signature_result = ValidationResult::success(
                Self::STAGE_NAME_SIGNATURE,
                Some(signature_stage_metadata.clone()),
            );

            let post_signature_result = self.run_post_signature_stage(
                &cose_sign1_parsed,
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


        // When counter-signatures provide integrity attestation (e.g. MST receipt verified
        // the Sig_structure through the OR path in the trust plan), bypass primary signature
        // verification. The counter-sig has already attested that the envelope is intact.
        if counter_sig_bypassed {
            let signature_result = ValidationResult::success(
                Self::STAGE_NAME_SIGNATURE,
                Some(signature_stage_metadata.clone()),
            );

            let post_signature_result = self.run_post_signature_stage(
                &cose_sign1_parsed,
                cose_key.as_ref(),
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

            let mut combined_metadata = BTreeMap::new();
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_RESOLUTION, &resolution_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_TRUST, &trust_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_SIGNATURE, &signature_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_POST, &post_signature_result);

            let overall = ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result,
                overall,
            });
        }

        // Standard path: verify primary signature with the resolved key.
        // Stage 3: Signature Verification
        let cose_key = cose_key
            .as_ref()
            .expect("cose_key must be present when key resolution succeeded");

        let signature_result = self.run_signature_stage(cose_sign1_parsed.as_ref(), cose_key);
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
            &cose_sign1_parsed,
            Some(cose_key),
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

    /// Internal async pipeline entrypoint.
    ///
    /// Mirrors [`Self::validate_internal`], but uses async resolvers/validators.
    async fn validate_internal_async(
        &self,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1Message>,
    ) -> Result<CoseSign1ValidationResult, CoseSign1ValidationError> {
        // Stage 1: Key Material Resolution
        let (resolution_result, cose_key) = self.run_resolution_stage_async(&cose_sign1_parsed).await;

        let attempt_signature_bypass_on_resolution_failure = !resolution_result.is_valid();

        // Stage 2: Key Material Trust
        let (trust_result, trust_decision, signature_stage_metadata) = self
            .run_trust_stage(
                cose_sign1_bytes.clone(),
                cose_sign1_parsed.clone(),
                true, // Always check for counter-sig bypass (OR-composed trust plans)
            )
            .map_err(CoseSign1ValidationError::Trust)?;

        let counter_sig_bypassed = signature_stage_metadata
            .get(Self::METADATA_KEY_SIGNATURE_VERIFICATION_MODE)
            .map(|v| v.as_str())
            == Some(Self::METADATA_VALUE_SIGNATURE_VERIFICATION_BYPASSED);

        if attempt_signature_bypass_on_resolution_failure {
            if !trust_result.is_valid() || !counter_sig_bypassed {
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
            let resolution_result = ValidationResult::success(
                Self::STAGE_NAME_KEY_MATERIAL_RESOLUTION,
                Some(resolution_metadata),
            );

            let signature_result = ValidationResult::success(
                Self::STAGE_NAME_SIGNATURE,
                Some(signature_stage_metadata.clone()),
            );

            let post_signature_result = self
                .run_post_signature_stage_async(
                    &cose_sign1_parsed,
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


        // When counter-signatures provide integrity attestation (e.g. MST receipt verified
        // the Sig_structure through the OR path in the trust plan), bypass primary signature
        // verification. The counter-sig has already attested that the envelope is intact.
        if counter_sig_bypassed {
            let signature_result = ValidationResult::success(
                Self::STAGE_NAME_SIGNATURE,
                Some(signature_stage_metadata.clone()),
            );

            let post_signature_result = self.run_post_signature_stage(
                &cose_sign1_parsed,
                cose_key.as_ref(),
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

            let mut combined_metadata = BTreeMap::new();
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_RESOLUTION, &resolution_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_TRUST, &trust_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_SIGNATURE, &signature_result);
            merge_stage_metadata(&mut combined_metadata, Self::METADATA_PREFIX_POST, &post_signature_result);

            let overall = ValidationResult::success(Self::VALIDATOR_NAME_OVERALL, Some(combined_metadata));

            return Ok(CoseSign1ValidationResult {
                resolution: resolution_result,
                trust: trust_result,
                signature: signature_result,
                post_signature_policy: post_signature_result,
                overall,
            });
        }

        // Standard path: verify primary signature with the resolved key.
        // Stage 3: Signature Verification
        let cose_key = cose_key
            .as_ref()
            .expect("cose_key must be present when key resolution succeeded");

        let signature_result = self.run_signature_stage(cose_sign1_parsed.as_ref(), cose_key);
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
                &cose_sign1_parsed,
                Some(cose_key),
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

    /// Run stage 1: attempt to resolve a COSE key for the message.
    ///
    /// Returns both the stage `ValidationResult` and an optional COSE key.
    /// A `Success` result implies a usable key was found.
    fn run_resolution_stage(
        &self,
        message: &CoseSign1Message,
    ) -> (ValidationResult, Option<Arc<dyn crypto_primitives::CryptoVerifier>>) {
        if self.cose_key_resolvers.is_empty() {
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
        for resolver in &self.cose_key_resolvers {
            let result = resolver.resolve(message, &self.options);
            diagnostics.extend(result.diagnostics);
            if result.is_success {
                if let Some(key) = result.cose_key {
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

    /// Async variant of [`Self::run_resolution_stage`].
    async fn run_resolution_stage_async(
        &self,
        message: &CoseSign1Message,
    ) -> (ValidationResult, Option<Arc<dyn crypto_primitives::CryptoVerifier>>) {
        if self.cose_key_resolvers.is_empty() {
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
        for r in &self.cose_key_resolvers {
            let result = r.resolve_async(message, &self.options).await;
            diagnostics.extend(result.diagnostics.clone());
            if result.is_success {
                if let Some(k) = result.cose_key {
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

    /// Run stage 2: evaluate the compiled trust plan.
    ///
    /// This stage determines whether signature verification should proceed. It also optionally
    /// emits signature-bypass metadata when resolution failed but counter-signatures can attest
    /// envelope integrity.
    fn run_trust_stage(
        &self,
        cose_sign1_bytes: Arc<[u8]>,
        cose_sign1_parsed: Arc<CoseSign1Message>,
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
            .evaluate_with_audit(
                &engine,
                &message_subject,
                &self.options.trust_evaluation_options,
            )
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

    /// Derive signature-stage metadata that indicates primary signature verification can be bypassed.
    ///
    /// This is used when signing-key resolution fails but one or more trusted counter-signatures
    /// indicate that the Sig_structure is intact (envelope integrity attestation).
    fn signature_bypass_metadata_from_counter_signatures(
        engine: &TrustFactEngine,
        message_subject: &TrustSubject,
    ) -> Option<BTreeMap<String, String>> {
        let counter_signature_subjects = match engine
            .get_facts::<crate::message_facts::CounterSignatureSubjectFact>(
            message_subject,
        ) {
            Ok(v) => v,
            Err(_) => return None,
        };

        for cs in counter_signature_subjects {
            let integrity_facts = match engine
                .get_facts::<crate::message_facts::CounterSignatureEnvelopeIntegrityFact>(
                &cs.subject,
            ) {
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
                    metadata.insert(
                        Self::METADATA_KEY_SIGNATURE_BYPASS_DETAILS.to_string(),
                        details,
                    );
                }

                return Some(metadata);
            }
        }

        None
    }

    /// Run stage 3: verify the COSE_Sign1 signature.
    ///
    /// This selects between:
    /// - a streaming Sig_structure path for large detached payloads, and
    /// - a buffered path that builds the full Sig_structure in memory.
    fn run_signature_stage(
        &self,
        message: &CoseSign1Message,
        cose_key: &Arc<dyn crypto_primitives::CryptoVerifier>,
    ) -> ValidationResult {
        // RFC 9052: The algorithm in the message MUST match the key's algorithm.
        // If the key reports a non-zero algorithm, it must match the message's algorithm.
        let msg_alg = message.alg();
        let key_alg = cose_key.algorithm();
        if key_alg != 0 {
            if let Some(alg) = msg_alg {
                if key_alg != alg {
                    return ValidationResult::failure_message(
                        Self::STAGE_NAME_SIGNATURE,
                        format!(
                            "{}: key algorithm {} != message algorithm {}",
                            Self::ERROR_MESSAGE_ALGORITHM_MISMATCH,
                            key_alg,
                            alg
                        ),
                        Some(Self::ERROR_CODE_ALGORITHM_MISMATCH),
                    );
                }
            }
        }

        // Determine embedded vs detached content.
        let detached_payload = if message.payload.is_none() {
            self.options.detached_payload.as_ref()
        } else {
            None
        };

        if message.payload.is_none() {
            let Some(p) = detached_payload else {
                return ValidationResult::failure_message(
                    Self::STAGE_NAME_SIGNATURE,
                    Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD,
                    Some(Self::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD),
                );
            };

            // If we have a streaming payload with a large size, prefer streaming Sig_structure.
            if let Payload::Streaming(streaming) = p {
                let len = streaming.size();
                if len > Self::LARGE_STREAM_THRESHOLD {
                    let associated_data =
                        self.options.associated_data.as_deref().unwrap_or(&[]);

                    let Some(_alg) = message.alg() else {
                        return ValidationResult::failure_message(
                            Self::STAGE_NAME_SIGNATURE,
                            Self::ERROR_MESSAGE_NO_APPLICABLE_SIGNATURE_VALIDATOR,
                            Some(Self::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR),
                        );
                    };

                    let mut sig_reader = match SigStructureReader::new_detached(
                        message.protected.as_bytes(),
                        associated_data,
                        streaming.as_ref(),
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
                        "streaming".to_string(),
                    );

                    // Use streaming verification via VerifyingContext
                    let mut verifying_ctx = match cose_key.verify_init(message.signature.as_ref()) {
                        Ok(ctx) => ctx,
                        Err(e) => {
                            return ValidationResult::failure_message(
                                Self::STAGE_NAME_SIGNATURE,
                                format!("Failed to initialize verifying context: {}", e),
                                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                            )
                        }
                    };

                    // Feed the sig_structure through the verifying context
                    let mut buffer = vec![0u8; 8192];
                    loop {
                        let n = match sig_reader.read(&mut buffer) {
                            Ok(n) => n,
                            Err(e) => {
                                return ValidationResult::failure_message(
                                    Self::STAGE_NAME_SIGNATURE,
                                    format!("Failed to read sig_structure: {}", e),
                                    Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                                )
                            }
                        };
                        if n == 0 {
                            break;
                        }
                        if let Err(e) = verifying_ctx.update(&buffer[..n]) {
                            return ValidationResult::failure_message(
                                Self::STAGE_NAME_SIGNATURE,
                                format!("Failed to update verifying context: {}", e),
                                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                            );
                        }
                    }

                    return match verifying_ctx.finalize() {
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
                            ex.to_string(),
                            Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
                        ),
                    };
                }
            }
        }

        // Fallback: buffer payload bytes and build full Sig_structure.
        let payload_bytes: Arc<[u8]> = if let Some(embedded) = message.payload.as_ref() {
            Arc::from(embedded.as_slice())
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

        let Some(_alg) = message.alg() else {
            return ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                Self::ERROR_MESSAGE_NO_APPLICABLE_SIGNATURE_VALIDATOR,
                Some(Self::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR),
            );
        };

        let sig_structure = match build_local_sig_structure(
            message.protected.as_bytes(),
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
            "non-streaming".to_string(),
        );

        match cose_key.verify(&sig_structure, message.signature.as_ref()) {
            Ok(true) => ValidationResult::success(Self::STAGE_NAME_SIGNATURE, Some(metadata)),
            Ok(false) => ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                Self::ERROR_MESSAGE_SIGNATURE_VERIFICATION_FAILED,
                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
            ),
            Err(ex) => ValidationResult::failure_message(
                Self::STAGE_NAME_SIGNATURE,
                ex.to_string(),
                Some(Self::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED),
            ),
        }
    }

    /// Run stage 4: post-signature validators.
    ///
    /// This is where policy-like checks happen after cryptographic verification succeeds.
    fn run_post_signature_stage(
        &self,
        message: &CoseSign1Message,
        cose_key: Option<&Arc<dyn crypto_primitives::CryptoVerifier>>,
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
            cose_key,
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

    /// Async variant of [`Self::run_post_signature_stage`].
    async fn run_post_signature_stage_async(
        &self,
        message: &CoseSign1Message,
        cose_key: Option<&Arc<dyn crypto_primitives::CryptoVerifier>>,
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
            cose_key,
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

    /// Read a detached payload fully into memory.
    ///
    /// This is used for small or unknown-size detached payloads. For large payloads,
    /// the validator prefers the streaming signature path.
    fn read_detached_payload_bytes(&self, payload: &Payload) -> Result<Arc<[u8]>, String> {
        match payload {
            Payload::Bytes(b) => {
                if b.is_empty() {
                    return Err(Self::ERROR_MESSAGE_SIGNATURE_MISSING_PAYLOAD.to_string());
                }
                Ok(Arc::from(b.as_slice()))
            }
            Payload::Streaming(streaming) => {
                let mut reader = streaming.open()
                    .map_err(|e| format!("detached_payload_open_failed: {}", e))?;
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

/// Streaming reader for COSE `Sig_structure`.
///
/// This allows signature verification without allocating the full payload in memory by emitting
/// a CBOR-encoded prefix followed by raw payload bytes.
struct SigStructureReader {
    prefix: std::io::Cursor<Vec<u8>>,
    payload: Box<dyn Read + Send>,
    done: bool,
}

impl SigStructureReader {
    /// Create a streaming Sig_structure reader for a detached payload.
    ///
    /// `payload_len` is the payload length used to encode the CBOR byte-string header.
    fn new_detached(
        protected: &[u8],
        external_aad: &[u8],
        streaming: &dyn StreamingPayload,
        payload_len: u64,
    ) -> Result<Self, String> {
        let payload = streaming.open()
            .map_err(|e| format!("detached_payload_open_failed: {}", e))?;
        let external = if external_aad.is_empty() {
            None
        } else {
            Some(external_aad)
        };
        let prefix = build_sig_structure_prefix(protected, external, payload_len)
            .map_err(|e| format!("sig_structure_encode_failed: {e}"))?;
        Ok(Self {
            prefix: std::io::Cursor::new(prefix),
            payload,
            done: false,
        })
    }
}

impl Read for SigStructureReader {
    /// Read bytes from the Sig_structure stream.
    ///
    /// The stream consists of a fixed prefix (CBOR array + label + headers + AAD + bstr length)
    /// followed by the raw detached payload.
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

pub type CoseSign1MessageValidator = CoseSign1Validator;

/// Merge stage metadata into a combined metadata map.
///
/// The `prefix` namespaces keys for the stage (e.g. `Resolution:`) to prevent collisions when
/// multiple stages emit the same logical key.
fn merge_stage_metadata(
    combined: &mut BTreeMap<String, String>,
    prefix: &'static str,
    stage: &ValidationResult,
) {
    for (k, v) in &stage.metadata {
        combined.insert(
            format!(
                "{prefix}.{}",
                k
            ),
            v.clone(),
        );
    }
}

/// Build a full, in-memory COSE Sig_structure.
///
/// This is the buffered counterpart to [`cose_sign1_primitives::build_sig_structure_prefix`],
/// used for embedded payloads or detached payloads that are small/unknown-size.
fn build_local_sig_structure(
    protected: &[u8],
    external_aad: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let external = if external_aad.is_empty() {
        None
    } else {
        Some(external_aad)
    };
    build_sig_structure(protected, external, payload)
        .map_err(|e| format!("sig_structure_encode_failed: {e}"))
}
