// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Targeted tests for uncovered lines in `validator.rs`.
//!
//! Covers:
//! - Async pipeline paths: validate_bytes_async, validate_async, validate_internal_async
//! - Counter-signature bypass paths (resolution failed + bypass, resolution succeeded + bypass)
//! - Async resolution stage with diagnostics
//! - Async post-signature stage (skip + empty + failure + success)
//! - Streaming signature error paths (verify_init fail, read fail, update fail, finalize false/err)
//! - Algorithm mismatch with key_alg == 0 (no mismatch check)
//! - read_detached_payload_bytes streaming error paths
//! - SigStructureReader Read impl
//! - build_local_sig_structure error path
//! - CounterSignatureResolver::resolve_async default
//! - PostSignatureValidator::validate_async default

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::error::PayloadError;
use cose_sign1_primitives::payload::{Payload, StreamingPayload};
use cose_sign1_primitives::sig_structure::SizedRead;
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::error::TrustError;
use cose_sign1_validation_primitives::facts::{FactKey, TrustFactContext, TrustFactProducer};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::borrow::Cow;
use std::future::Future;
use std::io::{Cursor, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// ---------------------------------------------------------------------------
// Manual async executor
// ---------------------------------------------------------------------------

fn block_on<F: Future>(mut fut: F) -> F::Output {
    fn raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone_fn(_: *const ()) -> RawWaker {
            raw_waker()
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_fn, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }

    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = unsafe { Pin::new_unchecked(&mut fut) };

    loop {
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(v) => return v,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

// ---------------------------------------------------------------------------
// CBOR helpers
// ---------------------------------------------------------------------------

fn encode_protected_alg(alg: i64) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap();
    enc.encode_i64(alg).unwrap();
    enc.into_bytes()
}

fn encode_empty_map() -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_map(0).unwrap();
    enc.into_bytes()
}

fn build_cose_sign1(payload: Option<&[u8]>, alg: Option<i64>) -> Vec<u8> {
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    let protected = alg
        .map(encode_protected_alg)
        .unwrap_or_else(encode_empty_map);
    enc.encode_bstr(&protected).unwrap();
    enc.encode_map(0).unwrap();

    match payload {
        Some(payload_data) => enc.encode_bstr(payload_data).unwrap(),
        None => enc.encode_null().unwrap(),
    }
    enc.encode_bstr(b"sig").unwrap();
    enc.into_bytes()
}

fn allow_all_trust_plan() -> CompiledTrustPlan {
    TrustPolicyBuilder::new().build().compile()
}

// ---------------------------------------------------------------------------
// Mock verifiers
// ---------------------------------------------------------------------------

struct AlwaysTrueVerifier;
impl crypto_primitives::CryptoVerifier for AlwaysTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct AlwaysFalseVerifier;
impl crypto_primitives::CryptoVerifier for AlwaysFalseVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

/// Verifier with algorithm() == 0 (no algorithm constraint).
struct ZeroAlgVerifier;
impl crypto_primitives::CryptoVerifier for ZeroAlgVerifier {
    fn algorithm(&self) -> i64 {
        0
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

/// Verifier reporting a different algorithm than the message.
struct MismatchAlgVerifier {
    alg: i64,
}
impl crypto_primitives::CryptoVerifier for MismatchAlgVerifier {
    fn algorithm(&self) -> i64 {
        self.alg
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Streaming verifier mocks
// ---------------------------------------------------------------------------

struct StreamingFalseVerifier;
impl crypto_primitives::CryptoVerifier for StreamingFalseVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingFalseCtx))
    }
}
struct StreamingFalseCtx;
impl crypto_primitives::VerifyingContext for StreamingFalseCtx {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(false)
    }
}

struct StreamingErrorVerifier;
impl crypto_primitives::CryptoVerifier for StreamingErrorVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingErrorCtx))
    }
}
struct StreamingErrorCtx;
impl crypto_primitives::VerifyingContext for StreamingErrorCtx {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Err(CryptoError::VerificationFailed(
            "streaming boom".to_string(),
        ))
    }
}

struct StreamingInitFailVerifier;
impl crypto_primitives::CryptoVerifier for StreamingInitFailVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Err(CryptoError::VerificationFailed("init failed".to_string()))
    }
}

struct StreamingUpdateFailVerifier;
impl crypto_primitives::CryptoVerifier for StreamingUpdateFailVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingUpdateFailCtx))
    }
}
struct StreamingUpdateFailCtx;
impl crypto_primitives::VerifyingContext for StreamingUpdateFailCtx {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::VerificationFailed("update failed".to_string()))
    }
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

struct StreamingTrueVerifier;
impl crypto_primitives::CryptoVerifier for StreamingTrueVerifier {
    fn algorithm(&self) -> i64 {
        -7
    }
    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(false)
    }
    fn supports_streaming(&self) -> bool {
        true
    }
    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(StreamingTrueCtx))
    }
}
struct StreamingTrueCtx;
impl crypto_primitives::VerifyingContext for StreamingTrueCtx {
    fn update(&mut self, _chunk: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Key resolvers
// ---------------------------------------------------------------------------

struct StaticResolver {
    key: Arc<dyn crypto_primitives::CryptoVerifier>,
}
impl CoseKeyResolver for StaticResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult::success(self.key.clone())
    }
}

/// Resolver that returns success=true but cose_key=None (covers line 1166).
struct SuccessButNullKeyResolver;
impl CoseKeyResolver for SuccessButNullKeyResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult {
            is_success: true,
            cose_key: None,
            diagnostics: vec!["key was null".to_string()],
            ..CoseKeyResolutionResult::default()
        }
    }
}

/// Resolver that fails with diagnostics (covers lines 1171-1172).
struct DiagnosticFailResolver;
impl CoseKeyResolver for DiagnosticFailResolver {
    fn resolve(
        &self,
        _message: &CoseSign1Message,
        _options: &CoseSign1ValidationOptions,
    ) -> CoseKeyResolutionResult {
        CoseKeyResolutionResult {
            is_success: false,
            diagnostics: vec![
                "cert chain invalid".to_string(),
                "key not found".to_string(),
            ],
            ..CoseKeyResolutionResult::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming payload helpers
// ---------------------------------------------------------------------------

struct LargeStreamingPayload {
    size: usize,
}

struct LargePayloadReader {
    remaining: usize,
}

impl Read for LargePayloadReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let to_write = std::cmp::min(buf.len(), self.remaining);
        for b in &mut buf[..to_write] {
            *b = 0xAB;
        }
        self.remaining -= to_write;
        Ok(to_write)
    }
}

impl SizedRead for LargePayloadReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.remaining as u64)
    }
}

impl StreamingPayload for LargeStreamingPayload {
    fn size(&self) -> u64 {
        self.size as u64
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(LargePayloadReader {
            remaining: self.size,
        }))
    }
}

struct FailOpenStreamingPayload;
impl StreamingPayload for FailOpenStreamingPayload {
    fn size(&self) -> u64 {
        100_000
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Err(PayloadError::OpenFailed("cannot open".to_string()))
    }
}

struct SmallStreamingPayload {
    data: Vec<u8>,
}

struct SmallPayloadReader {
    cursor: Cursor<Vec<u8>>,
    len: u64,
}
impl Read for SmallPayloadReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.cursor.read(buf)
    }
}
impl SizedRead for SmallPayloadReader {
    fn len(&self) -> Result<u64, std::io::Error> {
        Ok(self.len)
    }
}
impl StreamingPayload for SmallStreamingPayload {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        let len = self.data.len() as u64;
        Ok(Box::new(SmallPayloadReader {
            cursor: Cursor::new(self.data.clone()),
            len,
        }))
    }
}

struct EmptyStreamingPayload;
impl StreamingPayload for EmptyStreamingPayload {
    fn size(&self) -> u64 {
        0
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(SmallPayloadReader {
            cursor: Cursor::new(Vec::new()),
            len: 0,
        }))
    }
}

// ---------------------------------------------------------------------------
// Post-signature validators
// ---------------------------------------------------------------------------

struct FailingPostSigValidator;
impl PostSignatureValidator for FailingPostSigValidator {
    fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
        ValidationResult::failure_message("post-sig", "policy denied", Some("POST_DENIED"))
    }
}

// ---------------------------------------------------------------------------
// Counter-signature resolver that produces real counter-signatures
// ---------------------------------------------------------------------------

struct FakeCounterSignature {
    raw: Arc<[u8]>,
    is_protected: bool,
}
impl CounterSignature for FakeCounterSignature {
    fn raw_counter_signature_bytes(&self) -> Arc<[u8]> {
        self.raw.clone()
    }
    fn is_protected_header(&self) -> bool {
        self.is_protected
    }
    fn cose_key(&self) -> Arc<dyn crypto_primitives::CryptoVerifier> {
        Arc::new(AlwaysTrueVerifier)
    }
}

struct FakeCounterSigResolver;
impl CounterSignatureResolver for FakeCounterSigResolver {
    fn name(&self) -> &'static str {
        "fake_counter_sig"
    }
    fn resolve(&self, _message: &CoseSign1Message) -> CounterSignatureResolutionResult {
        CounterSignatureResolutionResult::success(vec![Arc::new(FakeCounterSignature {
            raw: Arc::from(b"counter_sig_bytes".as_slice()),
            is_protected: false,
        })])
    }
}

// ---------------------------------------------------------------------------
// Custom fact producer to emit CounterSignatureEnvelopeIntegrityFact
// ---------------------------------------------------------------------------

struct IntegrityFactProducer {
    sig_structure_intact: bool,
    details: Option<Cow<'static, str>>,
}

impl TrustFactProducer for IntegrityFactProducer {
    fn name(&self) -> &'static str {
        "integrity_fact_producer"
    }

    fn provides(&self) -> &'static [FactKey] {
        static KEYS: std::sync::LazyLock<[FactKey; 1]> =
            std::sync::LazyLock::new(|| [FactKey::of::<CounterSignatureEnvelopeIntegrityFact>()]);
        &*KEYS
    }

    fn produce(&self, ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        // Only produce on counter-signature subjects.
        if ctx.subject().kind == "CounterSignature" {
            ctx.observe(CounterSignatureEnvelopeIntegrityFact {
                sig_structure_intact: self.sig_structure_intact,
                details: self.details.clone(),
            })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Validator helpers
// ---------------------------------------------------------------------------

fn validator_with(
    resolver: Option<Arc<dyn CoseKeyResolver>>,
    post_validators: Vec<Arc<dyn PostSignatureValidator>>,
    configure: impl FnOnce(&mut CoseSign1ValidationOptions),
) -> CoseSign1Validator {
    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    if let Some(resolver) = resolver {
        trust_packs.push(Arc::new(
            SimpleTrustPack::no_facts("resolver_pack").with_cose_key_resolver(resolver),
        ));
    }

    if !post_validators.is_empty() {
        let pack = post_validators
            .into_iter()
            .fold(SimpleTrustPack::no_facts("post_sig_pack"), |p, v| {
                p.with_post_signature_validator(v)
            });
        trust_packs.push(Arc::new(pack));
    }

    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    CoseSign1Validator::new(trust_packs).with_options(configure)
}

fn large_stream_size() -> usize {
    (CoseSign1Validator::LARGE_STREAM_THRESHOLD + 1) as usize
}

// ===========================================================================
// Tests targeting validate_bytes_async (lines 604-622)
// ===========================================================================

#[test]
fn validate_bytes_async_success_covers_info_debug_logging() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

#[test]
fn validate_bytes_async_parse_failure_returns_cose_decode_error() {
    let v = validator_with(None, vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = block_on(v.validate_bytes_async(
        EverParseCborProvider,
        Arc::from(vec![0xFF, 0xFF].into_boxed_slice()),
    ));

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("COSE decode failed"));
}

// ===========================================================================
// Tests targeting validate_async (lines 567-575)
// ===========================================================================

#[test]
fn validate_async_embedded_success() {
    let cose = build_cose_sign1(Some(b"hello"), Some(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = block_on(v.validate_async(&parsed, Arc::from(cose.into_boxed_slice()))).unwrap();
    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

// ===========================================================================
// Tests targeting resolution with diagnostics (lines 1166, 1171-1172)
// ===========================================================================

#[test]
fn resolution_success_but_null_key_falls_through_to_failure_with_diagnostics() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let v = validator_with(Some(Arc::new(SuccessButNullKeyResolver)), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert!(result
        .resolution
        .metadata
        .get("Diagnostics")
        .map(|d| d.contains("key was null"))
        .unwrap_or(false));
}

#[test]
fn resolution_with_multiple_diagnostics_are_joined() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let v = validator_with(Some(Arc::new(DiagnosticFailResolver)), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    let diag = result.resolution.metadata.get("Diagnostics").unwrap();
    assert!(diag.contains("cert chain invalid"));
    assert!(diag.contains("key not found"));
}

// ===========================================================================
// Async resolution with diagnostics (lines 1216, 1225-1226)
// ===========================================================================

#[test]
fn async_resolution_success_but_null_key_reports_diagnostics() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let v = validator_with(Some(Arc::new(SuccessButNullKeyResolver)), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

#[test]
fn async_resolution_failure_with_diagnostics() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let v = validator_with(Some(Arc::new(DiagnosticFailResolver)), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

// ===========================================================================
// Async pipeline: resolution fails, no bypass -> early exit (lines 907-931)
// ===========================================================================

#[test]
fn async_pipeline_resolution_fails_no_bypass_returns_not_applicable() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));

    // No resolvers => resolution fails, no counter-sig bypass => early exit
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("allow_all").with_default_trust_plan(allow_all_trust_plan()),
    )];

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Async trust denied (covers 1002-1016)
// ===========================================================================

#[test]
fn async_pipeline_trust_denied_returns_not_applicable_signature() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    // Empty trust plan with bypass_trust = false denies trust
    let v = validator_with(Some(resolver), vec![], |_o| {});

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.trust.kind);
    assert_eq!(ValidationResultKind::NotApplicable, result.signature.kind);
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Async full pipeline success (covers lines 1062-1135)
// ===========================================================================

#[test]
fn async_pipeline_full_success_merges_metadata() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
    assert_eq!(ValidationResultKind::Success, result.resolution.kind);
    assert_eq!(ValidationResultKind::Success, result.trust.kind);
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}

// ===========================================================================
// Async signature failure (covers 1068-1080)
// ===========================================================================

#[test]
fn async_pipeline_signature_failure_returns_not_applicable_post_sig() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysFalseVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        ValidationResultKind::NotApplicable,
        result.post_signature_policy.kind
    );
}

// ===========================================================================
// Async post-signature failure (covers 1082-1100)
// ===========================================================================

#[test]
fn async_pipeline_post_signature_failure() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(
        Some(resolver),
        vec![Arc::new(FailingPostSigValidator)],
        |o| {
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Async post-signature skip and empty (covers lines 1635-1641)
// ===========================================================================

#[test]
fn async_pipeline_post_sig_skip_returns_success() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(
        Some(resolver),
        vec![Arc::new(FailingPostSigValidator)],
        |o| {
            o.skip_post_signature_validation = true;
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(
        ValidationResultKind::Success,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

#[test]
fn async_pipeline_post_sig_empty_validators_returns_success() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    // No post-sig validators at all (tests line 1640)
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(SimpleTrustPack::no_facts("resolver_pack").with_cose_key_resolver(resolver)),
        Arc::new(
            SimpleTrustPack::no_facts("allow_all_trust")
                .with_default_trust_plan(allow_all_trust_plan()),
        ),
    ];

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

// ===========================================================================
// Sync post-signature: empty validators (line 1601)
// ===========================================================================

#[test]
fn sync_post_sig_empty_validators_returns_success() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![
        Arc::new(SimpleTrustPack::no_facts("resolver_pack").with_cose_key_resolver(resolver)),
        Arc::new(
            SimpleTrustPack::no_facts("allow_all_trust")
                .with_default_trust_plan(allow_all_trust_plan()),
        ),
    ];

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

// ===========================================================================
// Algorithm mismatch (lines 1390-1407)
// ===========================================================================

#[test]
fn algorithm_mismatch_returns_failure() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7)); // ES256 in message
    let key: Arc<dyn crypto_primitives::CryptoVerifier> =
        Arc::new(MismatchAlgVerifier { alg: -35 });
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("algorithm"));
}

#[test]
fn zero_algorithm_key_skips_mismatch_check() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(ZeroAlgVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // ZeroAlgVerifier::verify returns true, so signature should pass
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}

// ===========================================================================
// Streaming signature error paths (lines 1431-1512)
// ===========================================================================

#[test]
fn streaming_no_alg_returns_no_applicable_validator() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, None); // no alg
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR.to_string()),
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.clone())
    );
}

#[test]
fn streaming_open_failure_returns_sig_structure_error() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(FailOpenStreamingPayload)));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("detached_payload_open_failed"));
}

#[test]
fn streaming_verify_init_fail_returns_failure() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingInitFailVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("initialize verifying context"));
}

#[test]
fn streaming_update_fail_returns_failure() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingUpdateFailVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("update verifying context"));
}

#[test]
fn streaming_finalize_false_returns_failure() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingFalseVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert_eq!(
        Some(CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED.to_string()),
        result
            .signature
            .failures
            .first()
            .and_then(|f| f.error_code.clone())
    );
}

#[test]
fn streaming_finalize_error_returns_failure() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingErrorVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("streaming boom"));
}

// ===========================================================================
// Detached payload: small streaming path (covers lines 1522-1527, 1674, 1680, 1684)
// ===========================================================================

#[test]
fn detached_small_streaming_payload_uses_buffered_path() {
    let small_data = b"small payload content".to_vec();
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(SmallStreamingPayload {
                data: small_data,
            })));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert_eq!(
        Some("non-streaming".to_string()),
        result
            .signature
            .metadata
            .get(CoseSign1Validator::METADATA_KEY_SELECTED_VALIDATOR)
            .cloned()
    );
}

#[test]
fn detached_empty_bytes_returns_missing_payload_error() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Bytes(vec![]));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("detached content"));
}

#[test]
fn detached_streaming_open_fail_buffered_returns_error() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })),
        vec![],
        |o| {
            // This streaming payload has size < threshold, so it takes the buffered path
            // but open fails
            o.detached_payload = Some(Payload::Streaming(Box::new(FailOpenSmallStreamingPayload)));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("detached_payload_open_failed"));
}

struct FailOpenSmallStreamingPayload;
impl StreamingPayload for FailOpenSmallStreamingPayload {
    fn size(&self) -> u64 {
        100 // below threshold
    }
    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Err(PayloadError::OpenFailed("open boom".to_string()))
    }
}

#[test]
fn detached_streaming_empty_content_returns_missing_payload() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(EmptyStreamingPayload)));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.signature.kind);
    assert!(result
        .signature
        .failures
        .first()
        .unwrap()
        .message
        .contains("detached content"));
}

// ===========================================================================
// Counter-signature bypass: sync resolution failed + bypass (lines 684-751)
// ===========================================================================

#[test]
fn counter_sig_bypass_sync_resolution_failed_with_integrity_fact() {
    // Build a validator with:
    // 1. A counter-sig resolver that produces counter-sigs
    // 2. A fact producer that emits CounterSignatureEnvelopeIntegrityFact
    // 3. No key resolver (resolution will fail)

    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: Some(Cow::Borrowed("MST receipt verified")),
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();

    // Pack with message fact producer that has counter-sig resolver
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));

    // Pack with integrity fact producer
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));

    // Trust plan that bypasses trust
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Resolution fails (no key resolvers), but counter-sig bypass should kick in
    // The overall result depends on whether the bypass path succeeds
    assert_eq!(ValidationResultKind::Success, result.overall.kind);
    assert!(result
        .signature
        .metadata
        .get("SignatureVerificationMode")
        .map(|v| v.contains("Bypassed"))
        .unwrap_or(false));
}

#[test]
fn counter_sig_bypass_sync_resolution_failed_post_sig_fails() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("post_pack")
            .with_post_signature_validator(Arc::new(FailingPostSigValidator)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Post-sig fails => overall fails
    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Counter-sig bypass: sync resolution succeeded + bypass (lines 775-811)
// ===========================================================================

#[test]
fn counter_sig_bypass_sync_resolution_succeeded_with_integrity_fact() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: Some(Cow::Borrowed("envelope verified")),
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("resolver_pack")
            .with_cose_key_resolver(Arc::new(StaticResolver { key })),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Resolution succeeds, counter-sig integrity also attests => bypass path (775-811)
    assert_eq!(ValidationResultKind::Success, result.overall.kind);
    assert!(result
        .signature
        .metadata
        .get("SignatureVerificationMode")
        .map(|v| v.contains("Bypassed"))
        .unwrap_or(false));
}

#[test]
fn counter_sig_bypass_sync_resolution_succeeded_post_sig_fails() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("resolver_pack")
            .with_cose_key_resolver(Arc::new(StaticResolver { key })),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("post_pack")
            .with_post_signature_validator(Arc::new(FailingPostSigValidator)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Post-signature fails => overall fails
    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Counter-sig bypass: async resolution failed + bypass (lines 932-999)
// ===========================================================================

#[test]
fn async_counter_sig_bypass_resolution_failed_success() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: Some(Cow::Borrowed("async bypass")),
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

#[test]
fn async_counter_sig_bypass_resolution_failed_post_sig_fails() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("post_pack")
            .with_post_signature_validator(Arc::new(FailingPostSigValidator)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Counter-sig bypass: async resolution succeeded + bypass (lines 1023-1059)
// ===========================================================================

#[test]
fn async_counter_sig_bypass_resolution_succeeded_success() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: Some(Cow::Borrowed("async resolved bypass")),
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("resolver_pack")
            .with_cose_key_resolver(Arc::new(StaticResolver { key })),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

#[test]
fn async_counter_sig_bypass_resolution_succeeded_post_sig_fails() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("resolver_pack")
            .with_cose_key_resolver(Arc::new(StaticResolver { key })),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("post_pack")
            .with_post_signature_validator(Arc::new(FailingPostSigValidator)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result =
        block_on(v.validate_bytes_async(EverParseCborProvider, Arc::from(cose.into_boxed_slice())))
            .unwrap();

    assert_eq!(
        ValidationResultKind::Failure,
        result.post_signature_policy.kind
    );
    assert_eq!(ValidationResultKind::Failure, result.overall.kind);
}

// ===========================================================================
// Counter-sig bypass details metadata (lines 1348-1369)
// ===========================================================================

#[test]
fn counter_sig_bypass_includes_details_metadata() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: Some(Cow::Borrowed("sha256 verified")),
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Check for bypass details metadata in the signature stage
    assert!(result
        .signature
        .metadata
        .get("SignatureBypassDetails")
        .map(|v| v.contains("sha256 verified"))
        .unwrap_or(false));
}

#[test]
fn counter_sig_bypass_no_details_when_none() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: true,
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // No details key when details is None
    assert!(!result
        .signature
        .metadata
        .contains_key("SignatureBypassDetails"));
}

// ===========================================================================
// Counter-sig integrity fact not intact (lines 1339-1341)
// ===========================================================================

#[test]
fn counter_sig_integrity_not_intact_does_not_bypass() {
    let counter_sig_resolver: Arc<dyn CounterSignatureResolver> = Arc::new(FakeCounterSigResolver);
    let integrity_producer: Arc<dyn TrustFactProducer> = Arc::new(IntegrityFactProducer {
        sig_structure_intact: false, // not intact
        details: None,
    });

    let message_producer = CoseSign1MessageFactProducer::new()
        .with_counter_signature_resolvers(vec![counter_sig_resolver]);

    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);

    let mut trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = Vec::new();
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("resolver_pack")
            .with_cose_key_resolver(Arc::new(StaticResolver { key })),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("msg_fact_pack").with_fact_producer(Arc::new(message_producer)),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("integrity_pack").with_fact_producer(integrity_producer),
    ));
    trust_packs.push(Arc::new(
        SimpleTrustPack::no_facts("allow_all_trust")
            .with_default_trust_plan(allow_all_trust_plan()),
    ));

    let v = CoseSign1Validator::new(trust_packs).with_options(|o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // Not bypassed - takes standard signature verification path
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert_eq!(
        Some("non-streaming".to_string()),
        result.signature.metadata.get("SelectedValidator").cloned()
    );
}

// ===========================================================================
// CounterSignatureResolver::resolve_async default (lines 323-328)
// ===========================================================================

#[test]
fn counter_signature_resolver_async_default_delegates_to_sync() {
    struct TestCSResolver;
    impl CounterSignatureResolver for TestCSResolver {
        fn name(&self) -> &'static str {
            "test_cs_resolver"
        }
        fn resolve(&self, _message: &CoseSign1Message) -> CounterSignatureResolutionResult {
            CounterSignatureResolutionResult::success(vec![])
        }
    }

    let cose = build_cose_sign1(Some(b"test"), Some(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();
    let resolver = TestCSResolver;

    let result = block_on(resolver.resolve_async(&parsed));
    assert!(result.is_success);
}

// ===========================================================================
// PostSignatureValidator::validate_async default (lines 342-347)
// ===========================================================================

#[test]
fn post_signature_validator_async_default_delegates_to_sync() {
    struct TestPSV;
    impl PostSignatureValidator for TestPSV {
        fn validate(&self, _context: &PostSignatureValidationContext<'_>) -> ValidationResult {
            ValidationResult::success("test_psv", None)
        }
    }

    let cose = build_cose_sign1(Some(b"test"), Some(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();
    let trust_decision = cose_sign1_validation_primitives::TrustDecision {
        is_trusted: true,
        reasons: vec![],
    };
    let metadata = std::collections::BTreeMap::new();
    let options = CoseSign1ValidationOptions::default();

    let context = PostSignatureValidationContext {
        message: &parsed,
        trust_decision: &trust_decision,
        signature_metadata: &metadata,
        options: &options,
        cose_key: None,
    };

    let validator = TestPSV;
    let result = block_on(validator.validate_async(&context));
    assert!(result.is_valid());
}

// ===========================================================================
// CoseSign1ValidatorInit From impls
// ===========================================================================

#[test]
fn validator_init_from_compiled_plan() {
    let plan = CoseSign1CompiledTrustPlan::from_parts(allow_all_trust_plan(), vec![]).unwrap();
    let v = CoseSign1Validator::new(plan);

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // No resolvers => resolution fails
    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

#[test]
fn validator_advanced_constructor() {
    let trust_packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![Arc::new(
        SimpleTrustPack::no_facts("allow_all").with_default_trust_plan(allow_all_trust_plan()),
    )];

    let mut options = CoseSign1ValidationOptions::default();
    options.trust_evaluation_options.bypass_trust = true;

    let v = CoseSign1Validator::advanced(trust_packs, options);

    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Failure, result.resolution.kind);
}

// ===========================================================================
// CoseSign1ValidationError Display
// ===========================================================================

#[test]
fn validation_error_display_trust() {
    let err = CoseSign1ValidationError::Trust("bad trust".to_string());
    assert!(err.to_string().contains("trust evaluation failed"));
    assert!(err.to_string().contains("bad trust"));

    // Also test Error trait
    let _: &dyn std::error::Error = &err;
}

#[test]
fn validation_error_display_cose_decode() {
    let err = CoseSign1ValidationError::CoseDecode("invalid cbor".to_string());
    assert!(err.to_string().contains("COSE decode failed"));
}

// ===========================================================================
// Associated data path through build_local_sig_structure (lines 1556-1564)
// ===========================================================================

#[test]
fn associated_data_used_in_sig_structure() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.associated_data = Some(Arc::from(b"external_aad".to_vec().into_boxed_slice()));
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    // The sig structure includes AAD, so verify() is called with different data
    // AlwaysTrueVerifier always passes, so this validates the path is exercised
    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}

// ===========================================================================
// Streaming path with associated data (covers lines 1427-1428)
// ===========================================================================

#[test]
fn streaming_with_associated_data() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(StreamingTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Streaming(Box::new(LargeStreamingPayload {
                size: large_stream_size(),
            })));
            o.associated_data = Some(Arc::from(b"aad".to_vec().into_boxed_slice()));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
}

// ===========================================================================
// Sync validate_bytes with detached Bytes payload (covers 1521-1527 fallback)
// ===========================================================================

#[test]
fn detached_bytes_payload_verification() {
    let v = validator_with(
        Some(Arc::new(StaticResolver {
            key: Arc::new(AlwaysTrueVerifier),
        })),
        vec![],
        |o| {
            o.detached_payload = Some(Payload::Bytes(b"detached content".to_vec()));
            o.trust_evaluation_options.bypass_trust = true;
        },
    );

    let cose = build_cose_sign1(None, Some(-7));
    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.signature.kind);
    assert_eq!(
        Some("non-streaming".to_string()),
        result.signature.metadata.get("SelectedValidator").cloned()
    );
}

// ===========================================================================
// Trust plan audit metadata (lines 1289-1290, 1309-1311)
// ===========================================================================

#[test]
fn trust_stage_includes_audit_metadata_when_bypass() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.trust.kind);
    assert!(result.trust.metadata.contains_key("BypassTrust"));
    assert!(result.trust.metadata.contains_key("TrustDecision"));
}

// ===========================================================================
// Sync validate method (not validate_bytes) (lines 559-565)
// ===========================================================================

#[test]
fn validate_method_success() {
    let cose = build_cose_sign1(Some(b"hello"), Some(-7));
    let parsed = CoseSign1Message::parse(&cose).unwrap();
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate(&parsed, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);
}

// ===========================================================================
// merge_stage_metadata coverage
// ===========================================================================

#[test]
fn overall_metadata_prefixes_stage_names() {
    let cose = build_cose_sign1(Some(b"payload"), Some(-7));
    let key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(AlwaysTrueVerifier);
    let resolver: Arc<dyn CoseKeyResolver> = Arc::new(StaticResolver { key });

    let v = validator_with(Some(resolver), vec![], |o| {
        o.trust_evaluation_options.bypass_trust = true;
    });

    let result = v
        .validate_bytes(EverParseCborProvider, Arc::from(cose.into_boxed_slice()))
        .unwrap();

    assert_eq!(ValidationResultKind::Success, result.overall.kind);

    // Check that merged metadata has prefixed keys
    let overall_keys: Vec<&String> = result.overall.metadata.keys().collect();
    let has_trust_prefix = overall_keys.iter().any(|k| k.starts_with("Trust."));
    let has_sig_prefix = overall_keys.iter().any(|k| k.starts_with("Signature."));
    assert!(
        has_trust_prefix,
        "Expected Trust. prefixed key in overall metadata"
    );
    assert!(
        has_sig_prefix,
        "Expected Signature. prefixed key in overall metadata"
    );
}
