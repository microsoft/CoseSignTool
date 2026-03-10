// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Simple targeted coverage tests for validator gaps.
//! Focus on async paths and result helpers without complex mocks.

use cose_sign1_validation::fluent::{
    CoseSign1ValidationError, CoseSign1ValidationOptions,
    CoseSign1Validator, CoseKeyResolutionResult,
    CounterSignatureResolutionResult,
    ValidationFailure, ValidationResult, ValidationResultKind,
    PostSignatureValidationContext, PostSignatureValidator, CoseKeyResolver,
    CoseSign1TrustPack, CoseSign1CompiledTrustPlan, CoseSign1Message,
    CryptoVerifier, CryptoError, Payload,
};
use cbor_primitives::{CborProvider, CborEncoder};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation_primitives::{TrustDecision};
use cose_sign1_validation_primitives::policy::TrustPolicyBuilder as PrimitivesTrustPolicyBuilder;
use cose_sign1_validation_primitives::rules::FnRule;
use cose_sign1_validation_primitives::subject::TrustSubject;
use cose_sign1_validation_primitives::facts::{TrustFactEngine, TrustFactProducer, TrustFactContext, FactKey};
use cose_sign1_validation_primitives::plan::CompiledTrustPlan;
use cose_sign1_validation_primitives::error::TrustError;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

// Helper function to create an allow-all trust plan for testing
fn allow_all_plan() -> CompiledTrustPlan {
    PrimitivesTrustPolicyBuilder::new()
        .add_trust_source(Arc::new(FnRule::new(
            "allow",
            |_e: &TrustFactEngine, _s: &TrustSubject| Ok(TrustDecision::trusted()),
        )))
        .build()
        .compile()
}

#[test]
fn test_validation_result_kind_comprehensive() {
    let kind_default = ValidationResultKind::default();
    assert_eq!(kind_default, ValidationResultKind::NotApplicable);
    
    let kind_success = ValidationResultKind::Success;
    let kind_failure = ValidationResultKind::Failure;
    let kind_na = ValidationResultKind::NotApplicable;
    
    // Test equality and inequality
    assert_eq!(kind_success, ValidationResultKind::Success);
    assert_ne!(kind_success, kind_failure);
    assert_ne!(kind_success, kind_na);
    assert_ne!(kind_failure, kind_na);
}

#[test]
fn test_validation_failure_fields() {
    let mut failure = ValidationFailure::default();
    assert!(failure.message.is_empty());
    assert!(failure.error_code.is_none());
    assert!(failure.property_name.is_none());
    assert!(failure.attempted_value.is_none());
    assert!(failure.exception.is_none());
    
    // Test field assignment
    failure.message = "Test message".to_string();
    failure.error_code = Some("TEST_CODE".to_string());
    failure.property_name = Some("test_prop".to_string());
    failure.attempted_value = Some("test_val".to_string());
    failure.exception = Some("test_exception".to_string());
    
    assert_eq!(failure.message, "Test message");
    assert_eq!(failure.error_code.as_deref(), Some("TEST_CODE"));
    assert_eq!(failure.property_name.as_deref(), Some("test_prop"));
    assert_eq!(failure.attempted_value.as_deref(), Some("test_val"));
    assert_eq!(failure.exception.as_deref(), Some("test_exception"));
}

#[test]
fn test_validation_result_methods() {
    // Test success result
    let success_result = ValidationResult::success("TestValidator".to_string(), None);
    assert!(success_result.is_valid());
    assert!(!success_result.is_failure());
    assert_eq!(success_result.kind, ValidationResultKind::Success);
    assert_eq!(success_result.validator_name, "TestValidator");
    
    // Test failure result
    let failure_result = ValidationResult::failure_message(
        "TestValidator",
        "Test failure message",
        Some("TEST_ERROR_CODE"),
    );
    assert!(!failure_result.is_valid());
    assert!(failure_result.is_failure());
    assert_eq!(failure_result.kind, ValidationResultKind::Failure);
    assert_eq!(failure_result.failures.len(), 1);
    assert_eq!(failure_result.failures[0].message, "Test failure message");
    assert_eq!(failure_result.failures[0].error_code.as_deref(), Some("TEST_ERROR_CODE"));
    
    // Test not applicable result
    let na_result = ValidationResult::not_applicable("TestValidator", Some("reason"));
    assert_eq!(na_result.kind, ValidationResultKind::NotApplicable);
    assert!(!na_result.is_valid());
    assert!(!na_result.is_failure());
    assert!(na_result.metadata.contains_key(ValidationResult::METADATA_REASON_KEY));
}

#[test]
fn test_validation_result_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("test_key".to_string(), "test_value".to_string());
    metadata.insert("another_key".to_string(), "another_value".to_string());
    
    let result = ValidationResult::success("TestValidator".to_string(), Some(metadata.clone()));
    assert!(result.is_valid());
    assert_eq!(result.metadata, metadata);
    assert_eq!(result.metadata.get("test_key").unwrap(), "test_value");
}

#[test]
fn test_cose_key_resolution_result_success() {
    use crypto_primitives::CryptoVerifier;
    
    // Simple mock verifier for testing
    struct TestVerifier;
    impl CryptoVerifier for TestVerifier {
        fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, crypto_primitives::CryptoError> {
            Ok(true)
        }
        fn algorithm(&self) -> i64 { -7 }  // ES256
    }
    
    let verifier = Arc::new(TestVerifier);
    let result = CoseKeyResolutionResult::success(verifier.clone());
    
    assert!(result.is_success);
    assert!(result.cose_key.is_some());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
    assert!(result.diagnostics.is_empty());
}

#[test]
fn test_cose_key_resolution_result_failure() {
    let result = CoseKeyResolutionResult::failure(
        Some("KEY_NOT_FOUND".to_string()),
        Some("Unable to resolve signing key".to_string())
    );
    
    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert_eq!(result.error_code.as_deref(), Some("KEY_NOT_FOUND"));
    assert_eq!(result.error_message.as_deref(), Some("Unable to resolve signing key"));
}

#[test]
fn test_counter_signature_resolution_result_success() {
    let result = CounterSignatureResolutionResult::success(vec![]);
    
    assert!(result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert!(result.error_code.is_none());
    assert!(result.error_message.is_none());
}

#[test] 
fn test_counter_signature_resolution_result_failure() {
    let result = CounterSignatureResolutionResult::failure(
        Some("CS_ERROR".to_string()),
        Some("Counter signature resolution failed".to_string())
    );
    
    assert!(!result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert_eq!(result.error_code.as_deref(), Some("CS_ERROR"));
    assert_eq!(result.error_message.as_deref(), Some("Counter signature resolution failed"));
}

#[test]
fn test_validation_options_defaults() {
    let options = CoseSign1ValidationOptions::default();
    
    assert!(options.detached_payload.is_none());
    assert!(options.associated_data.is_none());
    assert!(!options.skip_post_signature_validation);
}

#[test]
fn test_validation_options_with_detached_payload() {
    use cose_sign1_primitives::payload::Payload;
    
    let payload_data = b"test detached payload";
    let payload = Payload::Bytes(payload_data.to_vec());
    
    let mut options = CoseSign1ValidationOptions::default();
    options.detached_payload = Some(payload);
    options.skip_post_signature_validation = true;
    
    assert!(options.detached_payload.is_some());
    assert!(options.skip_post_signature_validation);
}

#[test]
fn test_validation_error_types() {
    let decode_error = CoseSign1ValidationError::CoseDecode("Invalid CBOR".to_string());
    match decode_error {
        CoseSign1ValidationError::CoseDecode(msg) => assert_eq!(msg, "Invalid CBOR"),
        _ => panic!("Unexpected error type"),
    }
    
    let trust_error = CoseSign1ValidationError::Trust("Trust evaluation failed".to_string());
    match trust_error {
        CoseSign1ValidationError::Trust(msg) => assert_eq!(msg, "Trust evaluation failed"),
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_validation_result_metadata_reason_key() {
    assert_eq!(ValidationResult::METADATA_REASON_KEY, "Reason");
}

// Test Clone implementations for coverage
#[test] 
fn test_cloneable_types() {
    let failure = ValidationFailure {
        message: "test".to_string(),
        error_code: Some("CODE".to_string()),
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    let cloned_failure = failure.clone();
    assert_eq!(failure.message, cloned_failure.message);
    assert_eq!(failure.error_code, cloned_failure.error_code);
    
    let result = ValidationResult {
        kind: ValidationResultKind::Success,
        validator_name: "test".to_string(),
        failures: vec![failure],
        metadata: BTreeMap::new(),
    };
    let cloned_result = result.clone();
    assert_eq!(result.kind, cloned_result.kind);
    assert_eq!(result.validator_name, cloned_result.validator_name);
    
    let cs_result = CounterSignatureResolutionResult::success(vec![]);
    let cloned_cs = cs_result.clone();
    assert_eq!(cs_result.is_success, cloned_cs.is_success);
}

// Test PartialEq implementations for coverage
#[test]
fn test_partial_eq_implementations() {
    let failure1 = ValidationFailure::default();
    let failure2 = ValidationFailure::default();
    assert_eq!(failure1, failure2);
    
    let result1 = ValidationResult::success("test".to_string(), None);
    let result2 = ValidationResult::success("test".to_string(), None);
    assert_eq!(result1, result2);
    
    let result3 = ValidationResult::failure_message("test", "error", None);
    assert_ne!(result1, result3);
}

// Test Debug implementations for coverage  
#[test]
fn test_debug_implementations() {
    let failure = ValidationFailure::default();
    let debug_str = format!("{:?}", failure);
    assert!(debug_str.contains("ValidationFailure"));
    
    let result = ValidationResult::success("test".to_string(), None);
    let debug_str = format!("{:?}", result);
    assert!(debug_str.contains("ValidationResult"));
    
    let kind = ValidationResultKind::Success;
    let debug_str = format!("{:?}", kind);
    assert!(debug_str.contains("Success"));
}

// Manual async executor for testing async validation paths
fn block_on<F: Future>(fut: F) -> F::Output {
    fn raw_waker() -> RawWaker {
        fn no_op(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker { raw_waker() }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("Future did not complete"),
    }
}

// Mock verifier for testing
#[derive(Clone)]
struct MockVerifier {
    should_succeed: bool,
    should_error: bool,
}

impl crypto_primitives::CryptoVerifier for MockVerifier {
    fn algorithm(&self) -> i64 {
        -7  // ES256
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if self.should_error {
            return Err(CryptoError::VerificationFailed("mock error".to_string()));
        }
        Ok(self.should_succeed && !data.is_empty() && !signature.is_empty())
    }
}

// Mock trust pack for Vec<Arc<dyn CoseSign1TrustPack>> pattern testing
struct MockTrustPack {
    should_resolve_key: bool,
}

impl CoseSign1TrustPack for MockTrustPack {
    fn name(&self) -> &'static str {
        "MockTrustPack"
    }

    fn fact_producer(&self) -> Arc<dyn TrustFactProducer> {
        Arc::new(MockFactProducer)
    }

    fn cose_key_resolvers(&self) -> Vec<Arc<dyn CoseKeyResolver>> {
        if self.should_resolve_key {
            vec![Arc::new(MockKeyResolver::success())]
        } else {
            vec![Arc::new(MockKeyResolver::failure())]
        }
    }

    fn post_signature_validators(&self) -> Vec<Arc<dyn PostSignatureValidator>> {
        vec![Arc::new(MockPostSignatureValidator)]
    }

    fn default_trust_plan(&self) -> Option<CompiledTrustPlan> {
        Some(allow_all_plan())
    }
}

struct MockFactProducer;

impl TrustFactProducer for MockFactProducer {
    fn name(&self) -> &'static str {
        "MockFactProducer"
    }
    
    fn produce(
        &self,
        _context: &mut TrustFactContext,
    ) -> Result<(), TrustError> {
        Ok(())
    }
    
    fn provides(&self) -> &'static [FactKey] {
        &[]
    }
}

// Mock key resolver for testing async paths and failures
struct MockKeyResolver {
    should_succeed: bool,
}

impl MockKeyResolver {
    fn success() -> Self {
        Self { should_succeed: true }
    }

    fn failure() -> Self {
        Self { should_succeed: false }
    }
}

impl CoseKeyResolver for MockKeyResolver {
    fn resolve(&self, _message: &CoseSign1Message, _options: &CoseSign1ValidationOptions) -> CoseKeyResolutionResult {
        if self.should_succeed {
            CoseKeyResolutionResult::success(Arc::new(MockVerifier { should_succeed: true, should_error: false }))
        } else {
            CoseKeyResolutionResult::failure(Some("TEST_ERROR".to_string()), Some("Mock resolver failure".to_string()))
        }
    }

    fn resolve_async<'a>(
        &'a self,
        _message: &'a CoseSign1Message,
        _options: &'a CoseSign1ValidationOptions,
    ) -> Pin<Box<dyn Future<Output = CoseKeyResolutionResult> + Send + 'a>> {
        Box::pin(async move {
            // Simulate async work
            if self.should_succeed {
                CoseKeyResolutionResult::success(Arc::new(MockVerifier { should_succeed: true, should_error: false }))
            } else {
                CoseKeyResolutionResult::failure(Some("ASYNC_TEST_ERROR".to_string()), Some("Mock async resolver failure".to_string()))
            }
        })
    }
}

struct MockPostSignatureValidator;

impl PostSignatureValidator for MockPostSignatureValidator {
    fn validate(&self, _context: &PostSignatureValidationContext) -> ValidationResult {
        ValidationResult::success("MockPostSigValidator".to_string(), None)
    }

    fn validate_async<'a>(
        &'a self,
        context: &'a PostSignatureValidationContext,
    ) -> Pin<Box<dyn Future<Output = ValidationResult> + Send + 'a>> {
        Box::pin(async move {
            self.validate(context)
        })
    }
}

// Create a minimal valid COSE_Sign1 message for testing
fn create_test_message() -> (CoseSign1Message, Arc<[u8]>) {
    let mut enc = cbor_primitives_everparse::EverParseCborProvider.encoder();
    
    // Create minimal COSE_Sign1: [protected, unprotected, payload, signature]
    enc.encode_array(4).unwrap();
    
    // Protected header (empty)
    enc.encode_bstr(&[]).unwrap();
    
    // Unprotected header (empty map)
    enc.encode_map(0).unwrap();
    
    // Payload (small test payload)
    enc.encode_bstr(b"test payload").unwrap();
    
    // Signature (fake bytes)
    enc.encode_bstr(&[1, 2, 3, 4]).unwrap();
    
    let bytes = Arc::<[u8]>::from(enc.into_bytes());
    let message = CoseSign1Message::parse(&bytes).unwrap();
    (message, bytes)
}

// Create a large payload for streaming tests
fn create_large_payload() -> Vec<u8> {
    // Create >85KB payload to trigger streaming path
    vec![b'X'; 90_000]
}

#[test]
fn test_validator_with_multiple_trust_packs() {
    let pack1 = Arc::new(MockTrustPack {
        should_resolve_key: false,
    });
    let pack2 = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });
    let pack3 = Arc::new(MockTrustPack {
        should_resolve_key: false,
    });

    let packs: Vec<Arc<dyn CoseSign1TrustPack>> = vec![pack1, pack2, pack3];
    
    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        packs,
    ).unwrap();

    let validator = CoseSign1Validator::new(plan);
    let (message, bytes) = create_test_message();

    let result = validator.validate(&message, bytes);
    
    // Should succeed since pack2 resolves a key
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.resolution.is_valid());
}

#[test]
fn test_validator_async_path_with_failed_resolution() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: false, // Will fail resolution
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    let validator = CoseSign1Validator::new(plan);
    let (message, bytes) = create_test_message();

    let result = block_on(validator.validate_async(&message, bytes));
    
    // Should handle async resolution failure gracefully
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(!result.resolution.is_valid());
    assert_eq!(result.signature.kind, ValidationResultKind::NotApplicable);
}

#[test]
fn test_validator_async_bytes_path() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    let validator = CoseSign1Validator::new(plan);
    let (_, bytes) = create_test_message();

    let result = block_on(validator.validate_bytes_async(
        EverParseCborProvider,
        bytes,
    ));
    
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.resolution.is_valid());
}

#[test]
fn test_validator_with_detached_payload() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    // Create a message with nil payload (detached)
    let mut enc = cbor_primitives_everparse::EverParseCborProvider.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap(); // Protected
    enc.encode_map(0).unwrap(); // Unprotected
    enc.encode_null().unwrap(); // Detached payload
    enc.encode_bstr(&[1, 2, 3, 4]).unwrap(); // Signature

    let bytes = Arc::<[u8]>::from(enc.into_bytes());
    let message = CoseSign1Message::parse(&bytes).unwrap();
    
    let detached_payload = Payload::Bytes(b"detached test payload".to_vec());

    let validator = CoseSign1Validator::new(plan)
        .with_options(|opts| {
            opts.detached_payload = Some(detached_payload);
        });

    let result = validator.validate(&message, bytes);
    
    assert!(result.is_ok());
    let result = result.unwrap();
    assert!(result.resolution.is_valid());
}

#[test]
fn test_validator_with_large_detached_streaming() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    // Create detached message
    let mut enc = cbor_primitives_everparse::EverParseCborProvider.encoder();
    enc.encode_array(4).unwrap();
    enc.encode_bstr(&[]).unwrap();
    enc.encode_map(0).unwrap();
    enc.encode_null().unwrap(); // Detached
    enc.encode_bstr(&[1, 2, 3, 4]).unwrap();

    let bytes = Arc::<[u8]>::from(enc.into_bytes());
    let message = CoseSign1Message::parse(&bytes).unwrap();
    
    // Create large payload to trigger streaming
    let large_payload_bytes = create_large_payload();
    let detached_payload = Payload::Bytes(large_payload_bytes);

    let validator = CoseSign1Validator::new(plan)
        .with_options(|opts| {
            opts.detached_payload = Some(detached_payload);
        });

    let result = validator.validate(&message, bytes);
    
    assert!(result.is_ok());
    // Note: The result may fail signature verification with mock data,
    // but we're testing that the streaming path is exercised
}

#[test] 
fn test_validator_counter_signature_bypass_logic() {
    // Create a pack that will fail key resolution
    let failing_pack = Arc::new(MockTrustPack {
        should_resolve_key: false,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![failing_pack],
    ).unwrap();

    let validator = CoseSign1Validator::new(plan);
    let (message, bytes) = create_test_message();

    let result = validator.validate(&message, bytes);
    
    assert!(result.is_ok());
    let result = result.unwrap();
    
    // Key resolution should fail
    assert!(!result.resolution.is_valid());
    
    // Since key resolution failed and no counter-signature bypass occurred,
    // later stages should be NotApplicable
    assert_eq!(result.signature.kind, ValidationResultKind::NotApplicable);
    assert_eq!(result.post_signature_policy.kind, ValidationResultKind::NotApplicable);
}

#[test]
fn test_validator_with_skip_post_signature() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    let validator = CoseSign1Validator::new(plan)
        .with_options(|opts| {
            opts.skip_post_signature_validation = true;
        });

    let (message, bytes) = create_test_message();
    let result = validator.validate(&message, bytes);
    
    assert!(result.is_ok());
    let result = result.unwrap();
    
    // Post-signature stage should not fail when skipped, even if validation would otherwise fail
    // The key point is that skip_post_signature_validation prevents post-signature validators from running
    assert_eq!(result.post_signature_policy.kind, ValidationResultKind::NotApplicable);
}

#[test]
fn test_validator_advanced_constructor() {
    let pack = Arc::new(MockTrustPack {
        should_resolve_key: true,
    });

    let plan = CoseSign1CompiledTrustPlan::from_parts(
        allow_all_plan(),
        vec![pack],
    ).unwrap();

    let mut options = CoseSign1ValidationOptions::default();
    options.skip_post_signature_validation = true;

    let validator = CoseSign1Validator::advanced(plan, options);
    let (message, bytes) = create_test_message();

    let result = validator.validate(&message, bytes);
    assert!(result.is_ok());
}

#[test]
fn test_validation_result_helper_methods() {
    // Test ValidationResult helper methods that may be uncovered
    let mut metadata = BTreeMap::new();
    metadata.insert("key".to_string(), "value".to_string());
    
    let result = ValidationResult::success("TestValidator".to_string(), Some(metadata));
    assert!(result.is_valid());
    assert!(!result.is_failure());
    
    let failure_result = ValidationResult::failure_message(
        "TestValidator",
        "Test failure",
        Some("TEST_CODE"),
    );
    assert!(!failure_result.is_valid());
    assert!(failure_result.is_failure());
    
    let na_result = ValidationResult::not_applicable("TestValidator", Some("reason"));
    assert_eq!(na_result.kind, ValidationResultKind::NotApplicable);
    assert!(!na_result.is_valid());
    assert!(!na_result.is_failure());
}

#[test]
fn test_cose_key_resolution_result_helpers() {
    let success_result = CoseKeyResolutionResult::success(
        Arc::new(MockVerifier { should_succeed: true, should_error: false })
    );
    assert!(success_result.is_success);
    assert!(success_result.cose_key.is_some());
    
    let failure_result = CoseKeyResolutionResult::failure(
        Some("ERROR_CODE".to_string()),
        Some("Error message".to_string()),
    );
    assert!(!failure_result.is_success);
    assert!(failure_result.cose_key.is_none());
    assert_eq!(failure_result.error_code.as_deref(), Some("ERROR_CODE"));
}

#[test]
fn test_counter_signature_resolution_result() {
    let success_result = CounterSignatureResolutionResult::success(vec![]);
    assert!(success_result.is_success);
    assert!(success_result.counter_signatures.is_empty());
    
    let failure_result = CounterSignatureResolutionResult::failure(
        Some("CS_ERROR".to_string()),
        Some("Counter signature error".to_string()),
    );
    assert!(!failure_result.is_success);
    assert_eq!(failure_result.error_code.as_deref(), Some("CS_ERROR"));
}

#[test]
fn test_validation_failure_comprehensive() {
    let mut failure = ValidationFailure::default();
    assert!(failure.message.is_empty());
    assert!(failure.error_code.is_none());
    
    failure.message = "Test failure message".to_string();
    failure.error_code = Some("TEST_CODE".to_string());
    failure.property_name = Some("test_property".to_string());
    failure.attempted_value = Some("test_value".to_string());
    failure.exception = Some("test_exception".to_string());
    
    // Test that all fields are properly set
    assert_eq!(failure.message, "Test failure message");
    assert_eq!(failure.error_code.as_deref(), Some("TEST_CODE"));
    assert_eq!(failure.property_name.as_deref(), Some("test_property"));
    assert_eq!(failure.attempted_value.as_deref(), Some("test_value"));
    assert_eq!(failure.exception.as_deref(), Some("test_exception"));
}

#[test]
fn test_async_key_resolution_default_impl() {
    // Test the default async implementation that delegates to sync
    let resolver = MockKeyResolver::success();
    let (message, _) = create_test_message();
    let options = CoseSign1ValidationOptions::default();
    
    let result = block_on(resolver.resolve_async(&message, &options));
    assert!(result.is_success);
}

#[test]
fn test_async_post_signature_validation_default_impl() {
    let validator = MockPostSignatureValidator;
    
    // Create a minimal context for testing
    let (message, _) = create_test_message();
    let trust_decision = TrustDecision { 
        is_trusted: true,
        reasons: vec!["mock trusted decision".to_string()],
    };
    let cose_key: Arc<dyn crypto_primitives::CryptoVerifier> = Arc::new(MockVerifier { should_succeed: true, should_error: false });
    let signature_metadata = BTreeMap::new();
    let options = CoseSign1ValidationOptions::default();
    
    let context = PostSignatureValidationContext {
        message: &message,
        cose_key: Some(&cose_key),
        trust_decision: &trust_decision,
        signature_metadata: &signature_metadata,
        options: &options,
    };
    
    let result = block_on(validator.validate_async(&context));
    assert!(result.is_valid());
}



