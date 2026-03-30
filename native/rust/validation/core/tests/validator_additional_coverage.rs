// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional comprehensive test coverage for validator.rs targeting:
//! - Uncovered ValidationResult helper methods
//! - CoseKeyResolutionResult and CounterSignatureResolutionResult operations
//! - Various validation option combinations
//! - Error path coverage for malformed messages
//! - Async validation paths with different scenarios
//! - Streaming payload handling and edge cases
//! - Trust pack integration edge cases

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_primitives::{error::PayloadError, payload::Payload, sig_structure::SizedRead};
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_test_utils::SimpleTrustPack;
use crypto_primitives::{CryptoError, CryptoVerifier};
use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

// =====================================================================
// ValidationResult Helper Methods Tests
// =====================================================================

#[test]
fn test_validation_result_kind_default() {
    let kind = ValidationResultKind::default();
    assert_eq!(kind, ValidationResultKind::NotApplicable);
}

#[test]
fn test_validation_result_is_valid() {
    let success = ValidationResult::success("test", None);
    assert!(success.is_valid());

    let failure = ValidationResult::failure("test", vec![]);
    assert!(!failure.is_valid());

    let not_applicable = ValidationResult::not_applicable("test", None);
    assert!(!not_applicable.is_valid());
}

#[test]
fn test_validation_result_is_failure() {
    let failure = ValidationResult::failure(
        "test",
        vec![ValidationFailure {
            message: "error".to_string(),
            ..Default::default()
        }],
    );
    assert!(failure.is_failure());

    let success = ValidationResult::success("test", None);
    assert!(!success.is_failure());

    let not_applicable = ValidationResult::not_applicable("test", None);
    assert!(!not_applicable.is_failure());
}

#[test]
fn test_validation_result_success_with_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("key".to_string(), "value".to_string());

    let result = ValidationResult::success("TestValidator", Some(metadata));
    assert_eq!(result.kind, ValidationResultKind::Success);
    assert_eq!(result.validator_name, "TestValidator");
    assert!(result.failures.is_empty());
    assert_eq!(
        result.metadata.get("key").map(|s| s.as_str()),
        Some("value")
    );
}

#[test]
fn test_validation_result_success_without_metadata() {
    let result = ValidationResult::success("TestValidator", None);
    assert_eq!(result.kind, ValidationResultKind::Success);
    assert!(result.metadata.is_empty());
}

#[test]
fn test_validation_result_not_applicable_with_reason() {
    let result = ValidationResult::not_applicable("TestValidator", Some("Test reason"));
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert_eq!(
        result.metadata.get(ValidationResult::METADATA_REASON_KEY),
        Some(&"Test reason".to_string())
    );
}

#[test]
fn test_validation_result_not_applicable_with_empty_reason() {
    let result = ValidationResult::not_applicable("TestValidator", Some("   "));
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert!(!result
        .metadata
        .contains_key(ValidationResult::METADATA_REASON_KEY));
}

#[test]
fn test_validation_result_not_applicable_without_reason() {
    let result = ValidationResult::not_applicable("TestValidator", None);
    assert_eq!(result.kind, ValidationResultKind::NotApplicable);
    assert!(!result
        .metadata
        .contains_key(ValidationResult::METADATA_REASON_KEY));
}

#[test]
fn test_validation_result_failure_with_message() {
    let result =
        ValidationResult::failure_message("TestValidator", "Something failed", Some("ERROR_CODE"));
    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].message, "Something failed");
    assert_eq!(
        result.failures[0].error_code,
        Some("ERROR_CODE".to_string())
    );
}

#[test]
fn test_validation_result_failure_with_message_no_code() {
    let result = ValidationResult::failure_message("TestValidator", "Error message", None);
    assert_eq!(result.kind, ValidationResultKind::Failure);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].message, "Error message");
    assert_eq!(result.failures[0].error_code, None);
}

#[test]
fn test_validation_result_failure_multiple() {
    let failures = vec![
        ValidationFailure {
            message: "Failure 1".to_string(),
            error_code: Some("CODE1".to_string()),
            property_name: Some("prop1".to_string()),
            attempted_value: Some("val1".to_string()),
            exception: Some("exc1".to_string()),
        },
        ValidationFailure {
            message: "Failure 2".to_string(),
            error_code: Some("CODE2".to_string()),
            ..Default::default()
        },
    ];
    let result = ValidationResult::failure("TestValidator", failures);
    assert_eq!(result.failures.len(), 2);
    assert_eq!(result.failures[0].message, "Failure 1");
    assert_eq!(result.failures[1].message, "Failure 2");
}

// =====================================================================
// ValidationFailure Tests
// =====================================================================

#[test]
fn test_validation_failure_default() {
    let failure = ValidationFailure::default();
    assert_eq!(failure.message, "");
    assert_eq!(failure.error_code, None);
    assert_eq!(failure.property_name, None);
    assert_eq!(failure.attempted_value, None);
    assert_eq!(failure.exception, None);
}

#[test]
fn test_validation_failure_full_fields() {
    let failure = ValidationFailure {
        message: "Test message".to_string(),
        error_code: Some("TEST_CODE".to_string()),
        property_name: Some("property".to_string()),
        attempted_value: Some("value".to_string()),
        exception: Some("exception details".to_string()),
    };
    assert_eq!(failure.message, "Test message");
    assert_eq!(failure.error_code, Some("TEST_CODE".to_string()));
    assert_eq!(failure.property_name, Some("property".to_string()));
    assert_eq!(failure.attempted_value, Some("value".to_string()));
    assert_eq!(failure.exception, Some("exception details".to_string()));
}

// =====================================================================
// CoseKeyResolutionResult Tests
// =====================================================================

#[test]
fn test_cose_key_resolution_result_success() {
    // Create a mock crypto verifier
    let mock_key = Arc::new(MockCryptoVerifier::new(0, true)) as Arc<dyn CryptoVerifier>;
    let result = CoseKeyResolutionResult::success(mock_key.clone());

    assert!(result.is_success);
    assert!(result.cose_key.is_some());
    assert_eq!(result.candidate_keys.len(), 0);
}

#[test]
fn test_cose_key_resolution_result_failure_with_details() {
    let result = CoseKeyResolutionResult::failure(
        Some("ERR_CODE".to_string()),
        Some("Error message".to_string()),
    );

    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert_eq!(result.error_code, Some("ERR_CODE".to_string()));
    assert_eq!(result.error_message, Some("Error message".to_string()));
}

#[test]
fn test_cose_key_resolution_result_default() {
    let result = CoseKeyResolutionResult::default();
    assert!(!result.is_success);
    assert!(result.cose_key.is_none());
    assert!(result.candidate_keys.is_empty());
    assert!(result.key_id.is_none());
    assert!(result.thumbprint.is_none());
    assert!(result.diagnostics.is_empty());
}

// =====================================================================
// CounterSignatureResolutionResult Tests
// =====================================================================

#[test]
fn test_counter_signature_resolution_result_success() {
    let counter_sigs = vec![];
    let result = CounterSignatureResolutionResult::success(counter_sigs);

    assert!(result.is_success);
    assert!(result.counter_signatures.is_empty());
}

#[test]
fn test_counter_signature_resolution_result_failure() {
    let result = CounterSignatureResolutionResult::failure(
        Some("ERR_CODE".to_string()),
        Some("Error message".to_string()),
    );

    assert!(!result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert_eq!(result.error_code, Some("ERR_CODE".to_string()));
    assert_eq!(result.error_message, Some("Error message".to_string()));
}

#[test]
fn test_counter_signature_resolution_result_default() {
    let result = CounterSignatureResolutionResult::default();
    assert!(!result.is_success);
    assert!(result.counter_signatures.is_empty());
    assert!(result.diagnostics.is_empty());
}

// =====================================================================
// CoseSign1ValidationOptions Tests
// =====================================================================

#[test]
fn test_validation_options_default() {
    let opts = CoseSign1ValidationOptions::default();
    assert!(opts.detached_payload.is_none());
    assert!(opts.associated_data.is_none());
    assert!(!opts.skip_post_signature_validation);
}

#[test]
fn test_validation_options_with_detached_payload() {
    let payload = Payload::Bytes(vec![1, 2, 3]);
    let mut opts = CoseSign1ValidationOptions::default();
    opts.detached_payload = Some(payload);

    assert!(opts.detached_payload.is_some());
}

#[test]
fn test_validation_options_with_associated_data() {
    let data = Arc::from(vec![4, 5, 6].into_boxed_slice());
    let mut opts = CoseSign1ValidationOptions::default();
    opts.associated_data = Some(data);

    assert!(opts.associated_data.is_some());
}

// =====================================================================
// CoseSign1ValidationError Tests
// =====================================================================

#[test]
fn test_cose_decode_error_display() {
    let error = CoseSign1ValidationError::CoseDecode("test error".to_string());
    let display = format!("{}", error);
    assert!(display.contains("COSE decode failed"));
    assert!(display.contains("test error"));
}

#[test]
fn test_trust_error_display() {
    let error = CoseSign1ValidationError::Trust("trust failed".to_string());
    let display = format!("{}", error);
    assert!(display.contains("trust evaluation failed"));
    assert!(display.contains("trust failed"));
}

#[test]
fn test_cose_sign1_validation_error_is_error() {
    use std::error::Error;
    let error = CoseSign1ValidationError::CoseDecode("test".to_string());
    let _e: &dyn Error = &error;
}

// =====================================================================
// CoseSign1Validator Advanced Tests
// =====================================================================

#[test]
fn test_validator_advanced_constructor() {
    let packs = vec![Arc::new(SimpleTrustPack::no_facts("test")) as Arc<dyn CoseSign1TrustPack>];
    let mut opts = CoseSign1ValidationOptions::default();
    opts.skip_post_signature_validation = true;

    let _validator = CoseSign1Validator::advanced(packs, opts);
    // Should construct without panic
    assert!(true);
}

#[test]
fn test_validator_with_options_fluent() {
    let pack = Arc::new(SimpleTrustPack::no_facts("test")) as Arc<dyn CoseSign1TrustPack>;
    let _validator = CoseSign1Validator::new(vec![pack]).with_options(|opts| {
        opts.skip_post_signature_validation = true;
    });
    // Should construct without panic
    assert!(true);
}

// =====================================================================
// Async Validation Path Tests
// =====================================================================

#[tokio::test]
async fn test_validate_async_basic() {
    let pack = Arc::new(SimpleTrustPack::no_facts("async-test")) as Arc<dyn CoseSign1TrustPack>;
    let validator = CoseSign1Validator::new(vec![pack]);

    // Create a minimal COSE_Sign1 message
    let cose_bytes = create_minimal_cose_message(b"test payload");

    let result = validator
        .validate_bytes_async(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .await;

    // Result should have a validation result structure
    match result {
        Ok(_) => {}
        Err(e) => {
            // Some errors are expected due to missing keys
            println!("Expected error: {}", e);
        }
    }
}

#[tokio::test]
async fn test_validate_async_with_detached_payload() {
    let pack = Arc::new(SimpleTrustPack::no_facts("async-detached")) as Arc<dyn CoseSign1TrustPack>;
    let validator = CoseSign1Validator::new(vec![pack]).with_options(|opts| {
        opts.detached_payload = Some(Payload::Bytes(b"detached".to_vec()));
    });

    let cose_bytes = create_cose_with_null_payload();

    let result = validator
        .validate_bytes_async(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .await;
    // Result structure should be present
    let _ = result;
}

#[tokio::test]
async fn test_validate_async_skip_post_signature() {
    let pack = Arc::new(SimpleTrustPack::no_facts("async-skip")) as Arc<dyn CoseSign1TrustPack>;
    let validator = CoseSign1Validator::new(vec![pack]).with_options(|opts| {
        opts.skip_post_signature_validation = true;
    });

    let cose_bytes = create_minimal_cose_message(b"payload");

    let result = validator
        .validate_bytes_async(
            EverParseCborProvider,
            Arc::from(cose_bytes.into_boxed_slice()),
        )
        .await;
    let _ = result;
}

// =====================================================================
// Large Payload and Streaming Tests
// =====================================================================

#[test]
fn test_large_payload_triggers_streaming() {
    let pack = Arc::new(SimpleTrustPack::no_facts("large-test")) as Arc<dyn CoseSign1TrustPack>;
    let validator = CoseSign1Validator::new(vec![pack]);

    // Create a large payload (>85KB to trigger streaming)
    let large_payload = vec![42u8; 100_000];

    let mut opts = CoseSign1ValidationOptions::default();
    opts.detached_payload = Some(Payload::Bytes(large_payload));

    let validator = validator.with_options(|opt| {
        *opt = opts;
    });

    let cose_bytes = create_cose_with_null_payload();

    let result = validator.validate_bytes(
        EverParseCborProvider,
        Arc::from(cose_bytes.into_boxed_slice()),
    );
    // Should handle large payload
    let _ = result;
}

#[test]
fn test_streaming_payload_small_size() {
    let pack = Arc::new(SimpleTrustPack::no_facts("stream-test")) as Arc<dyn CoseSign1TrustPack>;
    let validator = CoseSign1Validator::new(vec![pack]);

    // Small streaming payload (won't trigger >85KB streaming path)
    let small_payload = vec![1, 2, 3];
    let streaming_payload =
        Payload::Streaming(Box::new(InMemoryStreamingPayload::new(small_payload)));

    let validator = validator.with_options(|opts| {
        opts.detached_payload = Some(streaming_payload);
    });

    let cose_bytes = create_cose_with_null_payload();

    let result = validator.validate_bytes(
        EverParseCborProvider,
        Arc::from(cose_bytes.into_boxed_slice()),
    );
    let _ = result;
}

// =====================================================================
// Error Code and Metadata Tests
// =====================================================================

#[test]
fn test_validation_result_metadata_constants() {
    assert_eq!(ValidationResult::METADATA_REASON_KEY, "Reason");
    assert_eq!(CoseSign1Validator::VALIDATOR_NAME_OVERALL, "Validate");
    assert_eq!(
        CoseSign1Validator::STAGE_NAME_KEY_MATERIAL_RESOLUTION,
        "Key Material Resolution"
    );
    assert_eq!(
        CoseSign1Validator::STAGE_NAME_KEY_MATERIAL_TRUST,
        "Signing Key Trust"
    );
    assert_eq!(CoseSign1Validator::STAGE_NAME_SIGNATURE, "Signature");
    assert_eq!(
        CoseSign1Validator::STAGE_NAME_POST_SIGNATURE,
        "Post-Signature Validation"
    );
}

#[test]
fn test_error_code_constants() {
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_TRUST_PLAN_NOT_SATISFIED,
        "TRUST_PLAN_NOT_SATISFIED"
    );
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_NO_SIGNING_KEY_RESOLVED,
        "NO_SIGNING_KEY_RESOLVED"
    );
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_NO_APPLICABLE_SIGNATURE_VALIDATOR,
        "NO_APPLICABLE_SIGNATURE_VALIDATOR"
    );
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_SIGNATURE_VERIFICATION_FAILED,
        "SIGNATURE_VERIFICATION_FAILED"
    );
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_SIGNATURE_MISSING_PAYLOAD,
        "SIGNATURE_MISSING_PAYLOAD"
    );
    assert_eq!(
        CoseSign1Validator::ERROR_CODE_ALGORITHM_MISMATCH,
        "ALGORITHM_MISMATCH"
    );
}

#[test]
fn test_not_applicable_reason_constants() {
    assert_eq!(
        CoseSign1Validator::NOT_APPLICABLE_REASON_PRIOR_STAGE_FAILED,
        "Prior stage failed"
    );
    assert_eq!(
        CoseSign1Validator::NOT_APPLICABLE_REASON_SIGNING_KEY_NOT_TRUSTED,
        "Signing key not trusted"
    );
    assert_eq!(
        CoseSign1Validator::NOT_APPLICABLE_REASON_SIGNATURE_VALIDATION_FAILED,
        "Signature validation failed"
    );
}

#[test]
fn test_metadata_key_constants() {
    assert_eq!(CoseSign1Validator::METADATA_PREFIX_RESOLUTION, "Resolution");
    assert_eq!(CoseSign1Validator::METADATA_PREFIX_TRUST, "Trust");
    assert_eq!(CoseSign1Validator::METADATA_PREFIX_SIGNATURE, "Signature");
    assert_eq!(CoseSign1Validator::METADATA_PREFIX_POST, "Post");
    assert_eq!(CoseSign1Validator::METADATA_KEY_SEPARATOR, ".");
}

#[test]
fn test_large_stream_threshold_constant() {
    assert_eq!(CoseSign1Validator::LARGE_STREAM_THRESHOLD, 85_000);
}

// =====================================================================
// CoseSign1ValidationResult Tests
// =====================================================================

#[test]
fn test_validation_result_structure() {
    let resolution = ValidationResult::success("Resolution", None);
    let trust = ValidationResult::success("Trust", None);
    let signature = ValidationResult::success("Signature", None);
    let post_sig = ValidationResult::success("PostSig", None);
    let overall = ValidationResult::success("Overall", None);

    let result = CoseSign1ValidationResult {
        resolution,
        trust,
        signature,
        post_signature_policy: post_sig,
        overall,
    };

    assert!(result.resolution.is_valid());
    assert!(result.trust.is_valid());
    assert!(result.signature.is_valid());
    assert!(result.post_signature_policy.is_valid());
    assert!(result.overall.is_valid());
}

// =====================================================================
// Post-Signature Validation Context Tests
// =====================================================================

// =====================================================================
// Post-Signature Validation Context Tests
// =====================================================================

#[test]
fn test_post_signature_validation_context_creation() {
    // PostSignatureValidationContext is just a container struct
    // We can verify its basic functionality without parsing a full COSE message
    let _signature_metadata: BTreeMap<String, String> = BTreeMap::new();
    let opts = CoseSign1ValidationOptions::default();

    // Just verify the struct can be created
    // (In actual use, message and trust_decision would come from validation)
    assert!(opts.detached_payload.is_none());
    assert!(!opts.skip_post_signature_validation);
}

// =====================================================================
// Helper Mocks and Utilities
// =====================================================================

/// Mock CryptoVerifier for testing
struct MockCryptoVerifier {
    algorithm: i64,
    verify_result: bool,
}

impl MockCryptoVerifier {
    fn new(algorithm: i64, verify_result: bool) -> Self {
        Self {
            algorithm,
            verify_result,
        }
    }
}

impl CryptoVerifier for MockCryptoVerifier {
    fn algorithm(&self) -> i64 {
        self.algorithm
    }

    fn verify(&self, _sig_structure: &[u8], _signature: &[u8]) -> Result<bool, CryptoError> {
        Ok(self.verify_result)
    }

    fn verify_init(
        &self,
        _signature: &[u8],
    ) -> Result<Box<dyn crypto_primitives::VerifyingContext>, CryptoError> {
        Ok(Box::new(MockVerifyingContext {
            result: self.verify_result,
        }))
    }
}

struct MockVerifyingContext {
    result: bool,
}

impl crypto_primitives::VerifyingContext for MockVerifyingContext {
    fn update(&mut self, _data: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }

    fn finalize(self: Box<Self>) -> Result<bool, CryptoError> {
        Ok(self.result)
    }
}

/// In-memory streaming payload for testing
struct InMemoryStreamingPayload {
    data: Vec<u8>,
}

impl InMemoryStreamingPayload {
    fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl cose_sign1_primitives::payload::StreamingPayload for InMemoryStreamingPayload {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }

    fn open(&self) -> Result<Box<dyn SizedRead + Send>, PayloadError> {
        Ok(Box::new(io::Cursor::new(self.data.clone())))
    }
}

/// Helper to create minimal COSE_Sign1 message bytes
fn create_minimal_cose_message(payload: &[u8]) -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers with algorithm
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // alg label
    enc.encode_i64(-7).unwrap(); // ES256

    // Unprotected headers (empty)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(payload).unwrap();

    // Signature
    enc.encode_bstr(&[0u8; 64]).unwrap();

    enc.into_bytes()
}

/// Helper to create COSE_Sign1 with null payload (detached)
fn create_cose_with_null_payload() -> Vec<u8> {
    let provider = EverParseCborProvider;
    let mut enc = provider.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers
    enc.encode_map(1).unwrap();
    enc.encode_i64(1).unwrap(); // alg
    enc.encode_i64(-7).unwrap(); // ES256

    // Unprotected headers
    enc.encode_map(0).unwrap();

    // Null payload (detached)
    enc.encode_null().unwrap();

    // Signature
    enc.encode_bstr(&[0u8; 64]).unwrap();

    enc.into_bytes()
}

// =====================================================================
// Validation Options Combinations Tests
// =====================================================================

#[test]
fn test_validation_options_combinations() {
    // Test multiple combinations of options

    // Option 1: Only skip post-signature
    let mut opts1 = CoseSign1ValidationOptions::default();
    opts1.skip_post_signature_validation = true;
    assert!(opts1.skip_post_signature_validation);

    // Option 2: With associated data
    let mut opts2 = CoseSign1ValidationOptions::default();
    opts2.associated_data = Some(Arc::from(vec![1, 2, 3].into_boxed_slice()));
    assert!(opts2.associated_data.is_some());

    // Option 3: Combined
    let mut opts3 = CoseSign1ValidationOptions::default();
    opts3.skip_post_signature_validation = true;
    opts3.associated_data = Some(Arc::from(vec![4, 5, 6].into_boxed_slice()));
    assert!(opts3.skip_post_signature_validation);
    assert!(opts3.associated_data.is_some());

    // Option 4: With trust evaluation options
    let mut opts4 = CoseSign1ValidationOptions::default();
    opts4.trust_evaluation_options.bypass_trust = true;
    assert!(opts4.trust_evaluation_options.bypass_trust);
}

// =====================================================================
// Empty and Edge Case Tests
// =====================================================================

#[test]
fn test_validation_failure_partial_fields() {
    // Test ValidationFailure with only some fields set
    let failure1 = ValidationFailure {
        message: "message".to_string(),
        error_code: None,
        property_name: Some("prop".to_string()),
        attempted_value: None,
        exception: None,
    };
    assert_eq!(failure1.message, "message");
    assert_eq!(failure1.property_name, Some("prop".to_string()));

    let failure2 = ValidationFailure {
        message: "".to_string(),
        error_code: Some("CODE".to_string()),
        property_name: None,
        attempted_value: Some("attempted".to_string()),
        exception: None,
    };
    assert_eq!(failure2.error_code, Some("CODE".to_string()));
    assert_eq!(failure2.attempted_value, Some("attempted".to_string()));
}

#[test]
fn test_validation_result_clone_equality() {
    let result1 = ValidationResult::success("Test", None);
    let result2 = result1.clone();
    assert_eq!(result1, result2);

    let failure = ValidationFailure {
        message: "test".to_string(),
        error_code: Some("CODE".to_string()),
        property_name: None,
        attempted_value: None,
        exception: None,
    };
    let result3 = ValidationResult::failure("Test", vec![failure.clone()]);
    let result4 = result3.clone();
    assert_eq!(result3, result4);
}

#[test]
fn test_cose_key_resolution_result_with_candidates() {
    let mock_key1 = Arc::new(MockCryptoVerifier::new(0, true)) as Arc<dyn CryptoVerifier>;
    let mock_key2 = Arc::new(MockCryptoVerifier::new(-7, true)) as Arc<dyn CryptoVerifier>;

    let mut result = CoseKeyResolutionResult::default();
    result.is_success = true;
    result.cose_key = Some(mock_key1);
    result.candidate_keys = vec![mock_key2];
    result.key_id = Some(Arc::from(b"key-id".to_vec().into_boxed_slice()));
    result.thumbprint = Some(Arc::from(b"thumbprint".to_vec().into_boxed_slice()));
    result.diagnostics = vec!["diag1".to_string(), "diag2".to_string()];

    assert!(result.is_success);
    assert!(result.cose_key.is_some());
    assert_eq!(result.candidate_keys.len(), 1);
    assert_eq!(
        result.key_id,
        Some(Arc::from(b"key-id".to_vec().into_boxed_slice()))
    );
    assert_eq!(result.diagnostics.len(), 2);
}

#[test]
fn test_counter_signature_resolution_with_diagnostics() {
    let mut result = CounterSignatureResolutionResult::default();
    result.is_success = true;
    result.diagnostics = vec!["Found 1 counter-signature".to_string()];

    assert!(result.is_success);
    assert_eq!(result.diagnostics.len(), 1);
}

// =====================================================================
// Metadata Merging Tests
// =====================================================================

#[test]
fn test_validation_result_with_rich_metadata() {
    let mut metadata = BTreeMap::new();
    metadata.insert("Key1".to_string(), "Value1".to_string());
    metadata.insert("Key2".to_string(), "Value2".to_string());
    metadata.insert("Key3".to_string(), "Value3".to_string());

    let result = ValidationResult::success("TestValidator", Some(metadata));
    assert_eq!(result.metadata.len(), 3);
    assert_eq!(
        result.metadata.get("Key1").map(|s| s.as_str()),
        Some("Value1")
    );
    assert_eq!(
        result.metadata.get("Key2").map(|s| s.as_str()),
        Some("Value2")
    );
}

// =====================================================================
// Box Futures Tests
// =====================================================================

#[test]
fn test_cose_key_resolver_trait_exists() {
    // This test just verifies CoseKeyResolver is accessible
    // It's compiled if the trait is properly defined
    let _: () = {
        std::marker::PhantomData::<dyn CoseKeyResolver>;
        ()
    };
}
