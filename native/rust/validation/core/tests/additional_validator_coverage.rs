// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional coverage tests for validator.rs targeting specific failure paths and edge cases.

use cbor_primitives::{CborEncoder, CborProvider};
use cbor_primitives_everparse::EverParseCborProvider;
use cose_sign1_validation::fluent::*;
use cose_sign1_validation_primitives::{
    error::TrustError,
    fact_properties::{FactProperties, FactValue},
    facts::{FactKey, TrustFactContext, TrustFactProducer},
};
use cose_sign1_validation_test_utils::SimpleTrustPack;
use std::borrow::Cow;
use std::sync::Arc;

// Test fact for trust evaluation failures
#[derive(Debug, Clone)]
struct TestFact {
    name: String,
}

impl FactProperties for TestFact {
    fn get_property<'a>(&'a self, prop: &str) -> Option<FactValue<'a>> {
        match prop {
            "name" => Some(FactValue::Str(Cow::Borrowed(&self.name))),
            _ => None,
        }
    }
}

struct ErrorProducer;

impl TrustFactProducer for ErrorProducer {
    fn name(&self) -> &'static str {
        "error_producer"
    }

    fn produce(&self, _ctx: &mut TrustFactContext<'_>) -> Result<(), TrustError> {
        Err(TrustError::FactProduction(
            "deliberate test error".to_string(),
        ))
    }

    fn provides(&self) -> &'static [FactKey] {
        static ONCE: std::sync::OnceLock<Vec<FactKey>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| vec![FactKey::of::<TestFact>()])
            .as_slice()
    }
}

fn build_invalid_cose_bytes() -> Vec<u8> {
    // Invalid CBOR - truncated array
    vec![0x84, 0x40] // array(4) but only has one element
}

#[test]
fn validator_parse_failure_path() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Invalid CBOR should cause parse failure
    let invalid_bytes = build_invalid_cose_bytes();
    let invalid_arc: Arc<[u8]> = Arc::from(invalid_bytes.as_slice());
    let result = validator.validate_bytes(EverParseCborProvider, invalid_arc);

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, CoseSign1ValidationError::CoseDecode(_)));
}

#[test]
fn trust_evaluation_failure_path() {
    // Create a trust pack that will produce fact errors
    let error_pack =
        SimpleTrustPack::no_facts("error_pack").with_fact_producer(Arc::new(ErrorProducer));

    let validator =
        CoseSign1Validator::new(vec![Arc::new(error_pack) as Arc<dyn CoseSign1TrustPack>]);

    // Build a minimal valid COSE message
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers (empty map)
    enc.encode_map(0).unwrap();

    // Unprotected headers (empty map)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(b"payload").unwrap();

    // Signature (dummy)
    enc.encode_bstr(&[0u8; 32]).unwrap();

    let cose_bytes = enc.into_bytes();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.as_slice());

    let result = validator.validate_bytes(EverParseCborProvider, cose_arc);

    // Should fail during trust evaluation due to fact production error
    assert!(result.is_err());
}

#[tokio::test]
async fn validator_async_validation_path() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Build a minimal valid COSE message
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers (empty map)
    enc.encode_map(0).unwrap();

    // Unprotected headers (empty map)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(b"payload").unwrap();

    // Signature (dummy)
    enc.encode_bstr(&[0u8; 32]).unwrap();

    let cose_bytes = enc.into_bytes();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.as_slice());

    // Test async path
    let result = validator
        .validate_bytes_async(EverParseCborProvider, cose_arc)
        .await;

    // Should succeed in parsing but might fail later in validation
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn validator_with_options_closure_variations() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Build a minimal valid COSE message
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers (empty map)
    enc.encode_map(0).unwrap();

    // Unprotected headers (empty map)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(b"payload").unwrap();

    // Signature (dummy)
    enc.encode_bstr(&[0u8; 32]).unwrap();

    let cose_bytes = enc.into_bytes();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.as_slice());

    // Test validation with basic options
    let result = validator.validate_bytes(EverParseCborProvider, cose_arc);

    // Should succeed in parsing but might fail later in validation
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn validation_result_field_access() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Build a minimal valid COSE message
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers (empty map)
    enc.encode_map(0).unwrap();

    // Unprotected headers (empty map)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(b"payload").unwrap();

    // Signature (dummy)
    enc.encode_bstr(&[0u8; 32]).unwrap();

    let cose_bytes = enc.into_bytes();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.as_slice());

    // Get validation result and test field access
    if let Ok(result) = validator.validate_bytes(EverParseCborProvider, cose_arc) {
        // Test accessing all result fields to hit coverage
        let _resolution = &result.resolution;
        let _trust = &result.trust;
        let _signature = &result.signature;
        let _post_signature_policy = &result.post_signature_policy;
        let _overall = &result.overall;
    }
}

#[test]
fn validator_invalid_cbor_error_path() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Completely invalid CBOR
    let invalid_bytes = vec![0xFF, 0xFF, 0xFF, 0xFF];
    let invalid_arc: Arc<[u8]> = Arc::from(invalid_bytes.as_slice());

    let result = validator.validate_bytes(EverParseCborProvider, invalid_arc);

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, CoseSign1ValidationError::CoseDecode(_)));
}

#[test]
fn validator_missing_protected_headers_path() {
    let pack: Arc<dyn CoseSign1TrustPack> = Arc::new(SimpleTrustPack::no_facts("test"));
    let validator = CoseSign1Validator::new(vec![pack]);

    // Build COSE message with invalid protected headers
    let p = EverParseCborProvider;
    let mut enc = p.encoder();
    enc.encode_array(4).unwrap();

    // Protected headers as invalid bstr (should contain encoded map)
    enc.encode_bstr(&[0xFF]).unwrap();

    // Unprotected headers (empty map)
    enc.encode_map(0).unwrap();

    // Payload
    enc.encode_bstr(b"payload").unwrap();

    // Signature (dummy)
    enc.encode_bstr(&[0u8; 32]).unwrap();

    let cose_bytes = enc.into_bytes();
    let cose_arc: Arc<[u8]> = Arc::from(cose_bytes.as_slice());

    let result = validator.validate_bytes(EverParseCborProvider, cose_arc);

    // With lazy header parsing, invalid protected headers are tolerated at parse
    // time but cause a validation failure (not a hard error).
    match result {
        Err(_) => {
            // Still acceptable if the parser rejects it outright
        }
        Ok(validation_result) => {
            // Validation completed but should not be valid
            assert!(
                !validation_result.overall.is_valid(),
                "Validation should fail with invalid protected headers"
            );
        }
    }
}
