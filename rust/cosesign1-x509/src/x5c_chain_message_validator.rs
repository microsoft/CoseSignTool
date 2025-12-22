// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::HeaderValue;
use cosesign1_abstractions::{
    MessageValidationContext, MessageValidator, MessageValidatorError, MessageValidatorRegistration,
    ValidationResult,
};

use crate::x5c_verifier::validate_x5c_chain;

struct X5cChainMessageValidator;

impl MessageValidator for X5cChainMessageValidator {
    fn name(&self) -> &'static str {
        crate::X5C_CHAIN_VALIDATOR_NAME
    }

    fn validate(
        &self,
        ctx: &MessageValidationContext<'_>,
        options: Option<&(dyn std::any::Any + Send + Sync)>,
    ) -> Result<Option<ValidationResult>, MessageValidatorError> {
        // Only meaningful if signature verification ran and succeeded.
        let Some(sig) = ctx.signature_result else {
            return Ok(None);
        };
        if !sig.is_valid {
            return Ok(None);
        }

        let Some(options) = options else {
            return Ok(None);
        };

        let chain = options
            .downcast_ref::<crate::X509ChainVerifyOptions>()
            .ok_or_else(|| {
                MessageValidatorError::Message(
                    "x5c_chain validator options must be X509ChainVerifyOptions".to_string(),
                )
            })?;

        // Extract x5c from protected/unprotected headers.
        let x5c = ctx
            .parsed
            .protected_headers
            .get_array(33)
            .or_else(|| ctx.parsed.unprotected_headers.get_array(33));

        let Some(x5c) = x5c else {
            // Not applicable: no x5c header.
            return Ok(None);
        };

        let mut certs_der: Vec<Vec<u8>> = Vec::new();
        for v in x5c {
            match v {
                HeaderValue::Bytes(b) => certs_der.push(b.clone()),
                _ => {
                    return Err(MessageValidatorError::Message(
                        "x5c must be array of bstr".to_string(),
                    ))
                }
            }
        }

        Ok(Some(validate_x5c_chain(
            "X509Chain",
            &certs_der,
            chain,
        )))
    }
}

static VALIDATOR: X5cChainMessageValidator = X5cChainMessageValidator;

inventory::submit! {
    MessageValidatorRegistration {
        id: crate::X5C_CHAIN_VALIDATOR_ID,
        name: crate::X5C_CHAIN_VALIDATOR_NAME,
        // Prefer running chain validation early.
        priority: 100,
        validator: &VALIDATOR,
    }
}
