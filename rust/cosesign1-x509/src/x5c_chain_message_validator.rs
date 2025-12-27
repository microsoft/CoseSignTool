// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::{
    MessageValidationContext, MessageValidator, MessageValidatorError, MessageValidatorRegistration,
    ValidationResult,
};

use crate::x5c_header::extract_x5c_certs_der;
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

        let Some(certs_der) = extract_x5c_certs_der(ctx.parsed) else {
            // Not applicable: no x5c header.
            return Ok(None);
        };

        let certs_der = certs_der.map_err(MessageValidatorError::Message)?;

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
