// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::any::Any;

use cosesign1_abstractions::{MessageValidationContext, MessageValidator, MessageValidatorError};
use cosesign1_abstractions::ValidationResult;

use crate::{verify_transparent_statement, OfflineEcKeyStore, VerificationOptions};

pub const MST_VALIDATOR_NAME: &str = "mst";
// Stable ID for the MST validator.
// This provides a strong, non-string contract for enabling/configuring the validator.
pub const MST_VALIDATOR_ID: cosesign1_abstractions::MessageValidatorId =
    cosesign1_abstractions::MessageValidatorId(uuid::uuid!("2f6b3181-2e27-43d1-9f7a-6d9dfeb4fe76"));

pub struct MstValidatorOptions {
    pub store: OfflineEcKeyStore,
    pub options: VerificationOptions,
}

struct MstMessageValidator;

impl MessageValidator for MstMessageValidator {
    fn name(&self) -> &'static str {
        MST_VALIDATOR_NAME
    }

    fn validate(
        &self,
        ctx: &MessageValidationContext<'_>,
        options: Option<&(dyn Any + Send + Sync)>,
    ) -> Result<Option<ValidationResult>, MessageValidatorError> {
        let Some(options) = options else {
            // Not configured.
            return Ok(None);
        };

        let opt = options
            .downcast_ref::<MstValidatorOptions>()
            .ok_or_else(|| MessageValidatorError::Message("mst validator options must be MstValidatorOptions".to_string()))?;

        // MST verification validates the receipt signature and binds it to the statement.
        // This does not require trusting the COSE signing key.
        let r = verify_transparent_statement("MST", ctx.cose_bytes, &opt.store, &opt.options);
        Ok(Some(r))
    }
}

static VALIDATOR: MstMessageValidator = MstMessageValidator;

inventory::submit! {
    cosesign1_abstractions::MessageValidatorRegistration {
        id: MST_VALIDATOR_ID,
        name: MST_VALIDATOR_NAME,
        // Run after signature (if enabled), but give it a high priority among message validators.
        priority: 100,
        validator: &VALIDATOR,
    }
}
