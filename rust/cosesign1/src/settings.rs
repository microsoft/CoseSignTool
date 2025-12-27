// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;

pub struct SignatureVerificationSettings {
    _private: (),
}

impl SignatureVerificationSettings {
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for SignatureVerificationSettings {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VerificationSettings {
    /// If true, verify the COSE signature. If false, skip signature verification.
    ///
    /// This is useful for verification models that do not require trusting the COSE signing key,
    /// such as receipt-based verification (e.g., MST), where the receipt binds to the statement.
    pub(crate) require_cose_signature: bool,

    pub(crate) signature: SignatureVerificationSettings,

    /// Validators to run, by ID.
    ///
    /// Validator crates should export a stable `MessageValidatorId` constant (e.g. `cosesign1_mst::MST_VALIDATOR_ID`)
    /// so consumers never need to type a string.
    pub(crate) enabled_validators: Vec<cosesign1_abstractions::MessageValidatorId>,

    /// Options for message validators, keyed by validator ID.
    pub(crate) validator_options: HashMap<
        cosesign1_abstractions::MessageValidatorId,
        cosesign1_abstractions::OpaqueOptions,
    >,
}

impl VerificationSettings {
    /// Skip cryptographic COSE signature verification.
    ///
    /// This is useful for receipt/attestation-based verification models (e.g., MST)
    /// where trust does not come from the COSE signing key.
    pub fn without_cose_signature(mut self) -> Self {
        self.require_cose_signature = false;
        self
    }

    /// Add a message validator by ID.
    pub fn with_validator(mut self, id: cosesign1_abstractions::MessageValidatorId) -> Self {
        if !self.enabled_validators.contains(&id) {
            self.enabled_validators.push(id);
        }
        self
    }

    /// Configure a message validator (options) in one call.
    ///
    /// Intended usage is a single one-liner with a validator helper, e.g.:
    /// `settings.with_validator_options(cosesign1_mst::mst_message_validation_options(store, opt))`
    pub fn with_validator_options(
        mut self,
        opt: (
            cosesign1_abstractions::MessageValidatorId,
            cosesign1_abstractions::OpaqueOptions,
        ),
    ) -> Self {
        self.validator_options.insert(opt.0, opt.1);
        self.with_validator(opt.0)
    }
}

impl Default for VerificationSettings {
    fn default() -> Self {
        Self {
            require_cose_signature: true,
            signature: Default::default(),
            enabled_validators: Vec::new(),
            validator_options: HashMap::new(),
        }
    }
}
