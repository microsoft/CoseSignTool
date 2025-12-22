// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extensible message validation registry.
//!
//! This is a plugin system for validations that operate on the *message* as a whole,
//! beyond just cryptographic COSE signature verification.

use std::any::Any;

use crate::{OpaqueOptions, ParsedCoseSign1, ValidationResult};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MessageValidatorId(pub uuid::Uuid);

#[derive(thiserror::Error, Debug)]
pub enum MessageValidatorError {
    #[error("{0}")]
    Message(String),
}

/// Context passed to message validators.
pub struct MessageValidationContext<'a> {
    pub cose_bytes: &'a [u8],
    pub parsed: &'a ParsedCoseSign1,
    pub payload_to_verify: Option<&'a [u8]>,
    /// Result of COSE signature verification step, if it ran.
    pub signature_result: Option<&'a ValidationResult>,
}

pub trait MessageValidator: Sync {
    fn name(&self) -> &'static str;

    /// Run validation.
    ///
    /// Return value semantics:
    /// - `Ok(None)`: validator not applicable (or disabled by options).
    /// - `Ok(Some(result))`: validator ran; return a structured result.
    fn validate(
        &self,
        ctx: &MessageValidationContext<'_>,
        options: Option<&(dyn Any + Send + Sync)>,
    ) -> Result<Option<ValidationResult>, MessageValidatorError>;
}

pub struct MessageValidatorRegistration {
    pub id: MessageValidatorId,
    pub name: &'static str,
    pub priority: i32,
    pub validator: &'static dyn MessageValidator,
}

inventory::collect!(MessageValidatorRegistration);

pub fn validators_ordered() -> Vec<&'static MessageValidatorRegistration> {
    let mut regs: Vec<_> = inventory::iter::<MessageValidatorRegistration>.into_iter().collect();
    regs.sort_by(|a, b| b.priority.cmp(&a.priority));
    regs
}

pub fn validator_name(id: MessageValidatorId) -> Option<&'static str> {
    inventory::iter::<MessageValidatorRegistration>
        .into_iter()
        .find(|r| r.id == id)
        .map(|r| r.name)
}

#[derive(thiserror::Error, Debug)]
pub enum RunValidatorError {
    #[error("no validator registered with id '{0}'")]
    NoSuchValidator(uuid::Uuid),

    #[error("validator '{validator}' failed: {error}")]
    ValidatorFailed {
        validator: &'static str,
        error: MessageValidatorError,
    },
}

pub fn run_validator_by_id(
    id: MessageValidatorId,
    ctx: &MessageValidationContext<'_>,
    options: Option<&OpaqueOptions>,
) -> Result<Option<ValidationResult>, RunValidatorError> {
    let Some(reg) = validators_ordered().into_iter().find(|r| r.id == id) else {
        return Err(RunValidatorError::NoSuchValidator(id.0));
    };

    let opts_any = options.map(|o| o.as_any());

    reg.validator
        .validate(ctx, opts_any)
        .map_err(|e| RunValidatorError::ValidatorFailed {
            validator: reg.name,
            error: e,
        })
}
