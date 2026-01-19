// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    typed_fields as akv_typed, AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_validation_trust::fluent::{MessageScope, ScopeRules, Where};

pub trait AzureKeyVaultKidDetectedWhereExt {
    /// Require that the message `kid` looks like an Azure Key Vault key identifier.
    fn require_azure_key_vault_kid(self) -> Self;

    /// Require that the message `kid` does not look like an Azure Key Vault key identifier.
    fn require_not_azure_key_vault_kid(self) -> Self;
}

impl AzureKeyVaultKidDetectedWhereExt for Where<AzureKeyVaultKidDetectedFact> {
    /// Require that the message `kid` looks like an Azure Key Vault key identifier.
    fn require_azure_key_vault_kid(self) -> Self {
        self.r#true(akv_typed::akv_kid_detected::IS_AZURE_KEY_VAULT_KEY)
    }

    /// Require that the message `kid` does not look like an Azure Key Vault key identifier.
    fn require_not_azure_key_vault_kid(self) -> Self {
        self.r#false(akv_typed::akv_kid_detected::IS_AZURE_KEY_VAULT_KEY)
    }
}

pub trait AzureKeyVaultKidAllowedWhereExt {
    /// Require that the message `kid` is allowlisted by the AKV pack configuration.
    fn require_kid_allowed(self) -> Self;

    /// Require that the message `kid` is not allowlisted by the AKV pack configuration.
    fn require_kid_not_allowed(self) -> Self;
}

impl AzureKeyVaultKidAllowedWhereExt for Where<AzureKeyVaultKidAllowedFact> {
    /// Require that the message `kid` is allowlisted by the AKV pack configuration.
    fn require_kid_allowed(self) -> Self {
        self.r#true(akv_typed::akv_kid_allowed::IS_ALLOWED)
    }

    /// Require that the message `kid` is not allowlisted by the AKV pack configuration.
    fn require_kid_not_allowed(self) -> Self {
        self.r#false(akv_typed::akv_kid_allowed::IS_ALLOWED)
    }
}

/// Fluent helper methods for message-scope rules.
///
/// These are intentionally "one click down" from `TrustPlanBuilder::for_message(...)`.
pub trait AzureKeyVaultMessageScopeRulesExt {
    /// Require that the message `kid` looks like an Azure Key Vault key identifier.
    fn require_azure_key_vault_kid(self) -> Self;

    /// Require that the message `kid` is allowlisted by the AKV pack configuration.
    fn require_azure_key_vault_kid_allowed(self) -> Self;
}

impl AzureKeyVaultMessageScopeRulesExt for ScopeRules<MessageScope> {
    /// Require that the message `kid` looks like an Azure Key Vault key identifier.
    fn require_azure_key_vault_kid(self) -> Self {
        self.require::<AzureKeyVaultKidDetectedFact>(|w| w.require_azure_key_vault_kid())
    }

    /// Require that the message `kid` is allowlisted by the AKV pack configuration.
    fn require_azure_key_vault_kid_allowed(self) -> Self {
        self.require::<AzureKeyVaultKidAllowedFact>(|w| w.require_kid_allowed())
    }
}
