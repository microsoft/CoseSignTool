// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::facts::{
    typed_fields as akv_typed, AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact,
};
use cose_sign1_validation_trust::fluent::{MessageScope, ScopeRules, Where};

pub trait AzureKeyVaultKidDetectedWhereExt {
    fn require_azure_key_vault_kid(self) -> Self;
    fn require_not_azure_key_vault_kid(self) -> Self;
}

impl AzureKeyVaultKidDetectedWhereExt for Where<AzureKeyVaultKidDetectedFact> {
    fn require_azure_key_vault_kid(self) -> Self {
        self.r#true(akv_typed::akv_kid_detected::IS_AZURE_KEY_VAULT_KEY)
    }

    fn require_not_azure_key_vault_kid(self) -> Self {
        self.r#false(akv_typed::akv_kid_detected::IS_AZURE_KEY_VAULT_KEY)
    }
}

pub trait AzureKeyVaultKidAllowedWhereExt {
    fn require_kid_allowed(self) -> Self;
    fn require_kid_not_allowed(self) -> Self;
}

impl AzureKeyVaultKidAllowedWhereExt for Where<AzureKeyVaultKidAllowedFact> {
    fn require_kid_allowed(self) -> Self {
        self.r#true(akv_typed::akv_kid_allowed::IS_ALLOWED)
    }

    fn require_kid_not_allowed(self) -> Self {
        self.r#false(akv_typed::akv_kid_allowed::IS_ALLOWED)
    }
}

/// Fluent helper methods for message-scope rules.
///
/// These are intentionally "one click down" from `TrustPlanBuilder::for_message(...)`.
pub trait AzureKeyVaultMessageScopeRulesExt {
    fn require_azure_key_vault_kid(self) -> Self;
    fn require_azure_key_vault_kid_allowed(self) -> Self;
}

impl AzureKeyVaultMessageScopeRulesExt for ScopeRules<MessageScope> {
    fn require_azure_key_vault_kid(self) -> Self {
        self.require::<AzureKeyVaultKidDetectedFact>(|w| w.require_azure_key_vault_kid())
    }

    fn require_azure_key_vault_kid_allowed(self) -> Self {
        self.require::<AzureKeyVaultKidAllowedFact>(|w| w.require_kid_allowed())
    }
}
