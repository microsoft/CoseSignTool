// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureKeyVaultKidDetectedFact {
    pub is_azure_key_vault_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AzureKeyVaultKidAllowedFact {
    pub is_allowed: bool,
    pub details: Option<String>,
}

/// Field-name constants for declarative trust policies.
pub mod fields {
    pub mod akv_kid_detected {
        pub const IS_AZURE_KEY_VAULT_KEY: &str = "is_azure_key_vault_key";
    }

    pub mod akv_kid_allowed {
        pub const IS_ALLOWED: &str = "is_allowed";
    }
}

/// Typed fields for fluent trust-policy authoring.
pub mod typed_fields {
    use super::{AzureKeyVaultKidAllowedFact, AzureKeyVaultKidDetectedFact};
    use cose_sign1_validation_trust::field::Field;

    pub mod akv_kid_detected {
        use super::*;
        pub const IS_AZURE_KEY_VAULT_KEY: Field<AzureKeyVaultKidDetectedFact, bool> =
            Field::new(crate::facts::fields::akv_kid_detected::IS_AZURE_KEY_VAULT_KEY);
    }

    pub mod akv_kid_allowed {
        use super::*;
        pub const IS_ALLOWED: Field<AzureKeyVaultKidAllowedFact, bool> =
            Field::new(crate::facts::fields::akv_kid_allowed::IS_ALLOWED);
    }
}

impl FactProperties for AzureKeyVaultKidDetectedFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "is_azure_key_vault_key" => Some(FactValue::Bool(self.is_azure_key_vault_key)),
            _ => None,
        }
    }
}

impl FactProperties for AzureKeyVaultKidAllowedFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "is_allowed" => Some(FactValue::Bool(self.is_allowed)),
            _ => None,
        }
    }
}
