// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ATS-specific trust facts.

use cose_sign1_validation_primitives::fact_properties::{FactProperties, FactValue};
use std::borrow::Cow;

/// Whether the signing certificate was issued by Azure Trusted Signing.
#[derive(Debug, Clone)]
pub struct AtsSigningServiceIdentifiedFact {
    pub is_ats_issued: bool,
    pub issuer_cn: Option<String>,
    pub eku_oids: Vec<String>,
}

impl FactProperties for AtsSigningServiceIdentifiedFact {
    fn get_property(&self, name: &str) -> Option<FactValue<'_>> {
        match name {
            "is_ats_issued" => Some(FactValue::Bool(self.is_ats_issued)),
            "issuer_cn" => self.issuer_cn.as_deref().map(|s| FactValue::Str(Cow::Borrowed(s))),
            _ => None,
        }
    }
}

/// FIPS/SCITT compliance markers for ATS-issued certificates.
#[derive(Debug, Clone)]
pub struct AtsComplianceFact {
    pub fips_level: String,
    pub scitt_compliant: bool,
}

impl FactProperties for AtsComplianceFact {
    fn get_property(&self, name: &str) -> Option<FactValue<'_>> {
        match name {
            "fips_level" => Some(FactValue::Str(Cow::Borrowed(&self.fips_level))),
            "scitt_compliant" => Some(FactValue::Bool(self.scitt_compliant)),
            _ => None,
        }
    }
}