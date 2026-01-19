// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptPresentFact {
    pub present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptTrustedFact {
    pub trusted: bool,
    pub details: Option<String>,
}

/// The receipt issuer (`iss`) extracted from the MST receipt claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptIssuerFact {
    pub issuer: String,
}

/// The receipt signing key id (`kid`) used to resolve the receipt signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptKidFact {
    pub kid: String,
}

/// SHA-256 digest of the statement bytes that the MST verifier binds the receipt to.
///
/// The current MST verifier computes this over the COSE_Sign1 statement re-encoded
/// with *all* unprotected headers cleared (matching the Azure .NET verifier).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptStatementSha256Fact {
    pub sha256_hex: String,
}

/// Describes what bytes are covered by the statement digest that the receipt binds to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptStatementCoverageFact {
    pub coverage: String,
}

/// Indicates whether the receipt's own COSE signature verified.
///
/// Note: in the current verifier, this is only observed as `true` when the verifier returns
/// success; failures are represented via `MstReceiptTrustedFact { trusted: false, details: ... }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MstReceiptSignatureVerifiedFact {
    pub verified: bool,
}

/// Field-name constants for declarative trust policies.
pub mod fields {
    pub mod mst_receipt_present {
        pub const PRESENT: &str = "present";
    }

    pub mod mst_receipt_trusted {
        pub const TRUSTED: &str = "trusted";
    }

    pub mod mst_receipt_issuer {
        pub const ISSUER: &str = "issuer";
    }

    pub mod mst_receipt_kid {
        pub const KID: &str = "kid";
    }

    pub mod mst_receipt_statement_sha256 {
        pub const SHA256_HEX: &str = "sha256_hex";
    }

    pub mod mst_receipt_statement_coverage {
        pub const COVERAGE: &str = "coverage";
    }

    pub mod mst_receipt_signature_verified {
        pub const VERIFIED: &str = "verified";
    }
}

/// Typed fields for fluent trust-policy authoring.
pub mod typed_fields {
    use super::{
        MstReceiptIssuerFact, MstReceiptKidFact, MstReceiptPresentFact,
        MstReceiptSignatureVerifiedFact, MstReceiptStatementCoverageFact,
        MstReceiptStatementSha256Fact, MstReceiptTrustedFact,
    };
    use cose_sign1_validation_trust::field::Field;

    pub mod mst_receipt_present {
        use super::*;
        pub const PRESENT: Field<MstReceiptPresentFact, bool> =
            Field::new(crate::facts::fields::mst_receipt_present::PRESENT);
    }

    pub mod mst_receipt_trusted {
        use super::*;
        pub const TRUSTED: Field<MstReceiptTrustedFact, bool> =
            Field::new(crate::facts::fields::mst_receipt_trusted::TRUSTED);
    }

    pub mod mst_receipt_issuer {
        use super::*;
        pub const ISSUER: Field<MstReceiptIssuerFact, String> =
            Field::new(crate::facts::fields::mst_receipt_issuer::ISSUER);
    }

    pub mod mst_receipt_kid {
        use super::*;
        pub const KID: Field<MstReceiptKidFact, String> =
            Field::new(crate::facts::fields::mst_receipt_kid::KID);
    }

    pub mod mst_receipt_statement_sha256 {
        use super::*;
        pub const SHA256_HEX: Field<MstReceiptStatementSha256Fact, String> =
            Field::new(crate::facts::fields::mst_receipt_statement_sha256::SHA256_HEX);
    }

    pub mod mst_receipt_statement_coverage {
        use super::*;
        pub const COVERAGE: Field<MstReceiptStatementCoverageFact, String> =
            Field::new(crate::facts::fields::mst_receipt_statement_coverage::COVERAGE);
    }

    pub mod mst_receipt_signature_verified {
        use super::*;
        pub const VERIFIED: Field<MstReceiptSignatureVerifiedFact, bool> =
            Field::new(crate::facts::fields::mst_receipt_signature_verified::VERIFIED);
    }
}

impl FactProperties for MstReceiptPresentFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "present" => Some(FactValue::Bool(self.present)),
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptTrustedFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "trusted" => Some(FactValue::Bool(self.trusted)),
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptIssuerFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::mst_receipt_issuer::ISSUER => {
                Some(FactValue::Str(Cow::Borrowed(self.issuer.as_str())))
            }
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptKidFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::mst_receipt_kid::KID => Some(FactValue::Str(Cow::Borrowed(self.kid.as_str()))),
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptStatementSha256Fact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::mst_receipt_statement_sha256::SHA256_HEX => {
                Some(FactValue::Str(Cow::Borrowed(self.sha256_hex.as_str())))
            }
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptStatementCoverageFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::mst_receipt_statement_coverage::COVERAGE => {
                Some(FactValue::Str(Cow::Borrowed(self.coverage.as_str())))
            }
            _ => None,
        }
    }
}

impl FactProperties for MstReceiptSignatureVerifiedFact {
    /// Return the property value for declarative trust policies.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            fields::mst_receipt_signature_verified::VERIFIED => {
                Some(FactValue::Bool(self.verified))
            }
            _ => None,
        }
    }
}
