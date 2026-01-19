// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation_trust::fact_properties::{FactProperties, FactValue};
use std::borrow::Cow;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SigningCertificateIdentityFact {
    pub certificate_thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}

/// Field-name constants for declarative trust policies.
pub mod fields {
    pub mod x509_signing_certificate_identity {
        pub const CERTIFICATE_THUMBPRINT: &str = "certificate_thumbprint";
        pub const SUBJECT: &str = "subject";
        pub const ISSUER: &str = "issuer";
        pub const SERIAL_NUMBER: &str = "serial_number";
        pub const NOT_BEFORE_UNIX_SECONDS: &str = "not_before_unix_seconds";
        pub const NOT_AFTER_UNIX_SECONDS: &str = "not_after_unix_seconds";
    }

    pub mod x509_chain_element_identity {
        pub const INDEX: &str = "index";
        pub const CERTIFICATE_THUMBPRINT: &str = "certificate_thumbprint";
        pub const SUBJECT: &str = "subject";
        pub const ISSUER: &str = "issuer";
    }

    pub mod x509_chain_element_validity {
        pub const INDEX: &str = "index";
        pub const NOT_BEFORE_UNIX_SECONDS: &str = "not_before_unix_seconds";
        pub const NOT_AFTER_UNIX_SECONDS: &str = "not_after_unix_seconds";
    }

    pub mod x509_chain_trusted {
        pub const CHAIN_BUILT: &str = "chain_built";
        pub const IS_TRUSTED: &str = "is_trusted";
        pub const STATUS_FLAGS: &str = "status_flags";
        pub const STATUS_SUMMARY: &str = "status_summary";
        pub const ELEMENT_COUNT: &str = "element_count";
    }

    pub mod x509_public_key_algorithm {
        pub const CERTIFICATE_THUMBPRINT: &str = "certificate_thumbprint";
        pub const ALGORITHM_OID: &str = "algorithm_oid";
        pub const ALGORITHM_NAME: &str = "algorithm_name";
        pub const IS_PQC: &str = "is_pqc";
    }
}

/// Typed fields for fluent trust-policy authoring.
///
/// These are the compile-time checked building blocks that replace stringly-typed property names.
pub mod typed_fields {
    use super::{
        X509ChainElementIdentityFact, X509ChainElementValidityFact, X509ChainTrustedFact,
        X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
    };
    use cose_sign1_validation_trust::field::Field;

    pub mod x509_chain_trusted {
        use super::*;
        pub const IS_TRUSTED: Field<X509ChainTrustedFact, bool> =
            Field::new(crate::facts::fields::x509_chain_trusted::IS_TRUSTED);
        pub const CHAIN_BUILT: Field<X509ChainTrustedFact, bool> =
            Field::new(crate::facts::fields::x509_chain_trusted::CHAIN_BUILT);
        pub const ELEMENT_COUNT: Field<X509ChainTrustedFact, usize> =
            Field::new(crate::facts::fields::x509_chain_trusted::ELEMENT_COUNT);

        pub const STATUS_FLAGS: Field<X509ChainTrustedFact, u32> =
            Field::new(crate::facts::fields::x509_chain_trusted::STATUS_FLAGS);
    }

    pub mod x509_chain_element_identity {
        use super::*;
        pub const INDEX: Field<X509ChainElementIdentityFact, usize> =
            Field::new(crate::facts::fields::x509_chain_element_identity::INDEX);
        pub const CERTIFICATE_THUMBPRINT: Field<X509ChainElementIdentityFact, String> =
            Field::new(crate::facts::fields::x509_chain_element_identity::CERTIFICATE_THUMBPRINT);
        pub const SUBJECT: Field<X509ChainElementIdentityFact, String> =
            Field::new(crate::facts::fields::x509_chain_element_identity::SUBJECT);
        pub const ISSUER: Field<X509ChainElementIdentityFact, String> =
            Field::new(crate::facts::fields::x509_chain_element_identity::ISSUER);
    }

    pub mod x509_signing_certificate_identity {
        use super::*;
        pub const CERTIFICATE_THUMBPRINT: Field<X509SigningCertificateIdentityFact, String> =
            Field::new(
                crate::facts::fields::x509_signing_certificate_identity::CERTIFICATE_THUMBPRINT,
            );
        pub const SUBJECT: Field<X509SigningCertificateIdentityFact, String> =
            Field::new(crate::facts::fields::x509_signing_certificate_identity::SUBJECT);
        pub const ISSUER: Field<X509SigningCertificateIdentityFact, String> =
            Field::new(crate::facts::fields::x509_signing_certificate_identity::ISSUER);

        pub const SERIAL_NUMBER: Field<X509SigningCertificateIdentityFact, String> =
            Field::new(crate::facts::fields::x509_signing_certificate_identity::SERIAL_NUMBER);

        pub const NOT_BEFORE_UNIX_SECONDS: Field<X509SigningCertificateIdentityFact, i64> =
            Field::new(crate::facts::fields::x509_signing_certificate_identity::NOT_BEFORE_UNIX_SECONDS);
        pub const NOT_AFTER_UNIX_SECONDS: Field<X509SigningCertificateIdentityFact, i64> =
            Field::new(crate::facts::fields::x509_signing_certificate_identity::NOT_AFTER_UNIX_SECONDS);
    }

    pub mod x509_chain_element_validity {
        use super::*;
        pub const INDEX: Field<X509ChainElementValidityFact, usize> =
            Field::new(crate::facts::fields::x509_chain_element_validity::INDEX);
        pub const NOT_BEFORE_UNIX_SECONDS: Field<X509ChainElementValidityFact, i64> = Field::new(
            crate::facts::fields::x509_chain_element_validity::NOT_BEFORE_UNIX_SECONDS,
        );
        pub const NOT_AFTER_UNIX_SECONDS: Field<X509ChainElementValidityFact, i64> =
            Field::new(crate::facts::fields::x509_chain_element_validity::NOT_AFTER_UNIX_SECONDS);
    }

    pub mod x509_public_key_algorithm {
        use super::*;
        pub const IS_PQC: Field<X509PublicKeyAlgorithmFact, bool> =
            Field::new(crate::facts::fields::x509_public_key_algorithm::IS_PQC);
        pub const ALGORITHM_OID: Field<X509PublicKeyAlgorithmFact, String> =
            Field::new(crate::facts::fields::x509_public_key_algorithm::ALGORITHM_OID);

        pub const CERTIFICATE_THUMBPRINT: Field<X509PublicKeyAlgorithmFact, String> =
            Field::new(crate::facts::fields::x509_public_key_algorithm::CERTIFICATE_THUMBPRINT);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SigningCertificateIdentityAllowedFact {
    pub certificate_thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub is_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SigningCertificateEkuFact {
    pub certificate_thumbprint: String,
    pub oid_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SigningCertificateKeyUsageFact {
    pub certificate_thumbprint: String,
    pub usages: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SigningCertificateBasicConstraintsFact {
    pub certificate_thumbprint: String,
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509X5ChainCertificateIdentityFact {
    pub certificate_thumbprint: String,
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509ChainElementIdentityFact {
    pub index: usize,
    pub certificate_thumbprint: String,
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509ChainElementValidityFact {
    pub index: usize,
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509ChainTrustedFact {
    pub chain_built: bool,
    pub is_trusted: bool,
    pub status_flags: u32,
    pub status_summary: Option<String>,
    pub element_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSigningKeyTrustFact {
    pub thumbprint: String,
    pub subject: String,
    pub issuer: String,
    pub chain_built: bool,
    pub chain_trusted: bool,
    pub chain_status_flags: u32,
    pub chain_status_summary: Option<String>,
}

/// Fact capturing the public key algorithm OID; this stays robust for PQC/unknown algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509PublicKeyAlgorithmFact {
    pub certificate_thumbprint: String,
    pub algorithm_oid: String,
    pub algorithm_name: Option<String>,
    pub is_pqc: bool,
}

impl FactProperties for X509SigningCertificateIdentityFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "certificate_thumbprint" => Some(FactValue::Str(Cow::Borrowed(
                self.certificate_thumbprint.as_str(),
            ))),
            "subject" => Some(FactValue::Str(Cow::Borrowed(self.subject.as_str()))),
            "issuer" => Some(FactValue::Str(Cow::Borrowed(self.issuer.as_str()))),
            "serial_number" => Some(FactValue::Str(Cow::Borrowed(self.serial_number.as_str()))),
            "not_before_unix_seconds" => Some(FactValue::I64(self.not_before_unix_seconds)),
            "not_after_unix_seconds" => Some(FactValue::I64(self.not_after_unix_seconds)),
            _ => None,
        }
    }
}

impl FactProperties for X509ChainElementIdentityFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "index" => Some(FactValue::Usize(self.index)),
            "certificate_thumbprint" => Some(FactValue::Str(Cow::Borrowed(
                self.certificate_thumbprint.as_str(),
            ))),
            "subject" => Some(FactValue::Str(Cow::Borrowed(self.subject.as_str()))),
            "issuer" => Some(FactValue::Str(Cow::Borrowed(self.issuer.as_str()))),
            _ => None,
        }
    }
}

impl FactProperties for X509ChainElementValidityFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "index" => Some(FactValue::Usize(self.index)),
            "not_before_unix_seconds" => Some(FactValue::I64(self.not_before_unix_seconds)),
            "not_after_unix_seconds" => Some(FactValue::I64(self.not_after_unix_seconds)),
            _ => None,
        }
    }
}

impl FactProperties for X509ChainTrustedFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "chain_built" => Some(FactValue::Bool(self.chain_built)),
            "is_trusted" => Some(FactValue::Bool(self.is_trusted)),
            "status_flags" => Some(FactValue::U32(self.status_flags)),
            "element_count" => Some(FactValue::Usize(self.element_count)),
            "status_summary" => self
                .status_summary
                .as_ref()
                .map(|v| FactValue::Str(Cow::Borrowed(v.as_str()))),
            _ => None,
        }
    }
}

impl FactProperties for X509PublicKeyAlgorithmFact {
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>> {
        match name {
            "certificate_thumbprint" => Some(FactValue::Str(Cow::Borrowed(
                self.certificate_thumbprint.as_str(),
            ))),
            "algorithm_oid" => Some(FactValue::Str(Cow::Borrowed(self.algorithm_oid.as_str()))),
            "algorithm_name" => self
                .algorithm_name
                .as_ref()
                .map(|v| FactValue::Str(Cow::Borrowed(v.as_str()))),
            "is_pqc" => Some(FactValue::Bool(self.is_pqc)),
            _ => None,
        }
    }
}

/// Internal helper: certificate DER plus parsed identity.
#[derive(Debug, Clone)]
pub(crate) struct ParsedCert {
    pub der: Arc<Vec<u8>>,
    pub thumbprint_sha1_hex: String,
    pub subject: String,
    pub issuer: String,
    pub serial_hex: String,
    pub not_before_unix_seconds: i64,
    pub not_after_unix_seconds: i64,
}
