// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::SanType;

/// A Subject Alternative Name from an X.509 certificate
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectAlternativeName {
    /// The type of SAN
    pub san_type: SanType,

    /// The value of the SAN
    pub value: String,
}

impl SubjectAlternativeName {
    /// Create a new SubjectAlternativeName
    pub fn new(san_type: SanType, value: String) -> Self {
        Self { san_type, value }
    }

    /// Create an email SAN
    pub fn email(value: String) -> Self {
        Self::new(SanType::Email, value)
    }

    /// Create a DNS SAN
    pub fn dns(value: String) -> Self {
        Self::new(SanType::Dns, value)
    }

    /// Create a URI SAN
    pub fn uri(value: String) -> Self {
        Self::new(SanType::Uri, value)
    }

    /// Create a DN SAN
    pub fn dn(value: String) -> Self {
        Self::new(SanType::Dn, value)
    }
}
