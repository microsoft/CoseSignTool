// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::constants::{
    SAN_TYPE_DNS, SAN_TYPE_EMAIL, SAN_TYPE_URI, SAN_TYPE_DN
};

/// Type of Subject Alternative Name
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SanType {
    /// Email address
    Email,
    /// DNS name
    Dns,
    /// URI
    Uri,
    /// Distinguished Name
    Dn,
}

impl SanType {
    /// Convert SanType to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SanType::Email => SAN_TYPE_EMAIL,
            SanType::Dns => SAN_TYPE_DNS,
            SanType::Uri => SAN_TYPE_URI,
            SanType::Dn => SAN_TYPE_DN,
        }
    }

    /// Parse SanType from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            SAN_TYPE_EMAIL => Some(SanType::Email),
            SAN_TYPE_DNS => Some(SanType::Dns),
            SAN_TYPE_URI => Some(SanType::Uri),
            SAN_TYPE_DN => Some(SanType::Dn),
            _ => None,
        }
    }
}

/// A policy constraint in a DID:x509 identifier
#[derive(Debug, Clone, PartialEq)]
pub enum DidX509Policy {
    /// Extended Key Usage policy with list of OIDs
    Eku(Vec<String>),
    
    /// Subject Distinguished Name policy with key-value pairs
    /// Each tuple is (attribute_label, value), e.g., ("CN", "example.com")
    Subject(Vec<(String, String)>),
    
    /// Subject Alternative Name policy with type and value
    San(SanType, String),
    
    /// Fulcio issuer policy with issuer domain
    FulcioIssuer(String),
}
