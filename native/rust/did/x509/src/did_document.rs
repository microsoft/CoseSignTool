// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::DidX509Error;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

/// W3C DID Document according to DID Core specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    /// JSON-LD context URL(s)
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// DID identifier
    pub id: String,

    /// Verification methods
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// References to verification methods for assertion
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Vec<String>,
}

/// Verification method in a DID Document
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Verification method identifier
    pub id: String,

    /// Type of verification method (e.g., "JsonWebKey2020")
    #[serde(rename = "type")]
    pub type_: String,

    /// DID of the controller
    pub controller: String,

    /// Public key in JWK format
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: HashMap<Cow<'static, str>, String>,
}

impl DidDocument {
    /// Serialize the DID document to JSON string
    ///
    /// # Arguments
    /// * `indented` - Whether to format the JSON with indentation
    ///
    /// # Returns
    /// JSON string representation of the DID document
    pub fn to_json(&self, indented: bool) -> Result<String, DidX509Error> {
        if indented {
            serde_json::to_string_pretty(self)
        } else {
            serde_json::to_string(self)
        }
        .map_err(|e| DidX509Error::InvalidChain(format!("JSON serialization error: {}", e)))
    }
}
