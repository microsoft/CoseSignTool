// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JWKS (JSON Web Key Set) model for Code Transparency receipt signing keys.
//!
//! Port of C# `Azure.Security.CodeTransparency.JwksDocument`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A JSON Web Key (JWK) as returned by the Code Transparency `/jwks` endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonWebKey {
    /// Key type (e.g. `"EC"`, `"RSA"`).
    pub kty: String,
    /// Key ID.
    #[serde(default)]
    pub kid: String,
    /// Curve name for EC keys (e.g. `"P-256"`, `"P-384"`).
    #[serde(default)]
    pub crv: Option<String>,
    /// X coordinate (base64url, EC keys).
    #[serde(default)]
    pub x: Option<String>,
    /// Y coordinate (base64url, EC keys).
    #[serde(default)]
    pub y: Option<String>,
    /// Additional fields not explicitly modeled.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

/// A JSON Web Key Set document as returned by the Code Transparency `/jwks` endpoint.
///
/// Port of C# `Azure.Security.CodeTransparency.JwksDocument`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwksDocument {
    /// The keys in this key set.
    pub keys: Vec<JsonWebKey>,
}

impl JwksDocument {
    /// Parse a JWKS JSON string into a `JwksDocument`.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("failed to parse JWKS: {}", e))
    }

    /// Look up a key by `kid`. Returns `None` if not found.
    pub fn find_key(&self, kid: &str) -> Option<&JsonWebKey> {
        self.keys.iter().find(|k| k.kid == kid)
    }

    /// Returns true if this document contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}
