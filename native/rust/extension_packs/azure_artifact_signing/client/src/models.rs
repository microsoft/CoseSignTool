// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_core::http::poller::{PollerStatus, StatusMonitor};
use azure_core::http::JsonFormat;
use serde::{Deserialize, Serialize};

/// API version used by this client (from decompiled Azure.CodeSigning.Sdk).
pub const API_VERSION: &str = "2022-06-15-preview";

/// Auth scope suffix.
pub const AUTH_SCOPE_SUFFIX: &str = "/.default";

/// Sign request body (POST /sign).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignRequest {
    pub signature_algorithm: String,
    /// Base64-encoded digest.
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_hash_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticode_hash_list: Option<Vec<String>>,
}

/// Sign operation status (response from GET /sign/{operationId}).
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SignStatus {
    pub operation_id: String,
    pub status: OperationStatus,
    /// Base64-encoded DER signature (present when Succeeded).
    pub signature: Option<String>,
    /// Base64-encoded DER signing certificate (present when Succeeded).
    pub signing_certificate: Option<String>,
}

/// Long-running operation status values.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum OperationStatus {
    InProgress,
    Succeeded,
    Failed,
    TimedOut,
    NotFound,
    Running,
}

impl OperationStatus {
    /// Convert to azure_core's PollerStatus.
    pub fn to_poller_status(&self) -> PollerStatus {
        match self {
            Self::InProgress | Self::Running => PollerStatus::InProgress,
            Self::Succeeded => PollerStatus::Succeeded,
            Self::Failed | Self::TimedOut | Self::NotFound => PollerStatus::Failed,
        }
    }
}

/// Implement `StatusMonitor` so `SignStatus` can be used with `azure_core::http::Poller`.
impl StatusMonitor for SignStatus {
    /// The final output is the `SignStatus` itself (it contains signature + cert when Succeeded).
    type Output = SignStatus;
    type Format = JsonFormat;

    fn status(&self) -> PollerStatus {
        self.status.to_poller_status()
    }
}

/// Error response from the service.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub error_detail: Option<ErrorDetail>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
    pub target: Option<String>,
}

/// Client configuration options.
#[derive(Debug, Clone)]
pub struct CertificateProfileClientOptions {
    pub endpoint: String,
    pub account_name: String,
    pub certificate_profile_name: String,
    pub api_version: String,
    pub correlation_id: Option<String>,
    pub client_version: Option<String>,
}

impl CertificateProfileClientOptions {
    pub fn new(
        endpoint: impl Into<String>,
        account_name: impl Into<String>,
        certificate_profile_name: impl Into<String>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            account_name: account_name.into(),
            certificate_profile_name: certificate_profile_name.into(),
            api_version: API_VERSION.to_string(),
            correlation_id: None,
            client_version: None,
        }
    }

    /// Build the base URL for this profile.
    pub fn base_url(&self) -> String {
        format!(
            "{}/codesigningaccounts/{}/certificateprofiles/{}",
            self.endpoint.trim_end_matches('/'),
            self.account_name,
            self.certificate_profile_name,
        )
    }

    /// Build the auth scope from the endpoint.
    pub fn auth_scope(&self) -> String {
        format!(
            "{}{}",
            self.endpoint.trim_end_matches('/'),
            AUTH_SCOPE_SUFFIX
        )
    }
}

/// Signature algorithm identifiers (matches C# SignatureAlgorithm).
pub struct SignatureAlgorithm;

impl SignatureAlgorithm {
    pub const RS256: &'static str = "RS256";
    pub const RS384: &'static str = "RS384";
    pub const RS512: &'static str = "RS512";
    pub const PS256: &'static str = "PS256";
    pub const PS384: &'static str = "PS384";
    pub const PS512: &'static str = "PS512";
    pub const ES256: &'static str = "ES256";
    pub const ES384: &'static str = "ES384";
    pub const ES512: &'static str = "ES512";
    pub const ES256K: &'static str = "ES256K";
}
