// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for MST client operations.

use super::cbor_problem_details::CborProblemDetails;
use std::fmt;

/// Errors that can occur during MST client operations.
#[derive(Debug)]
pub enum MstClientError {
    /// HTTP request failed.
    HttpError(String),
    /// CBOR parsing failed.
    CborParseError(String),
    /// Operation timed out after polling.
    OperationTimeout {
        /// The operation ID that timed out.
        operation_id: String,
        /// Number of retries attempted.
        retries: u32,
    },
    /// Operation failed with an error status.
    OperationFailed {
        /// The operation ID that failed.
        operation_id: String,
        /// The status returned by the service.
        status: String,
    },
    /// Required field missing from response.
    MissingField {
        /// Name of the missing field.
        field: String,
    },
    /// MST service returned an error with structured CBOR problem details (RFC 9290).
    ServiceError {
        /// HTTP status code from the response.
        http_status: u16,
        /// Parsed CBOR problem details, if the response body contained them.
        problem_details: Option<CborProblemDetails>,
        /// Raw error message (fallback when problem details are unavailable).
        message: String,
    },
}

impl MstClientError {
    /// Creates a `ServiceError` from an HTTP response.
    ///
    /// Attempts to parse the response body as RFC 9290 CBOR problem details
    /// when the content type indicates CBOR.
    pub fn from_http_response(
        http_status: u16,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Self {
        let is_cbor = content_type
            .map(|ct| ct.contains("cbor"))
            .unwrap_or(false);

        let problem_details = if is_cbor {
            CborProblemDetails::try_parse(body)
        } else {
            None
        };

        let message = if let Some(ref pd) = problem_details {
            let mut parts = vec![format!("MST service error (HTTP {})", pd.status.unwrap_or(http_status as i64))];
            if let Some(ref title) = pd.title {
                parts.push(format!(": {}", title));
            }
            if let Some(ref detail) = pd.detail {
                if pd.title.as_deref() != Some(detail.as_str()) {
                    parts.push(format!(". {}", detail));
                }
            }
            parts.concat()
        } else {
            format!("MST service returned HTTP {}", http_status)
        };

        MstClientError::ServiceError {
            http_status,
            problem_details,
            message,
        }
    }
}

impl fmt::Display for MstClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MstClientError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            MstClientError::CborParseError(msg) => write!(f, "CBOR parse error: {}", msg),
            MstClientError::OperationTimeout {
                operation_id,
                retries,
            } => {
                write!(
                    f,
                    "Operation {} timed out after {} retries",
                    operation_id, retries
                )
            }
            MstClientError::OperationFailed {
                operation_id,
                status,
            } => {
                write!(
                    f,
                    "Operation {} failed with status: {}",
                    operation_id, status
                )
            }
            MstClientError::MissingField { field } => {
                write!(f, "Missing required field: {}", field)
            }
            MstClientError::ServiceError { message, .. } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for MstClientError {}
