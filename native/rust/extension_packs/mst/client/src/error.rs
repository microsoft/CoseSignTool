// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error types for MST client operations.

use crate::cbor_problem_details::CborProblemDetails;
use std::fmt;

/// Errors that can occur during MST client operations.
#[derive(Debug)]
pub enum CodeTransparencyError {
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

impl CodeTransparencyError {
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

        CodeTransparencyError::ServiceError {
            http_status,
            problem_details,
            message,
        }
    }

    /// Creates an `CodeTransparencyError` from an `azure_core::Error`.
    ///
    /// When the error is an `HttpResponse` (non-2xx status from the pipeline's
    /// `check_success`), extracts the status code and body to create a
    /// `ServiceError` with parsed CBOR problem details. Other error kinds
    /// become `HttpError`.
    pub fn from_azure_error(error: azure_core::Error) -> Self {
        if let azure_core::error::ErrorKind::HttpResponse { status, raw_response, .. } = error.kind() {
            let http_status = u16::from(*status);
            if let Some(raw) = raw_response {
                let ct = raw.headers().get_optional_string(
                    &azure_core::http::headers::CONTENT_TYPE,
                );
                let body = raw.body().as_ref();
                return Self::from_http_response(http_status, ct.as_deref(), body);
            }
            return CodeTransparencyError::ServiceError {
                http_status,
                problem_details: None,
                message: format!("MST service returned HTTP {}", http_status),
            };
        }
        CodeTransparencyError::HttpError(error.to_string())
    }
}

impl fmt::Display for CodeTransparencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeTransparencyError::HttpError(msg) => write!(f, "HTTP error: {}", msg),
            CodeTransparencyError::CborParseError(msg) => write!(f, "CBOR parse error: {}", msg),
            CodeTransparencyError::OperationTimeout {
                operation_id,
                retries,
            } => {
                write!(
                    f,
                    "Operation {} timed out after {} retries",
                    operation_id, retries
                )
            }
            CodeTransparencyError::OperationFailed {
                operation_id,
                status,
            } => {
                write!(
                    f,
                    "Operation {} failed with status: {}",
                    operation_id, status
                )
            }
            CodeTransparencyError::MissingField { field } => {
                write!(f, "Missing required field: {}", field)
            }
            CodeTransparencyError::ServiceError { message, .. } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for CodeTransparencyError {}
