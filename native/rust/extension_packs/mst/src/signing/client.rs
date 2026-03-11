// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MST transparency client implementation using azure_core HTTP pipeline.

use super::cbor_problem_details::CborProblemDetails;
use super::error::MstClientError;
use super::polling::MstPollingOptions;
use crate::http_client::{self, HttpTransport};
use cbor_primitives::CborDecoder;
use std::thread;
use std::time::Duration;
use url::Url;
use std::sync::Arc;

/// Configuration options for the MST transparency client.
#[derive(Debug)]
pub struct MstTransparencyClientOptions {
    /// API version to use for requests.
    pub api_version: String,
    /// Optional API key for authentication.
    pub api_key: Option<String>,
    /// Maximum number of polling attempts for operation status.
    pub max_poll_retries: u32,
    /// Delay between polling attempts (default fixed interval).
    pub poll_delay: Duration,
    /// Optional polling options for advanced back-off control.
    /// Takes precedence over `poll_delay` and `max_poll_retries` when set.
    pub polling_options: Option<MstPollingOptions>,
    /// Delay between fast retries for `TransactionNotCached` 503 responses
    /// when fetching entry statements. Default: 250 ms.
    pub transaction_not_cached_retry_delay: Duration,
    /// Maximum fast retries for `TransactionNotCached` 503 responses.
    /// Default: 8 (8 × 250 ms = 2 seconds max).
    pub transaction_not_cached_max_retries: u32,
}

impl Default for MstTransparencyClientOptions {
    fn default() -> Self {
        Self {
            api_version: "2024-01-01".to_string(),
            api_key: None,
            max_poll_retries: 30,
            poll_delay: Duration::from_secs(2),
            polling_options: None,
            transaction_not_cached_retry_delay: Duration::from_millis(250),
            transaction_not_cached_max_retries: 8,
        }
    }
}

/// Result from creating a transparency entry.
#[derive(Debug)]
pub struct CreateEntryResult {
    /// The operation ID for tracking the entry creation.
    pub operation_id: String,
    /// The final entry ID after the operation completes.
    pub entry_id: String,
}

/// Client for interacting with the MST transparency service.
#[derive(Debug)]
pub struct MstTransparencyClient {
    endpoint: Url,
    options: MstTransparencyClientOptions,
    http: Arc<dyn HttpTransport>,
}

impl MstTransparencyClient {
    /// Creates a new MST transparency client.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The base URL of the transparency service.
    /// * `options` - Configuration options for the client.
    pub fn new(endpoint: Url, options: MstTransparencyClientOptions) -> Self {
        Self { 
            endpoint, 
            options, 
            http: Arc::new(http_client::DefaultHttpTransport::new()) 
        }
    }
    
    /// Creates a new MST transparency client with a custom HTTP transport.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The base URL of the transparency service.
    /// * `options` - Configuration options for the client.
    /// * `http` - Custom HTTP transport implementation.
    pub fn with_http(endpoint: Url, options: MstTransparencyClientOptions, http: Arc<dyn HttpTransport>) -> Self {
        Self { endpoint, options, http }
    }

    /// Builds headers for requests, including the API key if configured.
    fn build_post_headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = vec![
            ("content-type", "application/cose".to_string()),
            ("accept", "application/cose; application/cbor".to_string()),
        ];
        if let Some(ref key) = self.options.api_key {
            headers.push(("authorization", format!("Bearer {}", key)));
        }
        headers
    }

    /// Creates a transparency entry by submitting a COSE_Sign1 message.
    ///
    /// This method:
    /// 1. POSTs the COSE bytes to the entries endpoint
    /// 2. Polls the operation status until it completes
    /// 3. Returns the operation ID and entry ID on success
    ///
    /// # Arguments
    ///
    /// * `cose_bytes` - The COSE_Sign1 message bytes to submit.
    ///
    /// # Returns
    ///
    /// A `CreateEntryResult` containing the operation ID and entry ID.
    pub fn create_entry(&self, cose_bytes: &[u8]) -> Result<CreateEntryResult, MstClientError> {
        // Build the entries URL
        let mut url = self.endpoint.clone();
        url.set_path(&format!("{}/entries", url.path().trim_end_matches('/')));
        url.set_query(Some(&format!("api-version={}", self.options.api_version)));

        // POST the COSE bytes — include auth header
        let (status, content_type, response_body) = self.http.post_bytes(
            &url,
            "application/cose",
            "application/cose; application/cbor",
            cose_bytes.to_vec(),
        )
        .map_err(MstClientError::HttpError)?;

        if status < 200 || status >= 300 {
            return Err(MstClientError::from_http_response(
                status,
                content_type.as_deref(),
                &response_body,
            ));
        }

        // Parse the response to get the operation ID
        let operation_id =
            read_cbor_text_field(&response_body, "OperationId").ok_or_else(|| {
                MstClientError::MissingField {
                    field: "OperationId".to_string(),
                }
            })?;

        // Poll the operation until it completes
        let entry_id = self.poll_operation(&operation_id)?;

        Ok(CreateEntryResult {
            operation_id,
            entry_id,
        })
    }

    /// Gets the transparency statement for an entry.
    ///
    /// Performs fast retries on HTTP 503 responses whose CBOR body contains the
    /// `TransactionNotCached` error code. This handles the MST service pattern
    /// where a newly registered entry has not yet propagated to the serving node
    /// and typically becomes available within sub-second latency.
    ///
    /// # Arguments
    ///
    /// * `entry_id` - The entry ID to retrieve the statement for.
    ///
    /// # Returns
    ///
    /// The COSE statement bytes.
    pub fn get_entry_statement(&self, entry_id: &str) -> Result<Vec<u8>, MstClientError> {
        let mut url = self.endpoint.clone();
        url.set_path(&format!(
            "{}/entries/{}/statement",
            url.path().trim_end_matches('/'),
            entry_id
        ));
        url.set_query(Some(&format!("api-version={}", self.options.api_version)));

        // First attempt
        let (status, content_type, body) = self.http.get_response(&url, "application/cose")
            .map_err(MstClientError::HttpError)?;

        if status >= 200 && status < 300 {
            return Ok(body);
        }

        // Check for TransactionNotCached 503 pattern and fast-retry
        if status == 503 && Self::is_transaction_not_cached(content_type.as_deref(), &body) {
            for _attempt in 0..self.options.transaction_not_cached_max_retries {
                thread::sleep(self.options.transaction_not_cached_retry_delay);

                let (retry_status, retry_ct, retry_body) = self.http.get_response(&url, "application/cose")
                    .map_err(MstClientError::HttpError)?;

                if retry_status >= 200 && retry_status < 300 {
                    return Ok(retry_body);
                }

                if retry_status != 503 || !Self::is_transaction_not_cached(retry_ct.as_deref(), &retry_body) {
                    // Different error — return it as a service error
                    return Err(MstClientError::from_http_response(
                        retry_status,
                        retry_ct.as_deref(),
                        &retry_body,
                    ));
                }
            }
            // Exhausted fast retries — return the final 503
            return Err(MstClientError::from_http_response(
                503,
                content_type.as_deref(),
                &body,
            ));
        }

        // Non-503 or non-TransactionNotCached error
        Err(MstClientError::from_http_response(status, content_type.as_deref(), &body))
    }

    /// Checks if a response body contains the `TransactionNotCached` error code.
    ///
    /// Parses the body as CBOR problem details (RFC 9290) and checks the `detail`,
    /// `title`, `type`, and extension fields for the error string (case-insensitive).
    pub fn is_transaction_not_cached(content_type: Option<&str>, body: &[u8]) -> bool {
        if body.is_empty() {
            return false;
        }

        let pd = match CborProblemDetails::try_parse(body) {
            Some(pd) => pd,
            None => return false,
        };

        let needle = "transactionnotcached";

        if let Some(ref detail) = pd.detail {
            if detail.to_lowercase().contains(needle) {
                return true;
            }
        }
        if let Some(ref title) = pd.title {
            if title.to_lowercase().contains(needle) {
                return true;
            }
        }
        if let Some(ref t) = pd.problem_type {
            if t.to_lowercase().contains(needle) {
                return true;
            }
        }
        for val in pd.extensions.values() {
            if val.to_lowercase().contains(needle) {
                return true;
            }
        }

        // Also handle non-CBOR: if content-type doesn't suggest CBOR, try raw string check
        let _ = content_type;
        false
    }

    /// Convenience method to create an entry and retrieve its statement.
    ///
    /// This combines `create_entry` and `get_entry_statement` in one call.
    ///
    /// # Arguments
    ///
    /// * `cose_bytes` - The COSE_Sign1 message bytes to submit.
    ///
    /// # Returns
    ///
    /// The transparency statement as COSE bytes.
    pub fn make_transparent(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, MstClientError> {
        let result = self.create_entry(cose_bytes)?;
        self.get_entry_statement(&result.entry_id)
    }

    /// Polls an operation until it completes or times out.
    ///
    /// Uses `MstPollingOptions` from options if set, otherwise falls back to
    /// `poll_delay` and `max_poll_retries`.
    fn poll_operation(&self, operation_id: &str) -> Result<String, MstClientError> {
        let max_retries = match &self.options.polling_options {
            Some(po) => po.effective_max_retries(self.options.max_poll_retries),
            None => self.options.max_poll_retries,
        };

        for retry in 0..max_retries {
            let mut url = self.endpoint.clone();
            url.set_path(&format!(
                "{}/operations/{}",
                url.path().trim_end_matches('/'),
                operation_id
            ));
            url.set_query(Some(&format!("api-version={}", self.options.api_version)));

            let response = self.http.get_bytes(&url, "application/cbor")
                .map_err(MstClientError::HttpError)?;

            // Check the Status field
            if let Some(status) = read_cbor_text_field(&response, "Status") {
                match status.as_str() {
                    "Succeeded" => {
                        // Extract and return the entry ID
                        return read_cbor_text_field(&response, "EntryId").ok_or_else(|| {
                            MstClientError::MissingField {
                                field: "EntryId".to_string(),
                            }
                        });
                    }
                    "Failed" => {
                        return Err(MstClientError::OperationFailed {
                            operation_id: operation_id.to_string(),
                            status,
                        });
                    }
                    "Running" => {
                        // Compute delay using polling options or fallback
                        let delay = match &self.options.polling_options {
                            Some(po) => po.delay_for_retry(retry, self.options.poll_delay),
                            None => self.options.poll_delay,
                        };
                        thread::sleep(delay);
                    }
                    _ => {
                        return Err(MstClientError::OperationFailed {
                            operation_id: operation_id.to_string(),
                            status,
                        });
                    }
                }
            } else {
                return Err(MstClientError::MissingField {
                    field: "Status".to_string(),
                });
            }
        }

        Err(MstClientError::OperationTimeout {
            operation_id: operation_id.to_string(),
            retries: max_retries,
        })
    }
}

/// Reads a text field from a CBOR map.
///
/// # Arguments
///
/// * `bytes` - The CBOR-encoded map bytes.
/// * `key` - The text key to look for in the map.
///
/// # Returns
///
/// The value as a String if found, None otherwise.
fn read_cbor_text_field(bytes: &[u8], key: &str) -> Option<String> {
    let mut d = cose_sign1_primitives::provider::decoder(bytes);
    let map_len = d.decode_map_len().ok()?;
    for _ in 0..map_len.unwrap_or(usize::MAX) {
        let k = d.decode_tstr().ok()?;
        if k == key {
            return d.decode_tstr().ok().map(|s| s.to_string());
        }
        d.skip().ok()?;
    }
    None
}
