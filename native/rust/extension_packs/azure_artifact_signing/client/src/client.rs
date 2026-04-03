// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Port of Azure.CodeSigning.CertificateProfileClient.
//!
//! Uses `azure_core::http::Pipeline` for HTTP requests with automatic
//! authentication, retry, and telemetry — matching the pattern from
//! `azure_security_keyvault_certificates::CertificateClient`.
//!
//! The `start_sign()` method returns a `Poller<SignStatus>` that callers
//! can `await` for the final result or stream for intermediate status updates.

use crate::models::*;
use azure_core::{
    credentials::TokenCredential,
    http::{
        headers::{RETRY_AFTER, RETRY_AFTER_MS, X_MS_RETRY_AFTER_MS},
        policies::auth::BearerTokenAuthorizationPolicy,
        poller::{
            get_retry_after, Poller, PollerContinuation, PollerResult, PollerState,
            StatusMonitor as _,
        },
        Body, ClientOptions, Method, Pipeline, RawResponse, Request, Url,
    },
    json, Result,
};
use base64::Engine;
use std::sync::Arc;

// =================================================================
// Pure functions for request building and response parsing
// These can be tested without requiring Azure credentials
// =================================================================

/// Build a sign request for POST /sign endpoint.
#[allow(clippy::too_many_arguments)]
pub fn build_sign_request(
    endpoint: &Url,
    api_version: &str,
    account_name: &str,
    certificate_profile_name: &str,
    algorithm: &str,
    digest: &[u8],
    correlation_id: Option<&str>,
    client_version: Option<&str>,
) -> Result<Request> {
    let mut url = endpoint.clone();
    let path = format!(
        "codesigningaccounts/{}/certificateprofiles/{}/sign",
        account_name, certificate_profile_name
    );
    url.set_path(&path);
    url.query_pairs_mut()
        .append_pair("api-version", api_version);

    let digest_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    let body_json = serde_json::to_vec(&SignRequest {
        signature_algorithm: algorithm.to_string(),
        digest: digest_b64,
        file_hash_list: None,
        authenticode_hash_list: None,
    })
    .map_err(|e| azure_core::Error::new(azure_core::error::ErrorKind::DataConversion, e))?;

    let mut request = Request::new(url, Method::Post);
    request.insert_header("accept", "application/json");
    request.insert_header("content-type", "application/json");
    request.set_body(Body::from(body_json));

    if let Some(cid) = correlation_id {
        request.insert_header("x-correlation-id", cid.to_string());
    }
    if let Some(ver) = client_version {
        request.insert_header("client-version", ver.to_string());
    }

    Ok(request)
}

/// Build a request for GET /sign/eku endpoint.
pub fn build_eku_request(
    endpoint: &Url,
    api_version: &str,
    account_name: &str,
    certificate_profile_name: &str,
) -> Result<Request> {
    let mut url = endpoint.clone();
    let path = format!(
        "codesigningaccounts/{}/certificateprofiles/{}/sign/eku",
        account_name, certificate_profile_name
    );
    url.set_path(&path);
    url.query_pairs_mut()
        .append_pair("api-version", api_version);

    let mut request = Request::new(url, Method::Get);
    request.insert_header("accept", "application/json");
    Ok(request)
}

/// Build a request for GET /sign/rootcert endpoint.
pub fn build_root_certificate_request(
    endpoint: &Url,
    api_version: &str,
    account_name: &str,
    certificate_profile_name: &str,
) -> Result<Request> {
    let mut url = endpoint.clone();
    let path = format!(
        "codesigningaccounts/{}/certificateprofiles/{}/sign/rootcert",
        account_name, certificate_profile_name
    );
    url.set_path(&path);
    url.query_pairs_mut()
        .append_pair("api-version", api_version);

    let mut request = Request::new(url, Method::Get);
    request.insert_header("accept", "application/x-x509-ca-cert, application/json");
    Ok(request)
}

/// Build a request for GET /sign/certchain endpoint.
pub fn build_certificate_chain_request(
    endpoint: &Url,
    api_version: &str,
    account_name: &str,
    certificate_profile_name: &str,
) -> Result<Request> {
    let mut url = endpoint.clone();
    let path = format!(
        "codesigningaccounts/{}/certificateprofiles/{}/sign/certchain",
        account_name, certificate_profile_name
    );
    url.set_path(&path);
    url.query_pairs_mut()
        .append_pair("api-version", api_version);

    let mut request = Request::new(url, Method::Get);
    request.insert_header(
        "accept",
        "application/pkcs7-mime, application/x-x509-ca-cert, application/json",
    );
    Ok(request)
}

/// Parse sign response body into SignStatus.
pub fn parse_sign_response(body: &[u8]) -> Result<SignStatus> {
    json::from_json(body)
}

/// Parse EKU response body into Vec<String>.
pub fn parse_eku_response(body: &[u8]) -> Result<Vec<String>> {
    json::from_json(body)
}

/// Parse certificate response body (for both root cert and cert chain).
pub fn parse_certificate_response(body: &[u8]) -> Vec<u8> {
    body.to_vec()
}

/// Client for the Azure Artifact Signing REST API.
///
/// Port of C# `CertificateProfileClient` from Azure.CodeSigning.Sdk.
///
/// # Usage
///
/// ```no_run
/// use azure_artifact_signing_client::{CertificateProfileClient, CertificateProfileClientOptions};
/// use azure_identity::DeveloperToolsCredential;
///
/// let options = CertificateProfileClientOptions::new(
///     "https://eus.codesigning.azure.net",
///     "my-account",
///     "my-profile",
/// );
/// let credential = DeveloperToolsCredential::new(None).unwrap();
/// let client = CertificateProfileClient::new(options, credential, None).unwrap();
///
/// // Start signing — returns a Poller you can await
/// // let result = client.start_sign("PS256", &digest, None)?.await?.into_model()?;
/// ```
pub struct CertificateProfileClient {
    endpoint: Url,
    api_version: String,
    pipeline: Pipeline,
    account_name: String,
    certificate_profile_name: String,
    correlation_id: Option<String>,
    client_version: Option<String>,
    /// Tokio runtime for sync wrappers at the FFI boundary.
    runtime: tokio::runtime::Runtime,
}

/// Options for creating a [`CertificateProfileClient`].
#[derive(Clone, Debug, Default)]
pub struct CertificateProfileClientCreateOptions {
    /// Allows customization of the HTTP client (retry, telemetry, etc.).
    pub client_options: ClientOptions,
}

impl CertificateProfileClient {
    /// Creates a new client with an explicit credential.
    ///
    /// Follows the same pattern as `azure_security_keyvault_certificates::CertificateClient::new()`.
    pub fn new(
        options: CertificateProfileClientOptions,
        credential: Arc<dyn TokenCredential>,
        create_options: Option<CertificateProfileClientCreateOptions>,
    ) -> Result<Self> {
        let create_options = create_options.unwrap_or_default();
        let auth_scope = options.auth_scope();
        let auth_policy: Arc<dyn azure_core::http::policies::Policy> = Arc::new(
            BearerTokenAuthorizationPolicy::new(credential, vec![auth_scope]),
        );
        let pipeline = Pipeline::new(
            option_env!("CARGO_PKG_NAME"),
            option_env!("CARGO_PKG_VERSION"),
            create_options.client_options,
            Vec::new(),
            vec![auth_policy],
            None,
        );
        Self::new_with_pipeline(options, pipeline)
    }

    /// Creates a new client with DeveloperToolsCredential (for local dev).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new_dev(options: CertificateProfileClientOptions) -> Result<Self> {
        let credential = azure_identity::DeveloperToolsCredential::new(None)?;
        Self::new(options, credential, None)
    }

    /// Creates a new client with custom pipeline for testing.
    ///
    /// # Arguments
    /// * `options` - Configuration options for the client.
    /// * `pipeline` - Custom HTTP pipeline to use.
    pub fn new_with_pipeline(
        options: CertificateProfileClientOptions,
        pipeline: Pipeline,
    ) -> Result<Self> {
        let endpoint = Url::parse(&options.endpoint)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| azure_core::Error::new(azure_core::error::ErrorKind::Other, e))?;

        Ok(Self {
            endpoint,
            api_version: options.api_version,
            pipeline,
            account_name: options.account_name,
            certificate_profile_name: options.certificate_profile_name,
            correlation_id: options.correlation_id,
            client_version: options.client_version,
            runtime,
        })
    }

    /// Build the base URL: `{endpoint}/codesigningaccounts/{account}/certificateprofiles/{profile}`
    fn base_url(&self) -> Url {
        let mut url = self.endpoint.clone();
        let path = format!(
            "codesigningaccounts/{}/certificateprofiles/{}",
            self.account_name, self.certificate_profile_name,
        );
        url.set_path(&path);
        url
    }

    // =================================================================
    // POST /sign (LRO — exposed as Poller<SignStatus>)
    // =================================================================

    /// Start a sign operation. Returns a [`Poller<SignStatus>`] that the caller
    /// can `await` for the final result, or stream for intermediate status.
    ///
    /// This follows the Azure SDK Poller pattern from
    /// `azure_security_keyvault_certificates::CertificateClient::create_certificate()`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn example(client: &azure_artifact_signing_client::CertificateProfileClient) -> azure_core::Result<()> {
    /// let digest = b"pre-computed-sha256-digest-bytes-here";
    /// let result = client.start_sign("PS256", digest, None)?.await?.into_model()?;
    /// println!("Signature: {} bytes", result.signature.unwrap_or_default().len());
    /// # Ok(()) }
    /// ```
    pub fn start_sign(
        &self,
        algorithm: &str,
        digest: &[u8],
        options: Option<SignOptions>,
    ) -> Result<Poller<SignStatus>> {
        let options = options.unwrap_or_default();
        let pipeline = self.pipeline.clone();
        let endpoint = self.endpoint.clone();
        let api_version = self.api_version.clone();
        let account_name = self.account_name.clone();
        let certificate_profile_name = self.certificate_profile_name.clone();
        let correlation_id = self.correlation_id.clone();
        let client_version = self.client_version.clone();

        // Convert borrowed parameters to owned values for the closure
        let algorithm_owned = algorithm.to_string();
        let digest_owned = digest.to_vec();

        // Build poll base URL (for operation status)
        let poll_base = self.base_url();

        // Build the initial sign request
        let initial_request = build_sign_request(
            &endpoint,
            &api_version,
            &account_name,
            &certificate_profile_name,
            algorithm,
            digest,
            correlation_id.as_deref(),
            client_version.as_deref(),
        )?;

        let _sign_url = initial_request.url().clone();

        Ok(Poller::new(
            move |poller_state: PollerState, poller_options| {
                let pipeline = pipeline.clone();
                let api_version = api_version.clone();
                let endpoint = endpoint.clone();
                let account_name = account_name.clone();
                let certificate_profile_name = certificate_profile_name.clone();
                let correlation_id = correlation_id.clone();
                let client_version = client_version.clone();
                let poll_base = poll_base.clone();
                let ctx = poller_options.context.clone();

                let (mut request, _next_link) = match poller_state {
                    PollerState::Initial => {
                        // Use the pre-built initial request
                        let request = match build_sign_request(
                            &endpoint,
                            &api_version,
                            &account_name,
                            &certificate_profile_name,
                            &algorithm_owned, // Use owned values
                            &digest_owned,    // Use owned values
                            correlation_id.as_deref(),
                            client_version.as_deref(),
                        ) {
                            Ok(req) => req,
                            Err(e) => return Box::pin(async move { Err(e) }),
                        };

                        // Build the poll URL from the operation (filled in after first response)
                        let poll_url = {
                            let mut u = poll_base.clone();
                            u.set_path(&format!("{}/sign", u.path()));
                            u.query_pairs_mut().append_pair("api-version", &api_version);
                            u
                        };

                        (request, poll_url)
                    }
                    PollerState::More(continuation) => {
                        // Subsequent GET /sign/{operationId}
                        let next_link = match continuation {
                            PollerContinuation::Links { next_link, .. } => next_link,
                            _ => unreachable!(),
                        };

                        // Ensure api-version is set
                        let qp: Vec<_> = next_link
                            .query_pairs()
                            .filter(|(name, _)| name != "api-version")
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                            .collect();
                        let mut next_link = next_link.clone();
                        next_link
                            .query_pairs_mut()
                            .clear()
                            .extend_pairs(&qp)
                            .append_pair("api-version", &api_version);

                        let mut request = Request::new(next_link.clone(), Method::Get);
                        request.insert_header("accept", "application/json");

                        (request, next_link)
                    }
                };

                Box::pin(async move {
                    let rsp = pipeline.send(&ctx, &mut request, None).await?;
                    let (status, headers, body_bytes) = rsp.deconstruct();
                    let retry_after = get_retry_after(
                        &headers,
                        &[RETRY_AFTER_MS, X_MS_RETRY_AFTER_MS, RETRY_AFTER],
                        &poller_options,
                    );
                    let res = parse_sign_response(&body_bytes)?;
                    let final_body = body_bytes.clone();
                    let rsp = RawResponse::from_bytes(status, headers, body_bytes).into();

                    Ok(match res.status() {
                        azure_core::http::poller::PollerStatus::InProgress => {
                            // Build poll URL from operationId
                            let mut poll_url = poll_base.clone();
                            poll_url.set_path(&format!(
                                "{}/sign/{}",
                                poll_url.path(),
                                res.operation_id,
                            ));

                            PollerResult::InProgress {
                                response: rsp,
                                retry_after,
                                continuation: PollerContinuation::Links {
                                    next_link: poll_url,
                                    final_link: None,
                                },
                            }
                        }
                        azure_core::http::poller::PollerStatus::Succeeded => {
                            // The SignStatus response already contains signature + cert,
                            // so the "target" callback just returns the same response.
                            PollerResult::Succeeded {
                                response: rsp,
                                target: Box::new(move || {
                                    Box::pin(async move {
                                        Ok(RawResponse::from_bytes(
                                            azure_core::http::StatusCode::Ok,
                                            azure_core::http::headers::Headers::new(),
                                            final_body,
                                        )
                                        .into())
                                    })
                                }),
                            }
                        }
                        _ => PollerResult::Done { response: rsp },
                    })
                })
            },
            options.poller_options,
        ))
    }

    /// Convenience: sign a digest synchronously (blocks on the Poller).
    ///
    /// For FFI boundary use. Rust callers should prefer `start_sign()` + `await`.
    pub fn sign(
        &self,
        algorithm: &str,
        digest: &[u8],
        options: Option<SignOptions>,
    ) -> Result<SignStatus> {
        let poller = self.start_sign(algorithm, digest, options)?;
        use std::future::IntoFuture;
        let response = self.runtime.block_on(poller.into_future())?;
        response.into_model()
    }

    // =================================================================
    // GET /sign/eku
    // =================================================================

    /// Get the Extended Key Usage OIDs for this certificate profile.
    pub fn get_eku(&self) -> Result<Vec<String>> {
        self.runtime.block_on(self.get_eku_async())
    }

    async fn get_eku_async(&self) -> Result<Vec<String>> {
        let ctx = azure_core::http::Context::new();
        let mut request = build_eku_request(
            &self.endpoint,
            &self.api_version,
            &self.account_name,
            &self.certificate_profile_name,
        )?;

        let rsp = self.pipeline.send(&ctx, &mut request, None).await?;
        let (_status, _headers, body) = rsp.deconstruct();
        parse_eku_response(&body)
    }

    // =================================================================
    // GET /sign/rootcert
    // =================================================================

    /// Get the root certificate (DER bytes).
    pub fn get_root_certificate(&self) -> Result<Vec<u8>> {
        self.runtime.block_on(self.get_root_certificate_async())
    }

    async fn get_root_certificate_async(&self) -> Result<Vec<u8>> {
        let ctx = azure_core::http::Context::new();
        let mut request = build_root_certificate_request(
            &self.endpoint,
            &self.api_version,
            &self.account_name,
            &self.certificate_profile_name,
        )?;

        let rsp = self.pipeline.send(&ctx, &mut request, None).await?;
        let (_status, _headers, body) = rsp.deconstruct();
        Ok(parse_certificate_response(&body))
    }

    // =================================================================
    // GET /sign/certchain
    // =================================================================

    /// Get the certificate chain (PKCS#7 bytes — DER-encoded).
    pub fn get_certificate_chain(&self) -> Result<Vec<u8>> {
        self.runtime.block_on(self.get_certificate_chain_async())
    }

    async fn get_certificate_chain_async(&self) -> Result<Vec<u8>> {
        let ctx = azure_core::http::Context::new();
        let mut request = build_certificate_chain_request(
            &self.endpoint,
            &self.api_version,
            &self.account_name,
            &self.certificate_profile_name,
        )?;

        let rsp = self.pipeline.send(&ctx, &mut request, None).await?;
        let (_status, _headers, body) = rsp.deconstruct();
        Ok(parse_certificate_response(&body))
    }

    /// Get the client options.
    pub fn api_version(&self) -> &str {
        &self.api_version
    }
}

/// Options for the `start_sign` method.
#[derive(Default)]
pub struct SignOptions {
    /// Options for the Poller (polling frequency, context, etc.).
    pub poller_options: Option<azure_core::http::poller::PollerOptions<'static>>,
}
