// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared HTTP client using azure_core Pipeline.

use azure_core::http::{ClientOptions, Context, Method, Pipeline, Request};
use std::sync::OnceLock;
use url::Url;

/// Trait abstracting HTTP transport for testability.
pub trait HttpTransport: Send + Sync + std::fmt::Debug {
    fn get_bytes(&self, url: &Url, accept: &str) -> Result<Vec<u8>, String>;
    fn get_string(&self, url: &Url, accept: &str) -> Result<String, String>;
    /// GET and return (status, content_type, body). Default delegates to `get_bytes`.
    fn get_response(&self, url: &Url, accept: &str) -> Result<(u16, Option<String>, Vec<u8>), String> {
        self.get_bytes(url, accept).map(|body| (200, None, body))
    }
    /// POST bytes and return (status, content_type, body).
    fn post_bytes(&self, url: &Url, content_type: &str, accept: &str, body: Vec<u8>) -> Result<(u16, Option<String>, Vec<u8>), String>;
}

/// Default HTTP transport implementation using azure_core Pipeline.
#[derive(Debug)]
pub struct DefaultHttpTransport {
    pipeline: Pipeline,
    runtime: tokio::runtime::Runtime,
}

impl DefaultHttpTransport {
    /// Creates a new `DefaultHttpTransport` with default `ClientOptions`.
    pub fn new() -> Self {
        Self::with_options(ClientOptions::default())
    }

    /// Creates a new `DefaultHttpTransport` with custom `ClientOptions`.
    /// 
    /// This constructor allows injecting custom transport configuration for testing.
    /// 
    /// # Arguments
    /// 
    /// * `options` - The `ClientOptions` to configure the HTTP pipeline.
    pub fn with_options(options: ClientOptions) -> Self {
        let pipeline = Pipeline::new(
            option_env!("CARGO_PKG_NAME"),
            option_env!("CARGO_PKG_VERSION"),
            options,
            vec![],
            vec![],
            None,
        );
        
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create tokio runtime");
            
        Self { pipeline, runtime }
    }
}

impl HttpTransport for DefaultHttpTransport {
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_bytes(&self, url: &Url, accept: &str) -> Result<Vec<u8>, String> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Get);
            request.insert_header("accept", accept.to_string());
            let ctx = Context::new();
            let response = self.pipeline
                .send(&ctx, &mut request, None)
                .await
                .map_err(|e| e.to_string())?;
            let body = response.into_body();
            Ok(body.as_ref().to_vec())
        })
    }
    
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_string(&self, url: &Url, accept: &str) -> Result<String, String> {
        let bytes = self.get_bytes(url, accept)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn get_response(&self, url: &Url, accept: &str) -> Result<(u16, Option<String>, Vec<u8>), String> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Get);
            request.insert_header("accept", accept.to_string());
            let ctx = Context::new();
            let response = self.pipeline
                .send(&ctx, &mut request, None)
                .await
                .map_err(|e| e.to_string())?;
            let status = u16::from(response.status());
            let ct = response.headers().get_optional_string(&azure_core::http::headers::CONTENT_TYPE);
            let body = response.into_body();
            Ok((status, ct, body.as_ref().to_vec()))
        })
    }
    
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn post_bytes(&self, url: &Url, content_type: &str, accept: &str, body: Vec<u8>) -> Result<(u16, Option<String>, Vec<u8>), String> {
        self.runtime.block_on(async {
            let mut request = Request::new(url.clone(), Method::Post);
            request.insert_header("content-type", content_type.to_string());
            request.insert_header("accept", accept.to_string());
            request.set_body(body);
            let ctx = Context::new();
            let response = self.pipeline
                .send(&ctx, &mut request, None)
                .await
                .map_err(|e| e.to_string())?;
            let status = u16::from(response.status());
            let ct = response.headers().get_optional_string(&azure_core::http::headers::CONTENT_TYPE);
            let resp_body = response.into_body();
            Ok((status, ct, resp_body.as_ref().to_vec()))
        })
    }
}

// Keep backward-compatible free functions:
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn get_bytes(url: &Url, accept: &str) -> Result<Vec<u8>, String> {
    static DEFAULT: OnceLock<DefaultHttpTransport> = OnceLock::new();
    DEFAULT.get_or_init(DefaultHttpTransport::new).get_bytes(url, accept)
}

/// Send a GET request and return the response body as a UTF-8 string.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn get_string(url: &Url, accept: &str) -> Result<String, String> {
    static DEFAULT: OnceLock<DefaultHttpTransport> = OnceLock::new();
    DEFAULT.get_or_init(DefaultHttpTransport::new).get_string(url, accept)
}

/// Send a POST request with a body and return response bytes.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn post_bytes(
    url: &Url,
    content_type: &str,
    accept: &str,
    body: Vec<u8>,
) -> Result<(u16, Option<String>, Vec<u8>), String> {
    static DEFAULT: OnceLock<DefaultHttpTransport> = OnceLock::new();
    DEFAULT.get_or_init(DefaultHttpTransport::new).post_bytes(url, content_type, accept, body)
}

/// Mock HTTP transport for testing. Only available with the `test-utils` feature.
#[cfg(feature = "test-utils")]
pub struct MockHttpTransport {
    pub get_responses: std::collections::HashMap<String, Result<Vec<u8>, String>>,
    pub get_full_responses: std::collections::HashMap<String, Result<(u16, Option<String>, Vec<u8>), String>>,
    pub post_responses: std::collections::HashMap<String, Result<(u16, Option<String>, Vec<u8>), String>>,
}

#[cfg(feature = "test-utils")]
impl std::fmt::Debug for MockHttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockHttpTransport")
            .field("get_responses", &self.get_responses.len())
            .field("get_full_responses", &self.get_full_responses.len())
            .field("post_responses", &self.post_responses.len())
            .finish()
    }
}

#[cfg(feature = "test-utils")]
impl MockHttpTransport {
    pub fn new() -> Self {
        Self {
            get_responses: std::collections::HashMap::new(),
            get_full_responses: std::collections::HashMap::new(),
            post_responses: std::collections::HashMap::new(),
        }
    }
}

#[cfg(feature = "test-utils")]
impl HttpTransport for MockHttpTransport {
    fn get_bytes(&self, url: &Url, _accept: &str) -> Result<Vec<u8>, String> {
        self.get_responses
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(|| Err(format!("No mock response for GET {}", url)))
    }
    
    fn get_string(&self, url: &Url, accept: &str) -> Result<String, String> {
        let bytes = self.get_bytes(url, accept)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    fn get_response(&self, url: &Url, accept: &str) -> Result<(u16, Option<String>, Vec<u8>), String> {
        if let Some(resp) = self.get_full_responses.get(url.as_str()) {
            return resp.clone();
        }
        // Fall back to get_bytes style (200 OK)
        self.get_bytes(url, accept).map(|body| (200, None, body))
    }
    
    fn post_bytes(&self, url: &Url, _content_type: &str, _accept: &str, _body: Vec<u8>) -> Result<(u16, Option<String>, Vec<u8>), String> {
        self.post_responses
            .get(url.as_str())
            .cloned()
            .unwrap_or_else(|| Err(format!("No mock response for POST {}", url)))
    }
}
