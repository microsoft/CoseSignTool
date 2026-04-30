// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use cosesigntool_plugin_api::auth::AUTH_KEY_LENGTH;
use cosesigntool_plugin_api::protocol::{
    methods, read_response, write_request, Request, RequestParams, Response, ResponseResult,
};
use cosesigntool_plugin_api::server::{dispatch_request, serve_connection, ServerError};
use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginConfig, PluginInfo, PluginProvider, TrustPolicyInfo,
    VerificationOptions, VerificationResult, VerificationStageKind, VerificationStageResult,
};

#[test]
fn dispatch_request_routes_supported_methods() {
    let mut plugin = TestPlugin::with_verification();

    match dispatch_request(&mut plugin, &Request::capabilities()).result {
        ResponseResult::PluginInfo(info) => {
            assert_eq!(info.id, "test-plugin");
            assert!(info.capabilities.contains(&PluginCapability::Signing));
            assert!(info.capabilities.contains(&PluginCapability::Verification));
        }
        other => panic!("unexpected capabilities result: {other:?}"),
    }

    let create_service = dispatch_request(
        &mut plugin,
        &Request::create_service(PluginConfig {
            options: HashMap::from([("profile".to_string(), "contoso".to_string())]),
        }),
    );
    match create_service.result {
        ResponseResult::CreateService { service_id } => assert_eq!(service_id, "service:contoso"),
        other => panic!("unexpected create_service result: {other:?}"),
    }

    match dispatch_request(&mut plugin, &Request::get_cert_chain("service:contoso")).result {
        ResponseResult::CertificateChain(chain) => {
            assert_eq!(chain.certificates, vec![b"service:contoso".to_vec()]);
        }
        other => panic!("unexpected cert chain result: {other:?}"),
    }

    match dispatch_request(&mut plugin, &Request::get_algorithm("service:contoso")).result {
        ResponseResult::Algorithm(result) => assert_eq!(result.algorithm, -37),
        other => panic!("unexpected algorithm result: {other:?}"),
    }

    match dispatch_request(&mut plugin, &Request::sign("service:contoso", vec![1, 2, 3], -37)).result {
        ResponseResult::Sign(result) => assert_eq!(result.signature, vec![1, 2, 3, 0x7f]),
        other => panic!("unexpected sign result: {other:?}"),
    }

    match dispatch_request(&mut plugin, &Request::trust_policy_info()).result {
        ResponseResult::TrustPolicyInfo(info) => assert_eq!(info.name, "test-trust"),
        other => panic!("unexpected trust policy result: {other:?}"),
    }

    match dispatch_request(
        &mut plugin,
        &Request::verify(
            vec![0xd2, 0x84],
            Some(vec![0xaa]),
            VerificationOptions {
                trust_embedded_chain: true,
                allowed_thumbprints: vec!["ABC123".to_string()],
                signature_only: false,
            },
        ),
    )
    .result
    {
        ResponseResult::Verification(result) => {
            assert!(result.is_valid);
            assert_eq!(result.stages[0].kind, VerificationStageKind::Success);
        }
        other => panic!("unexpected verification result: {other:?}"),
    }

    assert!(matches!(
        dispatch_request(&mut plugin, &Request::shutdown()).result,
        ResponseResult::Acknowledged
    ));
    let auth_response = dispatch_request(&mut plugin, &Request::authenticate(vec![0x11; AUTH_KEY_LENGTH]));
    assert_eq!(auth_response.error.expect("auth error should be present").code, "AUTH_ALREADY_COMPLETED");
}

#[test]
fn dispatch_request_handles_invalid_params_unknown_methods_and_capability_gating() {
    let mut plugin = TestPlugin::signing_only();

    let invalid = dispatch_request(&mut plugin, &Request::new(methods::CREATE_SERVICE, RequestParams::None));
    assert_eq!(invalid.error.expect("invalid params should fail").code, "INVALID_PARAMS");

    assert!(matches!(
        dispatch_request(&mut plugin, &Request::trust_policy_info()).result,
        ResponseResult::None
    ));
    assert!(matches!(
        dispatch_request(
            &mut plugin,
            &Request::verify(vec![0xd2, 0x84], None, VerificationOptions::default()),
        )
        .result,
        ResponseResult::None
    ));

    let unknown = dispatch_request(&mut plugin, &Request::new("unknown", RequestParams::None));
    assert_eq!(unknown.error.expect("unknown methods should fail").code, "UNKNOWN_METHOD");
}

#[test]
fn serve_connection_rejects_incorrect_auth_key() {
    let mut pipe = MockPipe::new(encode_requests(&[Request::authenticate(vec![0x22; AUTH_KEY_LENGTH])]));

    let error = serve_connection(
        &mut TestPlugin::with_verification(),
        &mut pipe,
        &[0x11; AUTH_KEY_LENGTH],
    )
    .expect_err("invalid auth should fail");

    match error {
        ServerError::AuthenticationFailed(message) => {
            assert!(message.contains("invalid auth key"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let responses = decode_responses(pipe.write_buf.as_slice());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].error.as_ref().expect("auth error should be present").code, "AUTH_FAILED");
}

#[test]
fn serve_connection_stops_processing_after_shutdown() {
    let mut pipe = MockPipe::new(encode_requests(&[
        Request::authenticate(vec![0x11; AUTH_KEY_LENGTH]),
        Request::capabilities(),
        Request::shutdown(),
        Request::capabilities(),
    ]));

    serve_connection(
        &mut TestPlugin::with_verification(),
        &mut pipe,
        &[0x11; AUTH_KEY_LENGTH],
    )
    .expect("server should exit cleanly after shutdown");

    let responses = decode_responses(pipe.write_buf.as_slice());
    assert_eq!(responses.len(), 3);
    assert!(matches!(responses[0].result, ResponseResult::Acknowledged));
    assert!(matches!(responses[1].result, ResponseResult::PluginInfo(_)));
    assert!(matches!(responses[2].result, ResponseResult::Acknowledged));
}

struct MockPipe {
    read_buf: Cursor<Vec<u8>>,
    write_buf: Vec<u8>,
}

impl MockPipe {
    fn new(read_bytes: Vec<u8>) -> Self {
        Self {
            read_buf: Cursor::new(read_bytes),
            write_buf: Vec::new(),
        }
    }
}

impl Read for MockPipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_buf.read(buf)
    }
}

impl Write for MockPipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_buf.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct TestPlugin {
    capabilities: Vec<PluginCapability>,
}

impl TestPlugin {
    fn with_verification() -> Self {
        Self {
            capabilities: vec![PluginCapability::Signing, PluginCapability::Verification],
        }
    }

    fn signing_only() -> Self {
        Self {
            capabilities: vec![PluginCapability::Signing],
        }
    }
}

impl PluginProvider for TestPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Exercises dispatch_request".to_string(),
            capabilities: self.capabilities.clone(),
            commands: Vec::new(),
            transparency_options: Vec::new(),
        }
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let profile = config
            .options
            .get("profile")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        Ok(format!("service:{profile}"))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        Ok(vec![service_id.as_bytes().to_vec()])
    }

    fn get_algorithm(&mut self, _service_id: &str) -> Result<i64, String> {
        Ok(-37)
    }

    fn sign(&mut self, _service_id: &str, data: &[u8], _algorithm: i64) -> Result<Vec<u8>, String> {
        let mut signature = data.to_vec();
        signature.push(0x7f);
        Ok(signature)
    }

    fn verify(
        &mut self,
        _cose_bytes: &[u8],
        _detached_payload: Option<&[u8]>,
        _options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, String> {
        Ok(Some(VerificationResult {
            is_valid: true,
            stages: vec![VerificationStageResult {
                stage: "signature".to_string(),
                kind: VerificationStageKind::Success,
                failures: Vec::new(),
                metadata: HashMap::new(),
            }],
            metadata: HashMap::from([("provider".to_string(), "test-plugin".to_string())]),
        }))
    }

    fn trust_policy_info(&self) -> Option<TrustPolicyInfo> {
        Some(TrustPolicyInfo {
            name: "test-trust".to_string(),
            description: "Validates mock receipts".to_string(),
            supported_modes: vec!["embedded".to_string()],
        })
    }
}

fn encode_requests(requests: &[Request]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for request in requests {
        write_request(&mut buffer, request).expect("request should encode");
    }
    buffer
}

fn decode_responses(bytes: &[u8]) -> Vec<Response> {
    let mut cursor = Cursor::new(bytes.to_vec());
    let mut responses = Vec::new();
    while (cursor.position() as usize) < bytes.len() {
        responses.push(read_response(&mut cursor).expect("response should decode"));
    }
    responses
}