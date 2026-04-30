// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex};

use cosesigntool_plugin_api::auth::AUTH_KEY_LENGTH;
use cosesigntool_plugin_api::client::{ClientError, PluginClient};
use cosesigntool_plugin_api::protocol::{read_request, write_response, Request, RequestParams, Response, ResponseResult};
use cosesigntool_plugin_api::traits::{
    AlgorithmResponse, CertificateChainResponse, PluginCapability, PluginCommandDef, PluginConfig,
    PluginInfo, PluginOptionDef, SignResponse, TrustPolicyInfo, VerificationFailure,
    VerificationOptions, VerificationResult, VerificationStageKind, VerificationStageResult,
};

#[test]
fn connect_with_stream_and_rpc_methods_send_expected_requests() {
    let write_buffer = Arc::new(Mutex::new(Vec::new()));
    let responses = encode_responses(&[
        Response::ok(ResponseResult::Acknowledged),
        Response::ok(ResponseResult::PluginInfo(sample_plugin_info())),
        Response::ok(ResponseResult::CreateService {
            service_id: "service-123".to_string(),
        }),
        Response::ok(ResponseResult::CertificateChain(CertificateChainResponse {
            certificates: vec![vec![0x30, 0x82, 0x01, 0x0a]],
        })),
        Response::ok(ResponseResult::Algorithm(AlgorithmResponse { algorithm: -37 })),
        Response::ok(ResponseResult::Sign(SignResponse {
            signature: vec![0xde, 0xad, 0xbe, 0xef],
        })),
        Response::ok(ResponseResult::TrustPolicyInfo(TrustPolicyInfo {
            name: "x509".to_string(),
            description: "Validates embedded chains".to_string(),
            supported_modes: vec!["embedded".to_string()],
        })),
        Response::ok(ResponseResult::Verification(sample_verification_result())),
        Response::ok(ResponseResult::Acknowledged),
    ]);

    let mut client = PluginClient::connect_with_stream(
        Box::new(MockPipe::new(responses, write_buffer.clone())),
        &sample_auth_key(),
    )
    .expect("client should authenticate over the mock stream");

    let info = client.capabilities().expect("capabilities should succeed");
    assert_eq!(info.id, "mock-plugin");

    let service_id = client
        .create_service(PluginConfig {
            options: HashMap::from([("profile".to_string(), "contoso".to_string())]),
        })
        .expect("create_service should succeed");
    assert_eq!(service_id, "service-123");

    let certificates = client
        .get_cert_chain(service_id.as_str())
        .expect("certificate chain should succeed");
    assert_eq!(certificates, vec![vec![0x30, 0x82, 0x01, 0x0a]]);

    let algorithm = client
        .get_algorithm(service_id.as_str())
        .expect("algorithm should succeed");
    assert_eq!(algorithm, -37);

    let signature = client
        .sign(service_id.as_str(), b"payload", algorithm)
        .expect("sign should succeed");
    assert_eq!(signature, vec![0xde, 0xad, 0xbe, 0xef]);

    let trust_policy_info = client
        .trust_policy_info()
        .expect("trust policy info should succeed")
        .expect("trust policy info should be present");
    assert_eq!(trust_policy_info.name, "x509");

    let verification = client
        .verify(
            b"signed-message",
            Some(b"payload"),
            VerificationOptions {
                trust_embedded_chain: true,
                allowed_thumbprints: vec!["ABC123".to_string()],
                signature_only: false,
            },
        )
        .expect("verify should succeed")
        .expect("verification result should be present");
    assert!(verification.is_valid);

    client.shutdown().expect("shutdown should succeed");

    let written = write_buffer.lock().expect("buffer lock should succeed").clone();
    let requests = decode_requests(written.as_slice());
    assert_eq!(requests.len(), 9);

    match &requests[0].params {
        RequestParams::Authenticate { auth_key } => assert_eq!(auth_key, &sample_auth_key()),
        other => panic!("unexpected auth params: {other:?}"),
    }
    assert_eq!(requests[1].method, "capabilities");
    match &requests[2].params {
        RequestParams::CreateService(config) => {
            assert_eq!(config.options.get("profile"), Some(&"contoso".to_string()));
        }
        other => panic!("unexpected create_service params: {other:?}"),
    }
    assert_eq!(requests[3].method, "get_cert_chain");
    assert_eq!(requests[4].method, "get_algorithm");
    match &requests[5].params {
        RequestParams::Sign(request) => {
            assert_eq!(request.service_id, "service-123");
            assert_eq!(request.data, b"payload");
            assert_eq!(request.algorithm, -37);
        }
        other => panic!("unexpected sign params: {other:?}"),
    }
    assert_eq!(requests[6].method, "get_trust_policy_info");
    match &requests[7].params {
        RequestParams::Verify {
            cose_bytes,
            detached_payload,
            options,
        } => {
            assert_eq!(cose_bytes, b"signed-message");
            assert_eq!(detached_payload.as_deref(), Some(&b"payload"[..]));
            assert!(options.trust_embedded_chain);
            assert_eq!(options.allowed_thumbprints, vec!["ABC123"]);
            assert!(!options.signature_only);
        }
        other => panic!("unexpected verify params: {other:?}"),
    }
    assert_eq!(requests[8].method, "shutdown");
}

#[test]
fn connect_with_stream_returns_plugin_error_when_authentication_fails() {
    let error = PluginClient::connect_with_stream(
        Box::new(MockPipe::new(
            encode_responses(&[Response::err("AUTH_FAILED", "invalid auth key")]),
            Arc::new(Mutex::new(Vec::new())),
        )),
        &sample_auth_key(),
    )
    .err()
    .expect("authentication failure should be surfaced");

    match error {
        ClientError::Plugin {
            method,
            code,
            message,
        } => {
            assert_eq!(method, "authenticate");
            assert_eq!(code, "AUTH_FAILED");
            assert_eq!(message, "invalid auth key");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn rpc_errors_are_returned_as_client_errors() {
    let mut client = PluginClient::connect_with_stream(
        Box::new(MockPipe::new(
            encode_responses(&[
                Response::ok(ResponseResult::Acknowledged),
                Response::err("SIGN_FAILED", "boom"),
            ]),
            Arc::new(Mutex::new(Vec::new())),
        )),
        &sample_auth_key(),
    )
    .expect("authentication should succeed");

    let error = client
        .sign("service-123", b"payload", -7)
        .expect_err("plugin errors should surface");

    match error {
        ClientError::Plugin {
            method,
            code,
            message,
        } => {
            assert_eq!(method, "sign");
            assert_eq!(code, "SIGN_FAILED");
            assert_eq!(message, "boom");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn unexpected_response_shapes_are_reported() {
    let mut client = PluginClient::connect_with_stream(
        Box::new(MockPipe::new(
            encode_responses(&[
                Response::ok(ResponseResult::Acknowledged),
                Response::ok(ResponseResult::Acknowledged),
            ]),
            Arc::new(Mutex::new(Vec::new())),
        )),
        &sample_auth_key(),
    )
    .expect("authentication should succeed");

    let error = client
        .capabilities()
        .expect_err("unexpected response shapes should fail");

    match error {
        ClientError::UnexpectedResponse { method, details } => {
            assert_eq!(method, "capabilities");
            assert!(details.contains("expected plugin info"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

struct MockPipe {
    read_buf: Cursor<Vec<u8>>,
    write_buf: Arc<Mutex<Vec<u8>>>,
}

impl MockPipe {
    fn new(read_bytes: Vec<u8>, write_buf: Arc<Mutex<Vec<u8>>>) -> Self {
        Self {
            read_buf: Cursor::new(read_bytes),
            write_buf,
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
        let mut write_buf = self.write_buf.lock().expect("buffer lock should succeed");
        write_buf.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn sample_auth_key() -> [u8; AUTH_KEY_LENGTH] {
    [0x11; AUTH_KEY_LENGTH]
}

fn encode_responses(responses: &[Response]) -> Vec<u8> {
    let mut buffer = Vec::new();
    for response in responses {
        write_response(&mut buffer, response).expect("response should encode");
    }
    buffer
}

fn decode_requests(bytes: &[u8]) -> Vec<Request> {
    let mut cursor = Cursor::new(bytes.to_vec());
    let mut requests = Vec::new();
    while let Some(request) = read_request(&mut cursor).expect("request should decode") {
        requests.push(request);
    }
    requests
}

fn sample_plugin_info() -> PluginInfo {
    PluginInfo {
        id: "mock-plugin".to_string(),
        name: "Mock Plugin".to_string(),
        version: "1.0.0".to_string(),
        description: "Exercises PluginClient over an in-memory stream".to_string(),
        capabilities: vec![PluginCapability::Signing, PluginCapability::Verification],
        commands: vec![PluginCommandDef {
            name: "mock".to_string(),
            description: "Mock provider".to_string(),
            options: vec![PluginOptionDef {
                name: "profile".to_string(),
                value_name: "profile".to_string(),
                description: "Mock profile".to_string(),
                required: false,
                default_value: None,
                short: None,
                is_flag: false,
            }],
            capability: PluginCapability::Signing,
        }],
        transparency_options: Vec::new(),
    }
}

fn sample_verification_result() -> VerificationResult {
    VerificationResult {
        is_valid: true,
        stages: vec![VerificationStageResult {
            stage: "signature".to_string(),
            kind: VerificationStageKind::Success,
            failures: vec![VerificationFailure {
                message: "none".to_string(),
                error_code: None,
            }],
            metadata: HashMap::new(),
        }],
        metadata: HashMap::from([("provider".to_string(), "mock".to_string())]),
    }
}