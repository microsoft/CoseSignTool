// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::io::Cursor;

use cosesigntool_plugin_api::protocol::{read_request, read_response, write_request, write_response, Request, RequestParams, Response, ResponseResult};
use cosesigntool_plugin_api::traits::{AlgorithmResponse, CertificateChainResponse, PluginCapability, PluginConfig, PluginInfo};

#[test]
fn sign_request_roundtrips_through_framed_cbor() {
    let request = Request::sign("service-123", vec![0x01, 0x02, 0x03], -7);
    let mut buffer = Vec::new();

    write_request(&mut buffer, &request).expect("sign request should encode");

    let mut cursor = Cursor::new(buffer);
    let decoded = read_request(&mut cursor)
        .expect("sign request should decode")
        .expect("frame should contain a request");

    assert_eq!(decoded.method, "sign");
    match decoded.params {
        RequestParams::Sign(params) => {
            assert_eq!(params.service_id, "service-123");
            assert_eq!(params.data, vec![0x01, 0x02, 0x03]);
            assert_eq!(params.algorithm, -7);
        }
        other => panic!("unexpected params: {:?}", other),
    }
}

#[test]
fn create_service_request_roundtrips_string_options_map() {
    let mut options = HashMap::new();
    options.insert("tenant".to_string(), "contoso".to_string());
    options.insert("slot".to_string(), "blue".to_string());
    let request = Request::create_service(PluginConfig { options });
    let mut buffer = Vec::new();

    write_request(&mut buffer, &request).expect("create_service request should encode");

    let mut cursor = Cursor::new(buffer);
    let decoded = read_request(&mut cursor)
        .expect("create_service request should decode")
        .expect("frame should contain a request");

    assert_eq!(decoded.method, "create_service");
    match decoded.params {
        RequestParams::CreateService(config) => {
            assert_eq!(config.options.get("tenant"), Some(&"contoso".to_string()));
            assert_eq!(config.options.get("slot"), Some(&"blue".to_string()));
        }
        other => panic!("unexpected params: {:?}", other),
    }
}

#[test]
fn plugin_info_response_roundtrips_through_framed_cbor() {
    let response = Response::ok(ResponseResult::PluginInfo(PluginInfo {
        id: "local".to_string(),
        name: "Local Test Plugin".to_string(),
        version: "1.2.3".to_string(),
        description: "Provides local signing".to_string(),
        capabilities: vec![PluginCapability::Signing, PluginCapability::Verification],
    }));
    let mut buffer = Vec::new();

    write_response(&mut buffer, &response).expect("plugin info response should encode");

    let mut cursor = Cursor::new(buffer);
    let decoded = read_response(&mut cursor).expect("plugin info response should decode");

    assert!(decoded.error.is_none());
    match decoded.result {
        ResponseResult::PluginInfo(info) => {
            assert_eq!(info.id, "local");
            assert_eq!(info.name, "Local Test Plugin");
            assert_eq!(info.version, "1.2.3");
            assert_eq!(info.description, "Provides local signing");
            assert_eq!(info.capabilities.len(), 2);
            assert_eq!(info.capabilities[0], PluginCapability::Signing);
            assert_eq!(info.capabilities[1], PluginCapability::Verification);
        }
        other => panic!("unexpected result: {:?}", other),
    }
}

#[test]
fn binary_response_payloads_roundtrip_without_base64() {
    let certs_response = Response::ok(ResponseResult::CertificateChain(CertificateChainResponse {
        certificates: vec![vec![0x30, 0x82, 0x01], vec![0x30, 0x82, 0x02]],
    }));
    let algorithm_response = Response::ok(ResponseResult::Algorithm(AlgorithmResponse { algorithm: -37 }));

    let mut certs_buffer = Vec::new();
    write_response(&mut certs_buffer, &certs_response).expect("certificate response should encode");
    let mut certs_cursor = Cursor::new(certs_buffer);
    let decoded_certs = read_response(&mut certs_cursor).expect("certificate response should decode");
    match decoded_certs.result {
        ResponseResult::CertificateChain(chain) => {
            assert_eq!(chain.certificates, vec![vec![0x30, 0x82, 0x01], vec![0x30, 0x82, 0x02]]);
        }
        other => panic!("unexpected certificate result: {:?}", other),
    }

    let mut algorithm_buffer = Vec::new();
    write_response(&mut algorithm_buffer, &algorithm_response).expect("algorithm response should encode");
    let mut algorithm_cursor = Cursor::new(algorithm_buffer);
    let decoded_algorithm = read_response(&mut algorithm_cursor).expect("algorithm response should decode");
    match decoded_algorithm.result {
        ResponseResult::Algorithm(result) => {
            assert_eq!(result.algorithm, -37);
        }
        other => panic!("unexpected algorithm result: {:?}", other),
    }
}
