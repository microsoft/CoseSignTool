// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosesigntool_plugin_api::auth::{auth_key_to_hex, generate_auth_key, AUTH_KEY_ENV_VAR};
use cosesigntool_plugin_api::client::PluginClient;
use cosesigntool_plugin_api::server;
use cosesigntool_plugin_api::traits::{PluginCapability, PluginConfig, PluginInfo, PluginProvider};

#[test]
fn client_and_server_roundtrip_all_supported_methods() {
    let _guard = env_lock().lock().expect("env lock should be acquired");
    let pipe_name = unique_pipe_name();
    let auth_key = generate_auth_key();
    let args = vec![
        "plugin-test".to_string(),
        "--pipe-name".to_string(),
        pipe_name.clone(),
    ];

    std::env::set_var(AUTH_KEY_ENV_VAR, auth_key_to_hex(&auth_key));

    let server_thread =
        std::thread::spawn(move || server::run_with_args(TestPlugin, args.as_slice()));

    let mut client = PluginClient::connect(pipe_name.as_str(), &auth_key)
        .expect("client should connect and authenticate");

    let info = client.capabilities().expect("capabilities should succeed");
    assert_eq!(info.id, "test-plugin");
    assert_eq!(info.capabilities, vec![PluginCapability::Signing]);

    let mut options = HashMap::new();
    options.insert("profile".to_string(), "contoso".to_string());
    let service_id = client
        .create_service(PluginConfig { options })
        .expect("create_service should succeed");
    assert_eq!(service_id, "service:contoso");

    let certificates = client
        .get_cert_chain(service_id.as_str())
        .expect("get_cert_chain should succeed");
    assert_eq!(
        certificates,
        vec![service_id.as_bytes().to_vec(), vec![0x30, 0x82, 0x01, 0x0a]]
    );

    let algorithm = client
        .get_algorithm(service_id.as_str())
        .expect("get_algorithm should succeed");
    assert_eq!(algorithm, -37);

    let signature = client
        .sign(service_id.as_str(), b"payload", algorithm)
        .expect("sign should succeed");
    assert_eq!(
        signature,
        expected_signature(service_id.as_str(), b"payload", algorithm)
    );

    client.shutdown().expect("shutdown should succeed");
    server_thread
        .join()
        .expect("server thread should join")
        .expect("server should exit cleanly");
    assert!(std::env::var(AUTH_KEY_ENV_VAR).is_err());
}

struct TestPlugin;

impl PluginProvider for TestPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Exercises the shared client/server helpers".to_string(),
            capabilities: vec![PluginCapability::Signing],
        }
    }

    fn create_service(&mut self, config: PluginConfig) -> Result<String, String> {
        let profile = config
            .options
            .get("profile")
            .cloned()
            .unwrap_or_else(|| "default".to_string());
        Ok(format!("service:{}", profile))
    }

    fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        Ok(vec![
            service_id.as_bytes().to_vec(),
            vec![0x30, 0x82, 0x01, 0x0a],
        ])
    }

    fn get_algorithm(&mut self, _service_id: &str) -> Result<i64, String> {
        Ok(-37)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        Ok(expected_signature(service_id, data, algorithm))
    }
}

fn expected_signature(service_id: &str, data: &[u8], algorithm: i64) -> Vec<u8> {
    let mut signature = service_id.as_bytes().to_vec();
    signature.extend_from_slice(data);
    signature.extend_from_slice(&algorithm.to_be_bytes());
    signature
}

fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

fn unique_pipe_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_nanos();
    let suffix = format!("{}-{}", std::process::id(), timestamp);

    #[cfg(windows)]
    {
        format!(r"\\.\pipe\cosesigntool-plugin-api-test-{}", suffix)
    }

    #[cfg(unix)]
    {
        std::env::current_dir()
            .expect("current directory should resolve")
            .join(format!(".cosesigntool-plugin-api-test-{}.sock", suffix))
            .to_string_lossy()
            .into_owned()
    }
}
