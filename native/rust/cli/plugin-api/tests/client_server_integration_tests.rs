// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use cosesigntool_plugin_api::auth::{auth_key_to_hex, generate_auth_key, AUTH_KEY_ENV_VAR};
use cosesigntool_plugin_api::client::PluginClient;
use cosesigntool_plugin_api::server;
use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginCommandDef, PluginConfig, PluginInfo, PluginOptionDef,
    PluginProvider, TrustPolicyInfo, VerificationOptions, VerificationResult,
    VerificationStageKind, VerificationStageResult,
};

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
    assert_eq!(
        info.capabilities,
        vec![PluginCapability::Signing, PluginCapability::Verification]
    );
    assert_eq!(info.commands.len(), 1);
    assert_eq!(info.commands[0].name, "ats");
    assert_eq!(info.commands[0].options.len(), 2);

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

    let trust_policy_info = client
        .trust_policy_info()
        .expect("trust policy info should succeed")
        .expect("test plugin should advertise verification support");
    assert_eq!(trust_policy_info.name, "test-trust");
    assert_eq!(
        trust_policy_info.supported_modes,
        vec!["embedded", "thumbprint_allowlist"]
    );

    let verification_options = verification_options();
    let verification = client
        .verify(
            b"signed-message",
            Some(b"detached-payload"),
            verification_options.clone(),
        )
        .expect("verify should succeed")
        .expect("test plugin should return a verification result");
    assert!(verification.is_valid);
    assert_eq!(verification.stages.len(), 2);
    assert_eq!(verification.stages[0].stage, "key_resolution");
    assert_eq!(verification.stages[0].kind, VerificationStageKind::Success);
    assert_eq!(verification.stages[1].stage, "post_signature");
    assert_eq!(verification.stages[1].kind, VerificationStageKind::Success);
    assert_eq!(
        verification.metadata.get("payload_present"),
        Some(&"true".to_string())
    );
    assert_eq!(
        verification.metadata.get("allowed_thumbprints"),
        Some(&verification_options.allowed_thumbprints.len().to_string())
    );

    client.shutdown().expect("shutdown should succeed");
    server_thread
        .join()
        .expect("server thread should join")
        .expect("server should exit cleanly");
    assert!(std::env::var(AUTH_KEY_ENV_VAR).is_err());
}

#[test]
fn verification_methods_return_none_when_capability_is_not_advertised() {
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
        std::thread::spawn(move || server::run_with_args(SigningOnlyPlugin, args.as_slice()));

    let mut client = PluginClient::connect(pipe_name.as_str(), &auth_key)
        .expect("client should connect and authenticate");

    assert!(client
        .trust_policy_info()
        .expect("trust policy info should succeed")
        .is_none());
    assert!(client
        .verify(b"message", None, VerificationOptions::default())
        .expect("verify should succeed")
        .is_none());

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
            capabilities: vec![PluginCapability::Signing, PluginCapability::Verification],
            commands: sample_plugin_commands(),
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

    fn verify(
        &mut self,
        cose_bytes: &[u8],
        detached_payload: Option<&[u8]>,
        options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, String> {
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "test-plugin".to_string());
        metadata.insert("cose_len".to_string(), cose_bytes.len().to_string());
        metadata.insert(
            "payload_present".to_string(),
            detached_payload.is_some().to_string(),
        );
        metadata.insert(
            "allowed_thumbprints".to_string(),
            options.allowed_thumbprints.len().to_string(),
        );

        let mut key_resolution_metadata = HashMap::new();
        key_resolution_metadata.insert("source".to_string(), "plugin".to_string());
        key_resolution_metadata.insert(
            "trust_embedded_chain".to_string(),
            options.trust_embedded_chain.to_string(),
        );

        let post_signature_kind = if options.signature_only {
            VerificationStageKind::NotApplicable
        } else {
            VerificationStageKind::Success
        };

        Ok(Some(VerificationResult {
            is_valid: true,
            stages: vec![
                VerificationStageResult {
                    stage: "key_resolution".to_string(),
                    kind: VerificationStageKind::Success,
                    failures: Vec::new(),
                    metadata: key_resolution_metadata,
                },
                VerificationStageResult {
                    stage: "post_signature".to_string(),
                    kind: post_signature_kind,
                    failures: Vec::new(),
                    metadata: HashMap::new(),
                },
            ],
            metadata,
        }))
    }

    fn trust_policy_info(&self) -> Option<TrustPolicyInfo> {
        Some(TrustPolicyInfo {
            name: "test-trust".to_string(),
            description: "Validates embedded chains and thumbprint policy".to_string(),
            supported_modes: vec!["embedded".to_string(), "thumbprint_allowlist".to_string()],
        })
    }
}

struct SigningOnlyPlugin;

impl PluginProvider for SigningOnlyPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            id: "signing-only".to_string(),
            name: "Signing Only Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Advertises signing only to exercise capability gating".to_string(),
            capabilities: vec![PluginCapability::Signing],
            commands: sample_plugin_commands(),
        }
    }

    fn create_service(&mut self, _config: PluginConfig) -> Result<String, String> {
        Ok("service:default".to_string())
    }

    fn get_cert_chain(&mut self, _service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        Ok(vec![vec![0x30, 0x82, 0x01, 0x0a]])
    }

    fn get_algorithm(&mut self, _service_id: &str) -> Result<i64, String> {
        Ok(-7)
    }

    fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>, String> {
        Ok(expected_signature(service_id, data, algorithm))
    }

    fn verify(
        &mut self,
        _cose_bytes: &[u8],
        _detached_payload: Option<&[u8]>,
        _options: VerificationOptions,
    ) -> Result<Option<VerificationResult>, String> {
        panic!("server should not call verify when verification capability is absent");
    }

    fn trust_policy_info(&self) -> Option<TrustPolicyInfo> {
        panic!("server should not query trust policy info when verification capability is absent");
    }
}

fn sample_plugin_commands() -> Vec<PluginCommandDef> {
    vec![PluginCommandDef {
        name: "ats".to_string(),
        description: "Azure Artifact Signing provider".to_string(),
        options: vec![
            PluginOptionDef {
                name: "ats-endpoint".to_string(),
                value_name: "ats-endpoint".to_string(),
                description: "Azure Artifact Signing endpoint URL".to_string(),
                required: true,
                default_value: None,
                short: None,
                is_flag: false,
            },
            PluginOptionDef {
                name: "detached".to_string(),
                value_name: "detached".to_string(),
                description: "Create detached signature".to_string(),
                required: false,
                default_value: None,
                short: None,
                is_flag: true,
            },
        ],
        capability: PluginCapability::Signing,
    }]
}

fn verification_options() -> VerificationOptions {
    VerificationOptions {
        trust_embedded_chain: true,
        allowed_thumbprints: vec!["ABC123".to_string(), "DEF456".to_string()],
        signature_only: false,
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
