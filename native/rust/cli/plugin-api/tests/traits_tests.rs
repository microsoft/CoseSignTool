// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesigntool_plugin_api::traits::{
    PluginCapability, PluginConfig, PluginInfo, PluginProvider, VerificationOptions,
};

#[test]
fn plugin_capability_roundtrips_to_and_from_strings() {
    for capability in [
        PluginCapability::Signing,
        PluginCapability::Verification,
        PluginCapability::Transparency,
    ] {
        assert_eq!(PluginCapability::from_str(capability.as_str()), Some(capability.clone()));
    }

    assert_eq!(PluginCapability::from_str("unknown"), None);
}

#[test]
fn default_plugin_provider_verification_methods_return_none() {
    let mut provider = MinimalProvider;

    let verification = provider
        .verify(b"signed-message", Some(b"payload"), VerificationOptions::default())
        .expect("default verify implementation should succeed");
    assert!(verification.is_none());
    assert!(provider.trust_policy_info().is_none());
}

struct MinimalProvider;

impl PluginProvider for MinimalProvider {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            id: "minimal".to_string(),
            name: "Minimal Provider".to_string(),
            version: "1.0.0".to_string(),
            description: "Exercises default PluginProvider methods".to_string(),
            capabilities: vec![PluginCapability::Signing],
            commands: Vec::new(),
            transparency_options: Vec::new(),
        }
    }

    fn create_service(&mut self, _config: PluginConfig) -> Result<String, String> {
        Ok("service-123".to_string())
    }

    fn get_cert_chain(&mut self, _service_id: &str) -> Result<Vec<Vec<u8>>, String> {
        Ok(vec![vec![0x30, 0x82, 0x01, 0x0a]])
    }

    fn get_algorithm(&mut self, _service_id: &str) -> Result<i64, String> {
        Ok(-7)
    }

    fn sign(&mut self, _service_id: &str, data: &[u8], _algorithm: i64) -> Result<Vec<u8>, String> {
        Ok(data.to_vec())
    }
}