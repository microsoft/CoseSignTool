// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin host — discovers, launches, and communicates with subprocess plugins.
//!
//! # Discovery
//!
//! Scans the `plugins/` directory (next to the CoseSignTool binary) for
//! executables matching `cosesigntool-plugin-*` (or `cosesigntool-plugin-*.exe`
//! on Windows). Each discovered binary is launched as a subprocess.
//!
//! # Lifecycle
//!
//! 1. Host spawns plugin binary with `--mode stdio` (uses stdin/stdout for IPC)
//! 2. Host sends `capabilities` request → plugin responds with `PluginInfo`
//! 3. Host sends `create_service` with config → plugin returns `service_id`
//! 4. Host sends `sign` / `get_cert_chain` requests as needed
//! 5. Host sends `shutdown` → plugin exits

use anyhow::{Context, Result};
use cosesigntool_plugin_api::protocol::{self, methods, Request, Response};
use cosesigntool_plugin_api::traits::*;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// A running plugin subprocess.
pub struct PluginProcess {
    pub info: PluginInfo,
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl PluginProcess {
    /// Send a request and read the response.
    fn call(&mut self, method: &str, params: Option<serde_json::Value>) -> Result<Response> {
        let request = Request {
            method: method.to_string(),
            params,
        };
        protocol::write_request(&mut self.stdin, &request)
            .with_context(|| format!("Failed to send '{}' to plugin '{}'", method, self.info.id))?;

        let response = protocol::read_response(&mut self.stdout)
            .with_context(|| format!("Failed to read response for '{}' from plugin '{}'", method, self.info.id))?;

        if let Some(ref err) = response.error {
            anyhow::bail!("Plugin '{}' error on '{}': [{}] {}", self.info.id, method, err.code, err.message);
        }

        Ok(response)
    }

    /// Get the certificate chain from the plugin.
    pub fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>> {
        let response = self.call(
            methods::GET_CERT_CHAIN,
            Some(serde_json::json!({"service_id": service_id})),
        )?;
        let chain_resp: CertificateChainResponse = serde_json::from_value(
            response.result.ok_or_else(|| anyhow::anyhow!("Missing result"))?,
        )?;
        Ok(chain_resp.certificates.into_iter().map(|b| b.0).collect())
    }

    /// Get the signing algorithm from the plugin.
    pub fn get_algorithm(&mut self, service_id: &str) -> Result<i64> {
        let response = self.call(
            methods::GET_ALGORITHM,
            Some(serde_json::json!({"service_id": service_id})),
        )?;
        let result = response.result.ok_or_else(|| anyhow::anyhow!("Missing result"))?;
        let algorithm = result
            .get("algorithm")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow::anyhow!("Missing algorithm in response"))?;
        Ok(algorithm)
    }

    /// Sign data using the plugin.
    pub fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>> {
        use base64::Engine;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(data);
        let response = self.call(
            methods::SIGN,
            Some(serde_json::json!({
                "service_id": service_id,
                "data": data_b64,
                "algorithm": algorithm,
            })),
        )?;
        let sign_resp: SignResponse = serde_json::from_value(
            response.result.ok_or_else(|| anyhow::anyhow!("Missing result"))?,
        )?;
        Ok(sign_resp.signature)
    }

    /// Create a signing service in the plugin.
    pub fn create_service(&mut self, config: &PluginConfig) -> Result<String> {
        let response = self.call(
            methods::CREATE_SERVICE,
            Some(serde_json::to_value(config)?),
        )?;
        let result = response.result.ok_or_else(|| anyhow::anyhow!("Missing result"))?;
        let service_id = result
            .get("service_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing service_id in response"))?;
        Ok(service_id.to_string())
    }

    /// Send shutdown and wait for the process to exit.
    pub fn shutdown(mut self) -> Result<()> {
        let _ = self.call(methods::SHUTDOWN, None);
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        // Best-effort shutdown
        let _ = protocol::write_request(
            &mut self.stdin,
            &Request {
                method: methods::SHUTDOWN.to_string(),
                params: None,
            },
        );
        let _ = self.child.wait();
    }
}

/// The plugin registry — discovers and manages plugin subprocesses.
pub struct PluginRegistry {
    plugins: HashMap<String, PluginProcess>,
}

impl PluginRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Discover plugins from the plugins/ directory next to the executable.
    pub fn discover(&mut self) -> Result<()> {
        let plugins_dir = Self::plugins_directory()?;
        if !plugins_dir.exists() {
            tracing::debug!("No plugins directory found at {}", plugins_dir.display());
            return Ok(());
        }

        tracing::info!("Discovering plugins in {}", plugins_dir.display());

        let pattern = if cfg!(windows) {
            "cosesigntool-plugin-*.exe"
        } else {
            "cosesigntool-plugin-*"
        };

        for entry in std::fs::read_dir(&plugins_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !filename.starts_with("cosesigntool-plugin-") {
                continue;
            }
            // Skip non-executables on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = entry.metadata()?.permissions().mode();
                if mode & 0o111 == 0 {
                    continue;
                }
            }

            match self.launch_plugin(&path) {
                Ok(()) => tracing::info!("Loaded plugin: {}", filename),
                Err(e) => tracing::warn!("Failed to load plugin {}: {}", filename, e),
            }
        }

        Ok(())
    }

    /// Launch a plugin binary and query its capabilities.
    fn launch_plugin(&mut self, path: &Path) -> Result<()> {
        let mut child = Command::new(path)
            .arg("--mode")
            .arg("stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn plugin: {}", path.display()))?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("No stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow::anyhow!("No stdout"))?;

        let mut plugin = PluginProcess {
            info: PluginInfo {
                id: String::new(),
                name: String::new(),
                version: String::new(),
                description: String::new(),
                capabilities: vec![],
            },
            child,
            stdin,
            stdout: BufReader::new(stdout),
        };

        // Query capabilities
        let response = plugin.call(methods::CAPABILITIES, None)?;
        let info: PluginInfo = serde_json::from_value(
            response.result.ok_or_else(|| anyhow::anyhow!("No capabilities result"))?,
        )?;

        let plugin_id = info.id.clone();
        plugin.info = info;
        self.plugins.insert(plugin_id, plugin);

        Ok(())
    }

    /// Get a mutable reference to a plugin by ID.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut PluginProcess> {
        self.plugins.get_mut(id)
    }

    /// List all discovered plugins.
    pub fn list(&self) -> Vec<&PluginInfo> {
        self.plugins.values().map(|p| &p.info).collect()
    }

    /// Find plugins that provide a specific capability.
    pub fn find_by_capability(&self, capability: PluginCapability) -> Vec<&PluginInfo> {
        self.plugins
            .values()
            .filter(|p| p.info.capabilities.contains(&capability))
            .map(|p| &p.info)
            .collect()
    }

    /// Shutdown all plugins.
    pub fn shutdown_all(self) {
        for (_, plugin) in self.plugins {
            let _ = plugin.shutdown();
        }
    }

    /// Get the plugins directory path.
    fn plugins_directory() -> Result<PathBuf> {
        let exe_dir = std::env::current_exe()
            .context("Failed to determine executable path")?
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Executable has no parent directory"))?
            .to_path_buf();
        Ok(exe_dir.join("plugins"))
    }
}
