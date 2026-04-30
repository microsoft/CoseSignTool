// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Plugin host — discovers, launches, and communicates with subprocess plugins.

use anyhow::{anyhow, Context, Result};
use cosesigntool_plugin_api::auth::{auth_key_to_hex, generate_auth_key, AUTH_KEY_ENV_VAR};
use cosesigntool_plugin_api::client::PluginClient;
use cosesigntool_plugin_api::traits::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct PluginEndpoint {
    pipe_name: String,
    #[cfg(unix)]
    socket_path: PathBuf,
}

impl PluginEndpoint {
    fn new() -> Result<Self> {
        let suffix = unique_pipe_suffix();

        #[cfg(windows)]
        {
            Ok(Self {
                pipe_name: format!(r"\\.\pipe\cosesigntool-plugin-{}", suffix),
            })
        }

        #[cfg(unix)]
        {
            let socket_path = std::env::current_dir()
                .context("Failed to determine current directory for plugin socket path")?
                .join(format!(".cosesigntool-plugin-{}.sock", suffix));
            let pipe_name = socket_path.to_string_lossy().into_owned();
            Ok(Self {
                pipe_name,
                socket_path,
            })
        }
    }

    fn cleanup(&self) {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

/// A running plugin subprocess.
pub struct PluginProcess {
    pub info: PluginInfo,
    child: Child,
    client: PluginClient,
    endpoint: PluginEndpoint,
}

impl PluginProcess {
    /// Get the certificate chain from the plugin.
    pub fn get_cert_chain(&mut self, service_id: &str) -> Result<Vec<Vec<u8>>> {
        self.client.get_cert_chain(service_id).with_context(|| {
            format!(
                "Failed to get the certificate chain from plugin '{}' for service '{}'",
                self.info.id, service_id
            )
        })
    }

    /// Get the signing algorithm from the plugin.
    pub fn get_algorithm(&mut self, service_id: &str) -> Result<i64> {
        self.client.get_algorithm(service_id).with_context(|| {
            format!(
                "Failed to get the signing algorithm from plugin '{}' for service '{}'",
                self.info.id, service_id
            )
        })
    }

    /// Sign data using the plugin.
    pub fn sign(&mut self, service_id: &str, data: &[u8], algorithm: i64) -> Result<Vec<u8>> {
        self.client
            .sign(service_id, data, algorithm)
            .with_context(|| {
                format!(
                    "Failed to sign with plugin '{}' for service '{}'",
                    self.info.id, service_id
                )
            })
    }

    /// Create a signing service in the plugin.
    pub fn create_service(&mut self, config: &PluginConfig) -> Result<String> {
        self.client
            .create_service(config.clone())
            .with_context(|| format!("Failed to create a service in plugin '{}'", self.info.id))
    }

    /// Sign a payload end-to-end using the plugin.
    pub fn sign_payload(
        &mut self,
        service_id: &str,
        payload: &[u8],
        content_type: &str,
        format: &str,
        options: PluginConfig,
    ) -> Result<Vec<u8>> {
        self.client
            .sign_payload(service_id, payload, content_type, format, options)
            .with_context(|| {
                format!(
                    "Failed to sign payload with plugin '{}' for service '{}'",
                    self.info.id, service_id
                )
            })
    }

    /// Send shutdown and wait for the process to exit.
    pub fn shutdown(mut self) -> Result<()> {
        let _ = self.client.send_shutdown();
        wait_for_child_exit(&mut self.child, Duration::from_secs(2))?;
        self.endpoint.cleanup();
        Ok(())
    }

    fn abort(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.endpoint.cleanup();
    }
}

impl Drop for PluginProcess {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {
                self.endpoint.cleanup();
                return;
            }
            Ok(None) => {}
            Err(_) => {
                self.endpoint.cleanup();
                return;
            }
        }

        let _ = self.client.send_shutdown();
        let _ = wait_for_child_exit(&mut self.child, Duration::from_millis(500));
        self.endpoint.cleanup();
    }
}

/// The plugin registry — discovers and manages plugin subprocesses.
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<Mutex<PluginProcess>>>,
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

        for entry in std::fs::read_dir(&plugins_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let filename = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !filename.starts_with("cosesigntool-plugin-") {
                continue;
            }

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
                Err(error) => tracing::warn!("Failed to load plugin {}: {}", filename, error),
            }
        }

        Ok(())
    }

    /// Launch a plugin binary and query its capabilities.
    fn launch_plugin(&mut self, path: &Path) -> Result<()> {
        let endpoint = PluginEndpoint::new()?;
        let auth_key = generate_auth_key();
        endpoint.cleanup();

        let mut child = Command::new(path)
            .arg("--mode")
            .arg("pipe")
            .arg("--pipe-name")
            .arg(endpoint.pipe_name.as_str())
            .env(AUTH_KEY_ENV_VAR, auth_key_to_hex(&auth_key))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("Failed to spawn plugin: {}", path.display()))?;

        let client = match PluginClient::connect(endpoint.pipe_name.as_str(), &auth_key) {
            Ok(client) => client,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                endpoint.cleanup();
                return Err(error).with_context(|| {
                    format!("Failed to connect to plugin pipe '{}'", endpoint.pipe_name)
                });
            }
        };

        let mut plugin = PluginProcess {
            info: PluginInfo {
                id: String::new(),
                name: String::new(),
                version: String::new(),
                description: String::new(),
                capabilities: Vec::new(),
                commands: Vec::new(),
                transparency_options: Vec::new(),
            },
            child,
            client,
            endpoint,
        };

        let info = match plugin.client.capabilities() {
            Ok(info) => info,
            Err(error) => {
                plugin.abort();
                return Err(error).with_context(|| {
                    format!(
                        "Failed to query capabilities from plugin {}",
                        path.display()
                    )
                });
            }
        };

        let plugin_id = info.id.clone();
        plugin.info = info;
        self.plugins
            .insert(plugin_id, Arc::new(Mutex::new(plugin)));
        Ok(())
    }

    /// Get a shared plugin handle by ID.
    pub fn get(&self, id: &str) -> Option<Arc<Mutex<PluginProcess>>> {
        self.plugins.get(id).cloned()
    }

    /// List all discovered plugins.
    pub fn list(&self) -> Vec<PluginInfo> {
        let mut plugins = self
            .plugins
            .values()
            .filter_map(|plugin| plugin.lock().ok().map(|process| process.info.clone()))
            .collect::<Vec<PluginInfo>>();
        plugins.sort_by(|left, right| left.id.cmp(&right.id));
        plugins
    }

    /// Find plugins that provide a specific capability.
    pub fn find_by_capability(&self, capability: PluginCapability) -> Vec<PluginInfo> {
        let mut plugins = self
            .plugins
            .values()
            .filter_map(|plugin| plugin.lock().ok().map(|process| process.info.clone()))
            .filter(|plugin| plugin.capabilities.contains(&capability))
            .collect::<Vec<PluginInfo>>();
        plugins.sort_by(|left, right| left.id.cmp(&right.id));
        plugins
    }

    /// Find the plugin command that handles the given signing provider name.
    pub fn find_signing_command(&self, command_name: &str) -> Option<(String, PluginCommandDef)> {
        let mut plugins = self.list();
        plugins.sort_by(|left, right| left.id.cmp(&right.id));

        for plugin in plugins {
            for command in &plugin.commands {
                if command.capability == PluginCapability::Signing && command.name == command_name {
                    return Some((plugin.id.clone(), command.clone()));
                }
            }
        }

        None
    }

    /// Shutdown all plugins.
    pub fn shutdown_all(self) {
        for (_, plugin) in self.plugins {
            match Arc::try_unwrap(plugin) {
                Ok(plugin) => {
                    if let Ok(plugin) = plugin.into_inner() {
                        let _ = plugin.shutdown();
                    }
                }
                Err(plugin) => {
                    if let Ok(mut plugin) = plugin.lock() {
                        let _ = plugin.client.send_shutdown();
                    }
                }
            }
        }
    }

    /// Get the plugins directory path.
    fn plugins_directory() -> Result<PathBuf> {
        let exe_dir = std::env::current_exe()
            .context("Failed to determine executable path")?
            .parent()
            .ok_or_else(|| anyhow!("Executable has no parent directory"))?
            .to_path_buf();
        Ok(exe_dir.join("plugins"))
    }
}

fn unique_pipe_suffix() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos();
    format!("{}-{}", std::process::id(), timestamp)
}

fn wait_for_child_exit(child: &mut Child, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(());
        }

        thread::sleep(Duration::from_millis(50));
    }
}
